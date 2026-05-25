from __future__ import annotations

import base64
import io
import json
import os
import re
import unittest
import urllib.error
from contextlib import redirect_stdout
from unittest.mock import patch

from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.transaction import VersionedTransaction
from spl.token.constants import TOKEN_PROGRAM_ID

from x402.interop import client as interop_client
from x402.interop.client import select_svm_challenge, select_svm_requirement
from x402.interop.exact import (
    MAX_MEMO_BYTES,
    MEMO_PROGRAM_ID,
    TOKEN_MINT_DECIMALS_OFFSET,
    MintMetadata,
    build_exact_payment_signature,
    build_exact_payment_signature_from_rpc,
    fetch_mint_metadata,
    keypair_from_json_secret,
    latest_blockhash,
)


class SelectSvmRequirementTests(unittest.TestCase):
    def test_ignores_malformed_payment_required_inputs(self) -> None:
        self.assertIsNone(
            select_svm_requirement(
                headers={"PAYMENT-REQUIRED": "not base64!!!"},
                body="",
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            )
        )
        self.assertIsNone(
            select_svm_requirement(
                headers={},
                body="{not json",
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            )
        )
        self.assertIsNone(
            select_svm_requirement(
                headers={},
                body=json.dumps([]),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            )
        )

    def test_ignores_non_list_accepts(self) -> None:
        self.assertEqual(
            select_svm_challenge(
                headers={},
                body=json.dumps({"accepts": {"scheme": "exact"}}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            ),
            (None, None),
        )

    def test_returns_resource_when_preferred_currency_does_not_match(self) -> None:
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
        }
        resource = {"type": "http", "uri": "/protected"}

        self.assertEqual(
            select_svm_challenge(
                headers={},
                body=json.dumps({"resource": resource, "accepts": [requirement]}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                accepted_currencies=["CASH"],
            ),
            (None, resource),
        )

    def test_currency_matching_accepts_sol_and_symbol_metadata(self) -> None:
        sol_requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "SOL",
            "amount": "10",
        }
        symbol_requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "unused",
            "currency": "usdc",
            "amount": "20",
        }

        self.assertEqual(
            select_svm_requirement(
                headers={},
                body=json.dumps({"accepts": [sol_requirement]}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                accepted_currencies=["SOL"],
            ),
            sol_requirement,
        )
        self.assertEqual(
            select_svm_requirement(
                headers={},
                body=json.dumps({"accepts": [symbol_requirement]}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                accepted_currencies=["USDC"],
            ),
            symbol_requirement,
        )

    def test_accepted_currencies_from_env_ignores_empty_values(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(interop_client._accepted_currencies_from_env())
        with patch.dict(os.environ, {"X402_INTEROP_PREFER_CURRENCIES": " , USDC, PYUSD ,, "}):
            self.assertEqual(interop_client._accepted_currencies_from_env(), ["USDC", "PYUSD"])

    def test_selects_requirement_from_payment_required_header(self) -> None:
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
        }
        envelope = {"x402Version": 2, "accepts": [requirement]}
        encoded = base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("ascii")

        self.assertEqual(
            select_svm_requirement(
                headers={"PAYMENT-REQUIRED": encoded},
                body="",
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            ),
            requirement,
        )

    def test_selects_challenge_resource_from_payment_required_header(self) -> None:
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
        }
        resource = {
            "url": "/protected",
            "description": "Surfpool-backed protected content",
            "mimeType": "application/json",
        }
        envelope = {"x402Version": 2, "resource": resource, "accepts": [requirement]}
        encoded = base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("ascii")

        self.assertEqual(
            select_svm_challenge(
                headers={"PAYMENT-REQUIRED": encoded},
                body="",
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            ),
            (requirement, resource),
        )

    def test_selects_matching_requirement_from_json_body(self) -> None:
        usdc = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
        }
        evm = {
            "scheme": "exact",
            "network": "eip155:8453",
            "asset": "0x0000000000000000000000000000000000000000",
            "amount": "1000",
        }

        self.assertEqual(
            select_svm_requirement(
                headers={},
                body=json.dumps({"accepts": [evm, usdc]}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            ),
            usdc,
        )

    def test_returns_none_when_no_solana_exact_requirement_matches(self) -> None:
        body = json.dumps(
            {
                "accepts": [
                    {
                        "scheme": "unsupported",
                        "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                        "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                        "amount": "1000",
                    }
                ]
            }
        )

        self.assertIsNone(
            select_svm_requirement(
                headers={},
                body=body,
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            )
        )

    def test_selects_preferred_currency_before_cheapest_amount(self) -> None:
        usdc = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "100",
        }
        pyusd = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
            "amount": "200",
        }

        self.assertEqual(
            select_svm_requirement(
                headers={},
                body=json.dumps({"accepts": [usdc, pyusd]}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                accepted_currencies=["PYUSD", "USDC"],
            ),
            pyusd,
        )

    def test_selects_second_preferred_currency_when_first_is_unavailable(self) -> None:
        usdc = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "100",
        }
        pyusd = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
            "amount": "200",
        }

        self.assertEqual(
            select_svm_requirement(
                headers={},
                body=json.dumps({"accepts": [pyusd, usdc]}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                accepted_currencies=["CASH", "USDC"],
            ),
            usdc,
        )

    def test_returns_none_when_no_preferred_currency_matches(self) -> None:
        usdc = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "100",
        }
        pyusd = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
            "amount": "200",
        }

        self.assertIsNone(
            select_svm_requirement(
                headers={},
                body=json.dumps({"accepts": [pyusd, usdc]}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                accepted_currencies=["CASH"],
            )
        )

    def test_selects_cheapest_matching_requirement_without_currency_preference(self) -> None:
        expensive = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "USDC",
            "amount": "200",
        }
        cheap = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "PYUSD",
            "amount": "100",
        }

        self.assertEqual(
            select_svm_requirement(
                headers={},
                body=json.dumps({"accepts": [expensive, cheap]}),
                network="solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            ),
            cheap,
        )

    def test_builds_exact_payment_signature_envelope(self) -> None:
        client = Keypair()
        fee_payer = Keypair()
        pay_to = Keypair()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
            "payTo": str(pay_to.pubkey()),
            "maxTimeoutSeconds": 300,
            "extra": {
                "feePayer": str(fee_payer.pubkey()),
                "decimals": 6,
                "tokenProgram": str(TOKEN_PROGRAM_ID),
                "memo": "unit-test",
            },
        }
        resource = {"url": "/protected", "description": "test", "mimeType": "application/json"}

        header = build_exact_payment_signature(
            requirement=requirement,
            client_keypair=client,
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
            resource=resource,
        )

        envelope = json.loads(base64.b64decode(header).decode("utf-8"))
        self.assertEqual(envelope["x402Version"], 2)
        self.assertEqual(envelope["accepted"], requirement)
        self.assertEqual(envelope["resource"], resource)

        tx = VersionedTransaction.from_bytes(
            base64.b64decode(envelope["payload"]["transaction"])
        )
        self.assertIn(client.pubkey(), tx.message.account_keys)
        self.assertIn(fee_payer.pubkey(), tx.message.account_keys)
        signer_index = list(tx.message.account_keys).index(client.pubkey())
        fee_payer_index = list(tx.message.account_keys).index(fee_payer.pubkey())
        self.assertNotEqual(tx.signatures[signer_index], Signature.default())
        self.assertEqual(tx.signatures[fee_payer_index], Signature.default())
        self.assertTrue(
            tx.signatures[signer_index].verify(
                client.pubkey(),
                to_bytes_versioned(tx.message),
            )
        )

    def test_rejects_memo_above_reference_limit(self) -> None:
        client = Keypair()
        fee_payer = Keypair()
        pay_to = Keypair()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
            "payTo": str(pay_to.pubkey()),
            "extra": {
                "feePayer": str(fee_payer.pubkey()),
                "decimals": 6,
                "tokenProgram": str(TOKEN_PROGRAM_ID),
                "memo": "x" * (MAX_MEMO_BYTES + 1),
            },
        }

        with self.assertRaisesRegex(ValueError, "extra.memo exceeds maximum 256 bytes"):
            build_exact_payment_signature(
                requirement=requirement,
                client_keypair=client,
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )

    def test_accepts_memo_at_reference_limit(self) -> None:
        client = Keypair()
        fee_payer = Keypair()
        pay_to = Keypair()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
            "payTo": str(pay_to.pubkey()),
            "extra": {
                "feePayer": str(fee_payer.pubkey()),
                "decimals": 6,
                "tokenProgram": str(TOKEN_PROGRAM_ID),
                "memo": "x" * MAX_MEMO_BYTES,
            },
        }

        header = build_exact_payment_signature(
            requirement=requirement,
            client_keypair=client,
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )
        envelope = json.loads(base64.b64decode(header).decode("utf-8"))
        transaction = VersionedTransaction.from_bytes(
            base64.b64decode(envelope["payload"]["transaction"])
        )

        memo_instruction = transaction.message.instructions[3]
        memo_program = transaction.message.account_keys[memo_instruction.program_id_index]

        self.assertEqual(memo_program, MEMO_PROGRAM_ID)
        self.assertEqual(bytes(memo_instruction.data).decode("utf-8"), "x" * MAX_MEMO_BYTES)
        self.assertEqual(len(memo_instruction.accounts), 0)

    def test_build_exact_payment_signature_uses_random_memo_nonce_by_default(self) -> None:
        client = Keypair()
        fee_payer = Keypair()
        pay_to = Keypair()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
            "payTo": str(pay_to.pubkey()),
            "extra": {
                "feePayer": str(fee_payer.pubkey()),
                "decimals": 6,
                "tokenProgram": str(TOKEN_PROGRAM_ID),
            },
        }

        headers = [
            build_exact_payment_signature(
                requirement=requirement,
                client_keypair=client,
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )
            for _attempt in range(2)
        ]
        memos = []
        for header in headers:
            envelope = json.loads(base64.b64decode(header).decode("utf-8"))
            transaction = VersionedTransaction.from_bytes(
                base64.b64decode(envelope["payload"]["transaction"])
            )
            memo_instruction = transaction.message.instructions[3]
            self.assertEqual(
                transaction.message.account_keys[memo_instruction.program_id_index],
                MEMO_PROGRAM_ID,
            )
            self.assertEqual(len(memo_instruction.accounts), 0)
            memo = bytes(memo_instruction.data).decode("utf-8")
            self.assertRegex(memo, re.compile(r"^[0-9a-f]{32}$"))
            memos.append(memo)

        self.assertNotEqual(memos[0], memos[1])

    def test_build_exact_payment_signature_requires_fee_payer(self) -> None:
        client = Keypair()
        pay_to = Keypair()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
            "payTo": str(pay_to.pubkey()),
            "extra": {
                "decimals": 6,
                "tokenProgram": str(TOKEN_PROGRAM_ID),
            },
        }

        with self.assertRaisesRegex(ValueError, "payment requirement is missing feePayer"):
            build_exact_payment_signature(
                requirement=requirement,
                client_keypair=client,
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )


class ExactRpcMetadataTests(unittest.TestCase):
    def test_keypair_from_json_secret_rejects_non_64_byte_arrays(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected a 64-byte Solana secret key JSON array"):
            keypair_from_json_secret(json.dumps([1, 2, 3]))
        with self.assertRaisesRegex(ValueError, "expected a 64-byte Solana secret key JSON array"):
            keypair_from_json_secret(json.dumps({"secret": []}))

    def test_fetch_mint_metadata_parses_account_data(self) -> None:
        data = bytes([0] * TOKEN_MINT_DECIMALS_OFFSET + [9])
        account = type("Account", (), {"data": data, "owner": TOKEN_PROGRAM_ID})()
        response = type("Response", (), {"value": account})()

        with patch("x402.interop.exact.Client") as client_class:
            client_class.return_value.get_account_info.return_value = response

            metadata = fetch_mint_metadata("http://rpc.test", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")

        self.assertEqual(metadata, MintMetadata(decimals=9, token_program=TOKEN_PROGRAM_ID))

    def test_fetch_mint_metadata_rejects_missing_short_or_unknown_owner(self) -> None:
        with patch("x402.interop.exact.Client") as client_class:
            client_class.return_value.get_account_info.return_value = type("Response", (), {"value": None})()
            with self.assertRaisesRegex(RuntimeError, "mint account not found"):
                fetch_mint_metadata("http://rpc.test", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")

        short_account = type("Account", (), {"data": b"short", "owner": TOKEN_PROGRAM_ID})()
        with patch("x402.interop.exact.Client") as client_class:
            client_class.return_value.get_account_info.return_value = type(
                "Response",
                (),
                {"value": short_account},
            )()
            with self.assertRaisesRegex(RuntimeError, "mint account data is too short"):
                fetch_mint_metadata("http://rpc.test", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")

        unknown_owner = Keypair().pubkey()
        account = type(
            "Account",
            (),
            {"data": bytes([0] * (TOKEN_MINT_DECIMALS_OFFSET + 1)), "owner": unknown_owner},
        )()
        with patch("x402.interop.exact.Client") as client_class:
            client_class.return_value.get_account_info.return_value = type(
                "Response",
                (),
                {"value": account},
            )()
            with self.assertRaisesRegex(RuntimeError, "mint owner is not a known token program"):
                fetch_mint_metadata("http://rpc.test", "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")

    def test_latest_blockhash_reads_rpc_value(self) -> None:
        value = type("Value", (), {"blockhash": Hash.default()})()
        response = type("Response", (), {"value": value})()

        with patch("x402.interop.exact.Client") as client_class:
            client_class.return_value.get_latest_blockhash.return_value = response

            self.assertEqual(latest_blockhash("http://rpc.test"), str(Hash.default()))

    def test_build_exact_payment_signature_from_rpc_uses_inline_metadata(self) -> None:
        client = Keypair()
        fee_payer = Keypair()
        pay_to = Keypair()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
            "payTo": str(pay_to.pubkey()),
            "decimals": 6,
            "tokenProgram": str(TOKEN_PROGRAM_ID),
            "extra": {
                "feePayer": str(fee_payer.pubkey()),
                "recentBlockhash": str(Hash.default()),
            },
        }

        with patch("x402.interop.exact.fetch_mint_metadata") as fetch_metadata:
            header = build_exact_payment_signature_from_rpc(
                requirement=requirement,
                client_secret_key=client.to_json(),
                rpc_url="http://rpc.test",
            )

        fetch_metadata.assert_not_called()
        envelope = json.loads(base64.b64decode(header).decode("utf-8"))
        self.assertEqual(envelope["accepted"], requirement)

    def test_build_exact_payment_signature_from_rpc_fetches_missing_metadata(self) -> None:
        client = Keypair()
        fee_payer = Keypair()
        pay_to = Keypair()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
            "payTo": str(pay_to.pubkey()),
            "extra": {
                "feePayer": str(fee_payer.pubkey()),
            },
        }

        with patch(
            "x402.interop.exact.fetch_mint_metadata",
            return_value=MintMetadata(decimals=6, token_program=TOKEN_PROGRAM_ID),
        ) as fetch_metadata:
            with patch("x402.interop.exact.latest_blockhash", return_value=str(Hash.default())):
                header = build_exact_payment_signature_from_rpc(
                    requirement=requirement,
                    client_secret_key=client.to_json(),
                    rpc_url="http://rpc.test",
                    resource={"type": "http", "uri": "/protected"},
                )

        fetch_metadata.assert_called_once_with(
            "http://rpc.test",
            "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        )
        envelope = json.loads(base64.b64decode(header).decode("utf-8"))
        self.assertEqual(envelope["resource"], {"type": "http", "uri": "/protected"})

    def test_build_exact_payment_signature_rejects_non_exact_scheme(self) -> None:
        with self.assertRaisesRegex(ValueError, "only exact payment requirements can be signed"):
            build_exact_payment_signature(
                requirement={"scheme": "unsupported"},
                client_keypair=Keypair(),
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )

    def test_build_exact_payment_signature_reads_extra_amount_and_top_level_memo(self) -> None:
        client = Keypair()
        fee_payer = Keypair()
        pay_to = Keypair()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "payTo": str(pay_to.pubkey()),
            "memo": "top-level-memo",
            "extra": {
                "amount": "1000",
                "feePayer": str(fee_payer.pubkey()),
            },
        }

        header = build_exact_payment_signature(
            requirement=requirement,
            client_keypair=client,
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )
        envelope = json.loads(base64.b64decode(header).decode("utf-8"))
        transaction = VersionedTransaction.from_bytes(
            base64.b64decode(envelope["payload"]["transaction"])
        )

        memo_instruction = transaction.message.instructions[3]
        self.assertEqual(bytes(memo_instruction.data).decode("utf-8"), "top-level-memo")

    def test_build_exact_payment_signature_accepts_integer_amount_fields(self) -> None:
        client = Keypair()
        fee_payer = Keypair()
        pay_to = Keypair()
        base_requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "payTo": str(pay_to.pubkey()),
            "extra": {
                "feePayer": str(fee_payer.pubkey()),
            },
        }

        for requirement in [
            {**base_requirement, "amount": 1000},
            {**base_requirement, "extra": {**base_requirement["extra"], "amount": 1000}},
        ]:
            with self.subTest(requirement=requirement):
                header = build_exact_payment_signature(
                    requirement=requirement,
                    client_keypair=client,
                    blockhash=str(Hash.default()),
                    decimals=6,
                    token_program=TOKEN_PROGRAM_ID,
                )
                envelope = json.loads(base64.b64decode(header).decode("utf-8"))
                self.assertEqual(envelope["accepted"], requirement)

    def test_build_exact_payment_signature_rejects_missing_integer_amount(self) -> None:
        with self.assertRaisesRegex(ValueError, "payment requirement is missing integer amount"):
            build_exact_payment_signature(
                requirement={
                    "scheme": "exact",
                    "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                    "payTo": str(Keypair().pubkey()),
                    "extra": {
                        "feePayer": str(Keypair().pubkey()),
                    },
                },
                client_keypair=Keypair(),
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )


class FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], body: object) -> None:
        self.status = status
        self.headers = headers
        self._body = body

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        return None

    def read(self) -> bytes:
        body = self._body if isinstance(self._body, str) else json.dumps(self._body)
        return body.encode("utf-8")


class FakeHttpError(urllib.error.HTTPError):
    def __init__(self, status: int, headers: dict[str, str], body: object) -> None:
        super().__init__("http://example.test/protected", status, "error", headers, None)
        self._body = body

    def read(self) -> bytes:
        body = self._body if isinstance(self._body, str) else json.dumps(self._body)
        return body.encode("utf-8")


class ClientMainTests(unittest.TestCase):
    def test_main_requires_target_url(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "X402_INTEROP_TARGET_URL is required"):
                interop_client.main()

    def test_main_pays_exact_challenge_and_emits_paid_result(self) -> None:
        client_secret_key = Keypair().to_json()
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
        }
        challenge = {
            "x402Version": 2,
            "resource": {"type": "http", "uri": "/protected"},
            "accepts": [requirement],
        }
        paid_body = {"ok": True}

        with patch.dict(
            os.environ,
            {
                "X402_INTEROP_TARGET_URL": "http://example.test/protected",
                "X402_INTEROP_RPC_URL": "http://rpc.test",
                "X402_INTEROP_CLIENT_SECRET_KEY": client_secret_key,
            },
            clear=True,
        ):
            with patch(
                "x402.interop.client.urllib.request.urlopen",
                side_effect=[
                    FakeHttpError(402, {}, challenge),
                    FakeResponse(200, {"x-fixture-settlement": "signature-1"}, paid_body),
                ],
            ) as urlopen:
                with patch(
                    "x402.interop.client.build_exact_payment_signature_from_rpc",
                    return_value="payment-header",
                ) as build_signature:
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(interop_client.main(), 0)

        build_signature.assert_called_once_with(
            requirement=requirement,
            client_secret_key=client_secret_key,
            rpc_url="http://rpc.test",
            resource={"type": "http", "uri": "/protected"},
        )
        paid_request = urlopen.call_args_list[1].args[0]
        self.assertEqual(paid_request.headers["Payment-signature"], "payment-header")
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["status"], 200)
        self.assertEqual(payload["responseBody"], paid_body)
        self.assertEqual(payload["settlement"], "signature-1")

    def test_main_emits_paid_http_error_body_as_text_when_not_json(self) -> None:
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
        }
        challenge = {"x402Version": 2, "accepts": [requirement]}

        with patch.dict(
            os.environ,
            {
                "X402_INTEROP_TARGET_URL": "http://example.test/protected",
                "X402_INTEROP_RPC_URL": "http://rpc.test",
                "X402_INTEROP_CLIENT_SECRET_KEY": Keypair().to_json(),
            },
            clear=True,
        ):
            with patch(
                "x402.interop.client.urllib.request.urlopen",
                side_effect=[
                    FakeResponse(402, {}, challenge),
                    FakeHttpError(402, {}, "not-json"),
                ],
            ):
                with patch(
                    "x402.interop.client.build_exact_payment_signature_from_rpc",
                    return_value="payment-header",
                ):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(interop_client.main(), 0)

        payload = json.loads(output.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], 402)
        self.assertEqual(payload["responseBody"], "not-json")

    def test_main_emits_payment_failed_result_when_exact_signing_fails(self) -> None:
        requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
            "amount": "1000",
        }
        challenge = {"x402Version": 2, "accepts": [requirement]}

        with patch.dict(
            os.environ,
            {
                "X402_INTEROP_TARGET_URL": "http://example.test/protected",
                "X402_INTEROP_RPC_URL": "http://rpc.test",
                "X402_INTEROP_CLIENT_SECRET_KEY": Keypair().to_json(),
            },
            clear=True,
        ):
            with patch(
                "x402.interop.client.urllib.request.urlopen",
                side_effect=[FakeHttpError(402, {}, challenge)],
            ):
                with patch(
                    "x402.interop.client.build_exact_payment_signature_from_rpc",
                    side_effect=RuntimeError("metadata unavailable"),
                ):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        self.assertEqual(interop_client.main(), 0)

        payload = json.loads(output.getvalue())
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["responseBody"]["error"], "python_exact_client_payment_failed")
        self.assertEqual(payload["responseBody"]["message"], "metadata unavailable")


if __name__ == "__main__":
    unittest.main()
