import base64
import io
import json
import os
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.hash import Hash
from solders.instruction import Instruction
from solders.keypair import Keypair
from solders.message import MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.system_program import TransferParams
from solders.system_program import transfer as system_transfer
from solders.transaction import VersionedTransaction
from spl.token.constants import TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID
from spl.token.instructions import (
    TransferCheckedParams,
    get_associated_token_address,
    transfer_checked,
)

from x402.interop import server as interop_server
from x402.interop.exact import build_exact_payment_signature
from x402.interop.server import (
    CAPABILITY_PAYLOAD,
    DEFAULT_RESOURCE_PATH,
    DEFAULT_SETTLEMENT_HEADER,
    MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS,
    MEMO_PROGRAM_ID,
    SETTLEMENT_CACHE_TTL_SECONDS,
    InteropHandler,
    ServerState,
    _claim_settlement_payload,
    _header_value,
    _normalize_amount,
    _payment_requirement_matches,
    _required_env,
    _send_transaction,
    exact_challenge,
    exact_requirement,
    settle_exact_payment,
)


class State(ServerState):
    network = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"
    mint = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU"
    amount = "1000"
    pay_to = "11111111111111111111111111111112"
    fee_payer = Keypair()
    rpc_url = "http://127.0.0.1:0"
    extra_offered_mints: list[str] = []

    def __init__(self) -> None:
        # Mirror ServerState.__init__ so the shared lock actually serialises
        # concurrent claim attempts during stress tests, instead of falling
        # through to a per-call lazy-init fallback. We deliberately skip the
        # parent __init__ because it reads X402_INTEROP_* env vars that the
        # tests stub via class attributes above.
        self.settlement_cache: dict[str, float] = {}
        self.settlement_cache_lock = threading.Lock()


class MultiCurrencyState(State):
    extra_offered_mints = ["CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM"]


class FakeRpcResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc, _traceback):
        return None

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class FakeHttpServer:
    def __init__(self, address, handler_class):
        self.address = address
        self.handler_class = handler_class
        self.server_port = 12345
        self.served = False
        self.closed = False
        self.shutdown_called = False

    def serve_forever(self):
        self.served = True

    def server_close(self):
        self.closed = True

    def shutdown(self):
        self.shutdown_called = True


def encode_payment_signature(payload):
    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def retarget_header_to_server_requirement(header):
    envelope = json.loads(base64.b64decode(header).decode("utf-8"))
    envelope["accepted"] = exact_requirement(State())
    return encode_payment_signature(envelope)


def transaction_from_instructions(fee_payer, instructions, signers=()):
    message = MessageV0.try_compile(fee_payer, instructions, [], Hash.default())
    signatures = [Signature.default()] * message.header.num_required_signatures
    account_keys = list(message.account_keys)
    for signer in signers:
        if signer.pubkey() in account_keys:
            signer_index = account_keys.index(signer.pubkey())
            if signer_index < len(signatures):
                signatures[signer_index] = signer.sign_message(to_bytes_versioned(message))
    return VersionedTransaction.populate(message, signatures)


def transfer_checked_instruction(client, requirement, token_program=TOKEN_PROGRAM_ID):
    mint = Pubkey.from_string(str(requirement["asset"]))
    pay_to = Pubkey.from_string(str(requirement["payTo"]))
    return transfer_checked(
        TransferCheckedParams(
            program_id=token_program,
            source=get_associated_token_address(client.pubkey(), mint, token_program),
            mint=mint,
            dest=get_associated_token_address(pay_to, mint, token_program),
            owner=client.pubkey(),
            amount=int(str(requirement["amount"])),
            decimals=int(str(requirement["extra"]["decimals"])),
        )
    )


def header_from_transaction(transaction, accepted=None):
    return encode_payment_signature(
        {
            "x402Version": 2,
            "accepted": accepted or exact_requirement(State()),
            "payload": {
                "transaction": base64.b64encode(bytes(transaction)).decode("ascii"),
            },
        }
    )


def dispatch_get(path, headers=None, state=None):
    handler = object.__new__(InteropHandler)
    handler.path = path
    handler.headers = headers or {}  # pyright: ignore[reportAttributeAccessIssue]
    handler.server = type("Server", (), {"state": state or State()})()  # pyright: ignore[reportAttributeAccessIssue]
    writes = []
    handler._write_json = (
        lambda status, body, payment_required=None, headers=None: writes.append(
            {
                "status": status,
                "body": body,
                "payment_required": payment_required,
                "headers": headers,
            }
        )
    )

    InteropHandler.do_GET(handler)
    return writes[0]


class InteropServerTest(unittest.TestCase):
    def test_required_env_reads_present_values_and_rejects_missing(self):
        with patch.dict(os.environ, {"EXAMPLE_ENV": "value"}, clear=True):
            self.assertEqual(_required_env("EXAMPLE_ENV"), "value")
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(RuntimeError, "EXAMPLE_ENV is required"),
        ):
            _required_env("EXAMPLE_ENV")

    def test_server_state_reads_environment_defaults_and_extra_mints(self):
        fee_payer = Keypair()
        with patch.dict(
            os.environ,
            {
                "X402_INTEROP_RPC_URL": "http://rpc.test",
                "X402_INTEROP_PAY_TO": str(Keypair().pubkey()),
                "X402_INTEROP_FACILITATOR_SECRET_KEY": fee_payer.to_json(),
                "X402_INTEROP_PRICE": "$1.250001",
                "X402_INTEROP_EXTRA_OFFERED_MINTS": " mint-a, ,mint-b ",
            },
            clear=True,
        ):
            state = ServerState()

        self.assertEqual(state.rpc_url, "http://rpc.test")
        self.assertEqual(state.amount, "1250001")
        self.assertEqual(state.extra_offered_mints, ["mint-a", "mint-b"])
        self.assertEqual(state.settlement_cache, {})

    def test_normalizes_price_to_six_decimals(self):
        self.assertEqual(_normalize_amount("$0.001"), "1000")
        self.assertEqual(_normalize_amount("0.001 USDC"), "1000")
        self.assertEqual(_normalize_amount("1.25"), "1250000")

    def test_normalize_amount_rejects_more_than_six_decimals(self):
        with self.assertRaisesRegex(RuntimeError, "too many decimal places"):
            _normalize_amount("$0.0000001")

    def test_header_value_is_case_insensitive(self):
        self.assertEqual(_header_value({"payment-signature": "sig"}, "PAYMENT-SIGNATURE"), "sig")
        self.assertIsNone(_header_value({"content-type": "application/json"}, "PAYMENT-SIGNATURE"))

    def test_payment_requirement_matches_binds_settlement_fields(self):
        requirement = exact_requirement(State())
        self.assertTrue(_payment_requirement_matches(requirement, requirement))

        mutated = {
            **requirement,
            "extra": {
                **requirement["extra"],
                "feePayer": "11111111111111111111111111111114",
            },
        }
        self.assertFalse(_payment_requirement_matches(mutated, requirement))

    def test_payment_requirement_matches_rejects_accepted_drift(self):
        requirement = exact_requirement(State())

        with self.subTest("maxTimeoutSeconds"):
            mutated = {**requirement, "maxTimeoutSeconds": requirement["maxTimeoutSeconds"] + 1}
            self.assertFalse(_payment_requirement_matches(mutated, requirement))

        with self.subTest("unexpected top-level field"):
            mutated = {**requirement, "description": "client-added drift"}
            self.assertFalse(_payment_requirement_matches(mutated, requirement))

        with self.subTest("unexpected extra field"):
            mutated = {
                **requirement,
                "extra": {
                    **requirement["extra"],
                    "memo": "client-added-drift",
                },
            }
            self.assertFalse(_payment_requirement_matches(mutated, requirement))

    def test_exact_challenge_advertises_extra_offered_mints(self):
        challenge = exact_challenge(MultiCurrencyState())

        self.assertEqual(
            [requirement["asset"] for requirement in challenge["accepts"]],
            [
                "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
                "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
            ],
        )
        self.assertEqual(
            challenge["accepts"][0]["extra"]["tokenProgram"],
            str(TOKEN_PROGRAM_ID),
        )
        self.assertEqual(
            challenge["accepts"][1]["extra"]["tokenProgram"],
            str(TOKEN_2022_PROGRAM_ID),
        )

    def test_settle_rejects_malformed_payment_signature_header(self):
        with self.assertRaisesRegex(RuntimeError, "invalid PAYMENT-SIGNATURE: invalid base64"):
            settle_exact_payment(State(), "not base64!!!")

        invalid_json = base64.b64encode(b"not json").decode("ascii")
        with self.assertRaisesRegex(RuntimeError, "invalid PAYMENT-SIGNATURE: invalid json"):
            settle_exact_payment(State(), invalid_json)

        non_object = base64.b64encode(b"[]").decode("ascii")
        with self.assertRaisesRegex(RuntimeError, "invalid PAYMENT-SIGNATURE: expected object"):
            settle_exact_payment(State(), non_object)

    def test_settle_rejects_malformed_payment_envelope(self):
        requirement = exact_requirement(State())

        with self.subTest("version"):
            unsupported_version = encode_payment_signature(
                {
                    "x402Version": 1,
                    "accepted": requirement,
                    "payload": {"transaction": "unused"},
                }
            )
            with self.assertRaisesRegex(RuntimeError, "unsupported x402Version: 1"):
                settle_exact_payment(State(), unsupported_version)

        with self.subTest("accepted"):
            missing_accepted = encode_payment_signature(
                {
                    "x402Version": 2,
                    "payload": {"transaction": "unused"},
                }
            )
            with self.assertRaisesRegex(
                RuntimeError,
                "No matching payment requirements",
            ):
                settle_exact_payment(State(), missing_accepted)

        with self.subTest("payload"):
            non_object_payload = encode_payment_signature(
                {
                    "x402Version": 2,
                    "accepted": requirement,
                    "payload": [],
                }
            )
            with self.assertRaisesRegex(RuntimeError, "payment payload is missing transaction"):
                settle_exact_payment(State(), non_object_payload)

    def test_settle_rejects_missing_or_invalid_transaction_payload(self):
        requirement = exact_requirement(State())

        missing_transaction = encode_payment_signature(
            {
                "x402Version": 2,
                "accepted": requirement,
                "payload": {},
            }
        )
        with self.assertRaisesRegex(RuntimeError, "payment payload is missing transaction"):
            settle_exact_payment(State(), missing_transaction)

        invalid_base64_transaction = encode_payment_signature(
            {
                "x402Version": 2,
                "accepted": requirement,
                "payload": {"transaction": "not base64!!!"},
            }
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_transaction_could_not_be_decoded",
        ):
            settle_exact_payment(State(), invalid_base64_transaction)

        invalid_wire_transaction = encode_payment_signature(
            {
                "x402Version": 2,
                "accepted": requirement,
                "payload": {"transaction": base64.b64encode(b"not a transaction").decode("ascii")},
            }
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_transaction_could_not_be_decoded",
        ):
            settle_exact_payment(State(), invalid_wire_transaction)

    def test_settle_rejects_transaction_amount_mismatch_before_broadcast(self):
        requirement = {
            **exact_requirement(State()),
            "amount": "999",
        }
        header = retarget_header_to_server_requirement(
            build_exact_payment_signature(
                requirement=requirement,
                client_keypair=Keypair(),
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )
        )

        with self.assertRaisesRegex(RuntimeError, "invalid_exact_svm_payload_amount_mismatch"):
            settle_exact_payment(State(), header)

    def test_settle_rejects_transaction_pay_to_mismatch_before_broadcast(self):
        requirement = {
            **exact_requirement(State()),
            "payTo": str(Keypair().pubkey()),
        }
        header = retarget_header_to_server_requirement(
            build_exact_payment_signature(
                requirement=requirement,
                client_keypair=Keypair(),
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )
        )

        with self.assertRaisesRegex(RuntimeError, "invalid_exact_svm_payload_recipient_mismatch"):
            settle_exact_payment(State(), header)

    def test_settle_rejects_transaction_mint_mismatch_before_broadcast(self):
        requirement = {
            **exact_requirement(State()),
            "asset": str(Keypair().pubkey()),
        }
        header = retarget_header_to_server_requirement(
            build_exact_payment_signature(
                requirement=requirement,
                client_keypair=Keypair(),
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )
        )

        with self.assertRaisesRegex(RuntimeError, "invalid_exact_svm_payload_mint_mismatch"):
            settle_exact_payment(State(), header)

    def test_settle_accepts_extra_offered_mint_before_broadcast(self):
        state = MultiCurrencyState()
        requirement = exact_challenge(state)["accepts"][1]
        header = build_exact_payment_signature(
            requirement=requirement,
            client_keypair=Keypair(),
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_2022_PROGRAM_ID,
        )

        with patch("x402.interop.server._send_transaction", return_value="signature-1"):
            self.assertEqual(settle_exact_payment(state, header), "signature-1")

    def test_settle_rejects_missing_transfer_instruction_before_broadcast(self):
        transaction = transaction_from_instructions(
            State.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                set_compute_unit_price(1),
                Instruction(MEMO_PROGRAM_ID, b"memo-only", []),
            ],
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_no_transfer_instruction",
        ):
            settle_exact_payment(State(), header_from_transaction(transaction))

    def test_settle_rejects_invalid_compute_limit_instruction_before_broadcast(self):
        client = Keypair()
        requirement = exact_requirement(State())
        transaction = transaction_from_instructions(
            State.fee_payer.pubkey(),
            [
                Instruction(MEMO_PROGRAM_ID, b"not-compute-limit", []),
                set_compute_unit_price(1),
                transfer_checked_instruction(client, requirement),
            ],
            signers=(client,),
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction",
        ):
            settle_exact_payment(State(), header_from_transaction(transaction))

    def test_settle_rejects_invalid_compute_price_instruction_before_broadcast(self):
        client = Keypair()
        requirement = exact_requirement(State())
        transaction = transaction_from_instructions(
            State.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                Instruction(MEMO_PROGRAM_ID, b"not-compute-price", []),
                transfer_checked_instruction(client, requirement),
            ],
            signers=(client,),
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction",
        ):
            settle_exact_payment(State(), header_from_transaction(transaction))

    def test_settle_rejects_compute_unit_price_above_reference_limit(self):
        client = Keypair()
        requirement = exact_requirement(State())
        transaction = transaction_from_instructions(
            State.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                set_compute_unit_price(MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS + 1),
                transfer_checked_instruction(client, requirement),
            ],
            signers=(client,),
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high",
        ):
            settle_exact_payment(State(), header_from_transaction(transaction))

    def test_compute_limit_intentionally_unbounded_matches_rust_spine(self):
        """Parity check: the CU *limit* value is intentionally unbounded.

        Mirrors verify_compute_limit_instruction in
        rust/src/protocol/schemes/exact/verify.rs (~L317) and
        verifyComputeLimitInstruction in
        typescript/packages/x402/src/facilitator/exact/scheme.ts (~L444),
        both of which only validate program id / payload length /
        SetComputeUnitLimit discriminator and do NOT bound the limit value.
        Greptile P1 flagged the lack of an upper bound; the deliberate
        decision is to keep cross-implementation parity until the spine
        introduces a cap. If a cap is added upstream, this test should
        flip to assert rejection above the cap.
        """
        from x402.interop import server as server_module

        client = Keypair()
        requirement = exact_requirement(State())
        # Solana's per-transaction max compute units (1.4M) — the exact
        # value flagged by Greptile as a fee-drain risk if combined with
        # the price cap. Expected behavior today: accepted at the
        # instruction-shape layer (no upper bound enforced).
        max_per_tx_cu = 1_400_000
        transaction = transaction_from_instructions(
            State.fee_payer.pubkey(),
            [
                set_compute_unit_limit(max_per_tx_cu),
                set_compute_unit_price(1),
                transfer_checked_instruction(client, requirement),
            ],
            signers=(client,),
        )
        compiled = transaction.message.instructions
        account_keys = list(transaction.message.account_keys)

        # Must NOT raise — parity with Rust + TS spine.
        server_module._verify_compute_limit_instruction(compiled[0], account_keys)

    def test_settle_rejects_fee_payer_as_transfer_authority_before_broadcast(self):
        header = build_exact_payment_signature(
            requirement=exact_requirement(State()),
            client_keypair=State.fee_payer,
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_transaction_fee_payer_transferring_funds",
        ):
            settle_exact_payment(State(), header)

    def test_settle_rejects_transfer_instruction_shape_before_broadcast(self):
        transaction = transaction_from_instructions(
            State.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                set_compute_unit_price(1),
                Instruction(TOKEN_PROGRAM_ID, b"bad-transfer", []),
            ],
        )

        with self.assertRaisesRegex(RuntimeError, "invalid_exact_svm_payload_no_transfer_instruction"):
            settle_exact_payment(State(), header_from_transaction(transaction))

    def test_settle_rejects_memo_mismatch_before_broadcast(self):
        expected_requirement = {
            **exact_requirement(State()),
            "extra": {
                **exact_requirement(State())["extra"],
                "memo": "expected-memo",
            },
        }
        transaction_requirement = {
            **expected_requirement,
            "extra": {
                **expected_requirement["extra"],
                "memo": "actual-memo",
            },
        }
        header = build_exact_payment_signature(
            requirement=transaction_requirement,
            client_keypair=Keypair(),
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )
        envelope = json.loads(base64.b64decode(header).decode("utf-8"))
        envelope["accepted"] = expected_requirement

        with patch(
            "x402.interop.server.exact_requirements",
            return_value=[expected_requirement],
        ), self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_memo_mismatch",
        ):
            settle_exact_payment(State(), encode_payment_signature(envelope))

    def test_settle_rejects_missing_expected_memo_before_broadcast(self):
        expected_requirement = {
            **exact_requirement(State()),
            "extra": {
                **exact_requirement(State())["extra"],
                "memo": "expected-memo",
            },
        }
        transaction_requirement = {
            **expected_requirement,
            "extra": {
                **expected_requirement["extra"],
            },
        }
        del transaction_requirement["extra"]["memo"]
        header = build_exact_payment_signature(
            requirement=transaction_requirement,
            client_keypair=Keypair(),
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )
        envelope = json.loads(base64.b64decode(header).decode("utf-8"))
        envelope["accepted"] = expected_requirement

        with patch(
            "x402.interop.server.exact_requirements",
            return_value=[expected_requirement],
        ), self.assertRaisesRegex(RuntimeError, "invalid_exact_svm_payload_memo_mismatch"):
            settle_exact_payment(State(), encode_payment_signature(envelope))

    def test_settle_allows_lighthouse_optional_instruction_before_broadcast(self):
        client = Keypair()
        requirement = exact_requirement(State())
        transaction = transaction_from_instructions(
            State.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                set_compute_unit_price(1),
                transfer_checked_instruction(client, requirement),
                Instruction(Pubkey.from_string("L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"), b"", []),
            ],
            signers=(client,),
        )

        with patch("x402.interop.server._send_transaction", return_value="signature-1"):
            self.assertEqual(settle_exact_payment(State(), header_from_transaction(transaction)), "signature-1")

    def test_settle_accepts_lighthouse_with_varied_discriminators_and_accounts(self):
        # Parity regression: the Rust spine
        # (rust/src/protocol/schemes/exact/verify.rs L260-272) and the TS spine
        # (typescript/packages/x402/src/facilitator/exact/scheme.ts L289-296)
        # both accept any Lighthouse instruction unconditionally — no
        # discriminator allowlist, no account-count cap. The Python adapter
        # MUST mirror this until a protocol-wide hardening lands in the
        # canonical Rust spine (see notes/lighthouse-allowlist-tracking.md).
        # Diverging here unilaterally would silently break interop with real
        # Phantom / Solflare-signed mainnet transactions.
        lighthouse_program = Pubkey.from_string(
            "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
        )
        scenarios = [
            # (label, discriminator_byte, payload_tail, account_count)
            ("empty_payload_no_accounts", None, b"", 0),
            ("known_discriminator_2_accounts", 0x02, b"\x00" * 32, 2),
            ("unrecognized_discriminator_high_byte", 0xFE, b"\x11" * 8, 1),
            ("oversized_payload_many_accounts", 0x05, b"\x42" * 256, 16),
        ]
        for label, disc, tail, account_count in scenarios:
            with self.subTest(scenario=label):
                client = Keypair()
                requirement = exact_requirement(State())
                data = b"" if disc is None else bytes([disc]) + tail
                # Fresh dummy account metas (read-only, non-signer); per the
                # spine, the optional-instruction account-list shape is not
                # inspected at all.
                from solders.instruction import AccountMeta
                accounts = [
                    AccountMeta(Keypair().pubkey(), False, False)
                    for _ in range(account_count)
                ]
                transaction = transaction_from_instructions(
                    State.fee_payer.pubkey(),
                    [
                        set_compute_unit_limit(20_000),
                        set_compute_unit_price(1),
                        transfer_checked_instruction(client, requirement),
                        Instruction(lighthouse_program, data, accounts),
                    ],
                    signers=(client,),
                )
                with patch(
                    "x402.interop.server._send_transaction",
                    return_value=f"signature-{label}",
                ):
                    self.assertEqual(
                        settle_exact_payment(
                            State(), header_from_transaction(transaction)
                        ),
                        f"signature-{label}",
                    )

    def test_settle_rejects_unknown_optional_instruction_before_broadcast(self):
        client = Keypair()
        requirement = exact_requirement(State())
        transaction = transaction_from_instructions(
            State.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                set_compute_unit_price(1),
                transfer_checked_instruction(client, requirement),
                Instruction(Keypair().pubkey(), b"unknown", []),
            ],
            signers=(client,),
        )

        with self.assertRaisesRegex(RuntimeError, "invalid_exact_svm_payload_unknown_fourth_instruction"):
            settle_exact_payment(State(), header_from_transaction(transaction))

    def test_settle_releases_duplicate_claim_when_fee_payer_is_missing(self):
        other_fee_payer = Keypair()
        transaction_requirement = {
            **exact_requirement(State()),
            "extra": {
                **exact_requirement(State())["extra"],
                "feePayer": str(other_fee_payer.pubkey()),
            },
        }
        header = retarget_header_to_server_requirement(
            build_exact_payment_signature(
                requirement=transaction_requirement,
                client_keypair=Keypair(),
                blockhash=str(Hash.default()),
                decimals=6,
                token_program=TOKEN_PROGRAM_ID,
            )
        )
        state = State()

        for _attempt in range(2):
            with self.assertRaisesRegex(
                RuntimeError,
                "fee payer not found in transaction accounts",
            ):
                settle_exact_payment(state, header)

    def test_settle_rejects_duplicate_transaction_payload(self):
        header = build_exact_payment_signature(
            requirement=exact_requirement(State()),
            client_keypair=Keypair(),
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )
        state = State()

        with patch("x402.interop.server._send_transaction", return_value="signature-1"):
            self.assertEqual(settle_exact_payment(state, header), "signature-1")
            with self.assertRaisesRegex(RuntimeError, "duplicate_settlement"):
                settle_exact_payment(state, header)

    def test_settle_releases_duplicate_claim_when_broadcast_fails(self):
        header = build_exact_payment_signature(
            requirement=exact_requirement(State()),
            client_keypair=Keypair(),
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )
        state = State()

        with patch("x402.interop.server._send_transaction", side_effect=RuntimeError("rpc down")):
            for _attempt in range(2):
                with self.assertRaisesRegex(RuntimeError, "rpc down"):
                    settle_exact_payment(state, header)

    def test_settlement_cache_prunes_expired_claims(self):
        state = State()
        _claim_settlement_payload(state, "transaction-payload")
        state.settlement_cache["transaction-payload"] -= SETTLEMENT_CACHE_TTL_SECONDS + 1

        _claim_settlement_payload(state, "transaction-payload")

        self.assertIn("transaction-payload", state.settlement_cache)

    def test_send_transaction_posts_base64_transaction_and_handles_rpc_responses(self):
        transaction = transaction_from_instructions(State.fee_payer.pubkey(), [set_compute_unit_limit(20_000)])
        state = State()
        state.rpc_url = "http://rpc.test"

        with patch(
            "x402.interop.server.urllib.request.urlopen",
            return_value=FakeRpcResponse({"result": "signature-1"}),
        ) as urlopen:
            self.assertEqual(_send_transaction(state, transaction), "signature-1")

        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://rpc.test")
        self.assertEqual(request.get_method(), "POST")
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["method"], "sendTransaction")
        self.assertEqual(body["params"][1]["encoding"], "base64")

        with patch(
            "x402.interop.server.urllib.request.urlopen",
            return_value=FakeRpcResponse({"error": {"message": "boom"}}),
        ), self.assertRaisesRegex(RuntimeError, "sendTransaction RPC error"):
            _send_transaction(state, transaction)

        with patch(
            "x402.interop.server.urllib.request.urlopen",
            return_value=FakeRpcResponse({"result": ""}),
        ), self.assertRaisesRegex(RuntimeError, "sendTransaction returned empty signature"):
            _send_transaction(state, transaction)

    def test_get_routes_emit_expected_responses_without_socket_io(self):
        cases = [
            ("/health", 200, {"ok": True}, None),
            ("/capabilities", 200, CAPABILITY_PAYLOAD, None),
            ("/exact", 402, {"error": "payment_required"}, exact_challenge(State())),
            ("/missing", 404, {"error": "not_found"}, None),
        ]

        for path, status, body, payment_required in cases:
            with self.subTest(path=path):
                write = dispatch_get(path)
                self.assertEqual(write["status"], status)
                self.assertEqual(write["body"], body)
                self.assertEqual(write["payment_required"], payment_required)

    def test_protected_route_requires_payment_signature(self):
        write = dispatch_get(DEFAULT_RESOURCE_PATH)

        self.assertEqual(write["status"], 402)
        self.assertEqual(write["body"], {"error": "payment_required"})
        self.assertEqual(write["payment_required"], exact_challenge(State()))

    def test_protected_route_settles_payment_signature(self):
        with patch("x402.interop.server.settle_exact_payment", return_value="signature-1") as settle:
            write = dispatch_get(DEFAULT_RESOURCE_PATH, headers={"payment-signature": "payment-header"})

        settle.assert_called_once()
        self.assertEqual(write["status"], 200)
        self.assertEqual(write["headers"], {DEFAULT_SETTLEMENT_HEADER: "signature-1"})
        self.assertEqual(write["body"]["settlement"]["transaction"], "signature-1")

    def test_protected_route_returns_payment_error_on_settlement_failure(self):
        with patch(
            "x402.interop.server.settle_exact_payment",
            side_effect=RuntimeError("invalid payment"),
        ):
            write = dispatch_get(DEFAULT_RESOURCE_PATH, headers={"payment-signature": "payment-header"})

        self.assertEqual(write["status"], 402)
        self.assertEqual(write["body"]["invalidReason"], "invalid payment")
        self.assertEqual(write["payment_required"], exact_challenge(State()))

    def test_server_rejects_cross_server_credential_with_canonical_token(self):
        """Cross-server replay regression: when server B receives a credential
        whose `accepted` block targets a different server's pay-to / asset /
        amount, server B must reject (non-2xx) AND the response body must
        carry one of the canonical tokens recognised by the interop
        cross-server-scenarios harness (see tests/interop). Mirrors Go's
        reject body shape (go/cmd/interop-server/main.go ~L856:
        `{"error": "payment_invalid", "message": ...}`).
        """
        canonical_tokens = (
            "invalid_exact_svm_payload_recipient_mismatch",
            "recipient_mismatch",
            "Destination ATA does not belong to expected recipient",
            "AtaMismatch",
            "challenge_verification_failed",
            "verification_failed",
            "unauthorized",
            "No matching payment requirements",
            "does not match any offered payment option",
            "payment_invalid",
        )

        # Construct a credential whose `accepted` points at a *different*
        # server's requirements (different payTo / amount / asset) — i.e. the
        # exact cross-server replay scenario.
        foreign_requirement = {
            "scheme": "exact",
            "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
            "asset": "So11111111111111111111111111111111111111112",
            "amount": "99999",
            "payTo": str(Keypair().pubkey()),
            "maxTimeoutSeconds": 60,
            "extra": {
                "feePayer": str(Keypair().pubkey()),
                "decimals": 6,
                "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            },
        }
        foreign_header = encode_payment_signature(
            {
                "x402Version": 2,
                "accepted": foreign_requirement,
                "payload": {"transaction": "irrelevant-bytes"},
            }
        )

        write = dispatch_get(
            DEFAULT_RESOURCE_PATH,
            headers={"payment-signature": foreign_header},
        )

        self.assertGreaterEqual(write["status"], 400)
        self.assertLess(write["status"], 600)
        body_blob = json.dumps(write["body"]).lower()
        self.assertTrue(
            any(token.lower() in body_blob for token in canonical_tokens),
            f"cross-server reject body missing canonical token; got: {write['body']}",
        )

    def test_write_json_sets_content_headers_and_payment_required_header(self):
        handler = object.__new__(InteropHandler)
        sent = []
        handler.send_response = lambda status: sent.append(("response", status))  # pyright: ignore[reportAttributeAccessIssue]
        handler.send_header = lambda name, value: sent.append(("header", name, value))  # pyright: ignore[reportAttributeAccessIssue]
        handler.end_headers = lambda: sent.append(("end",))
        handler.wfile = io.BytesIO()

        InteropHandler._write_json(
            handler,
            402,
            {"error": "payment_required"},
            payment_required=exact_challenge(State()),
            headers={"x-extra": "1"},
        )

        self.assertEqual(sent[0], ("response", 402))
        self.assertIn(("header", "content-type", "application/json"), sent)
        self.assertIn(("header", "x-extra", "1"), sent)
        payment_required_headers = [
            item[2] for item in sent if item[0] == "header" and item[1] == "PAYMENT-REQUIRED"
        ]
        self.assertEqual(
            json.loads(base64.b64decode(payment_required_headers[0]).decode("utf-8")),
            exact_challenge(State()),
        )
        self.assertEqual(handler.wfile.getvalue(), b'{"error":"payment_required"}')

    def test_log_message_is_silent(self):
        self.assertIsNone(InteropHandler.log_message(object.__new__(InteropHandler), "hello %s", "world"))

    def test_main_starts_server_prints_ready_payload_and_closes(self):
        servers = []
        signal_handlers = []
        fake_state = State()

        def make_server(address, handler_class):
            server = FakeHttpServer(address, handler_class)
            servers.append(server)
            return server

        output = io.StringIO()
        with (
            patch("x402.interop.server.ServerState", return_value=fake_state),
            patch("x402.interop.server.ThreadingHTTPServer", side_effect=make_server),
            patch(
                "x402.interop.server.signal.signal",
                side_effect=lambda signum, handler: signal_handlers.append((signum, handler)),
            ),
            patch("sys.stdout", output),
        ):
            self.assertEqual(interop_server.main(), 0)

        self.assertEqual(servers[0].address, ("127.0.0.1", 0))
        self.assertIs(servers[0].handler_class, InteropHandler)
        self.assertIs(servers[0].state, fake_state)
        self.assertTrue(servers[0].served)
        self.assertTrue(servers[0].closed)
        ready = json.loads(output.getvalue())
        self.assertEqual(ready["type"], "ready")
        self.assertEqual(ready["port"], 12345)
        self.assertIn("exact", ready["capabilities"])

        signal_handlers[0][1](0, None)
        self.assertTrue(servers[0].shutdown_called)

    def test_payment_errors_are_normalized(self):
        body = InteropHandler.payment_error_body(RuntimeError("sendTransaction RPC error: {}"))

        self.assertEqual(
            body,
            {
                "error": "payment_invalid",
                "message": "sendTransaction RPC error: {}",
                "invalidReason": "sendTransaction RPC error: {}",
            },
        )


class FeePayerAttackRegressionTest(unittest.TestCase):
    """MPP §19.5 attack regression: fee-payer co-signing must never permit
    draining the server's fee_payer account via SOL transfers, SPL transfers
    from the fee_payer's ATA, signer-slot manipulation, or tampered metadata.
    """

    def _state(self):
        return State()

    def _legit_instructions(self, state, client):
        requirement = exact_requirement(state)
        return [
            set_compute_unit_limit(20_000),
            set_compute_unit_price(1),
            transfer_checked_instruction(client, requirement, TOKEN_PROGRAM_ID),
            Instruction(MEMO_PROGRAM_ID, b"nonce-1234567890abcdef", []),
        ]

    def test_positive_control_clean_payment_settles(self):
        state = self._state()
        client = Keypair()
        header = build_exact_payment_signature(
            requirement=exact_requirement(state),
            client_keypair=client,
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )
        with patch("x402.interop.server._send_transaction", return_value="sig-ok"):
            self.assertEqual(settle_exact_payment(state, header), "sig-ok")

    def test_drain_via_system_program_transfer_from_fee_payer_is_rejected(self):
        """DRAIN: extra SystemProgram.Transfer drains lamports from fee_payer."""
        state = self._state()
        client = Keypair()
        attacker = Keypair()
        instructions = self._legit_instructions(state, client)
        instructions.append(
            system_transfer(
                TransferParams(
                    from_pubkey=state.fee_payer.pubkey(),
                    to_pubkey=attacker.pubkey(),
                    lamports=1_000_000_000,
                )
            )
        )
        tx = transaction_from_instructions(state.fee_payer.pubkey(), instructions, signers=[client])
        header = header_from_transaction(tx)
        with self.assertRaisesRegex(
            RuntimeError,
            "fee_payer_transferring_funds|unknown_(fourth|fifth|sixth)_instruction",
        ):
            settle_exact_payment(state, header)

    def test_spl_drain_via_extra_transfer_checked_from_fee_payer_ata_is_rejected(self):
        """SPL DRAIN: extra transferChecked from fee_payer's ATA to attacker."""
        state = self._state()
        client = Keypair()
        attacker = Keypair()
        mint = Pubkey.from_string(state.mint)
        instructions = self._legit_instructions(state, client)
        instructions.append(
            transfer_checked(
                TransferCheckedParams(
                    program_id=TOKEN_PROGRAM_ID,
                    source=get_associated_token_address(state.fee_payer.pubkey(), mint, TOKEN_PROGRAM_ID),
                    mint=mint,
                    dest=get_associated_token_address(attacker.pubkey(), mint, TOKEN_PROGRAM_ID),
                    owner=state.fee_payer.pubkey(),
                    amount=1,
                    decimals=6,
                )
            )
        )
        tx = transaction_from_instructions(state.fee_payer.pubkey(), instructions, signers=[client])
        header = header_from_transaction(tx)
        # The extra instruction references fee_payer (as transfer authority),
        # so _verify_exact_transaction's account-scan rejects it before the
        # optional-instruction allowlist runs.
        with self.assertRaisesRegex(
            RuntimeError,
            "fee_payer_transferring_funds|unknown_(fourth|fifth|sixth)_instruction",
        ):
            settle_exact_payment(state, header)

    def test_slot_attack_fee_payer_at_signer_slot_one_is_rejected(self):
        """SLOT: build the message with a non-fee-payer pubkey at slot 0 so
        state.fee_payer lands at signer slot 1. The transfer instruction then
        references the slot-0 signer as the transfer authority, which is not
        a valid exact payment and must fail."""
        state = self._state()
        client = Keypair()
        exact_requirement(state)
        mint = Pubkey.from_string(state.mint)
        pay_to = Pubkey.from_string(state.pay_to)
        # Compile with client as fee_payer (slot 0); state.fee_payer is added
        # as an additional account by referencing it via a system_transfer.
        instructions = [
            set_compute_unit_limit(20_000),
            set_compute_unit_price(1),
            transfer_checked(
                TransferCheckedParams(
                    program_id=TOKEN_PROGRAM_ID,
                    source=get_associated_token_address(client.pubkey(), mint, TOKEN_PROGRAM_ID),
                    mint=mint,
                    dest=get_associated_token_address(pay_to, mint, TOKEN_PROGRAM_ID),
                    owner=client.pubkey(),
                    amount=int(state.amount),
                    decimals=6,
                )
            ),
            Instruction(MEMO_PROGRAM_ID, b"nonce", []),
            system_transfer(
                TransferParams(
                    from_pubkey=state.fee_payer.pubkey(),
                    to_pubkey=client.pubkey(),
                    lamports=1,
                )
            ),
        ]
        tx = transaction_from_instructions(client.pubkey(), instructions, signers=[client, state.fee_payer])
        header = header_from_transaction(tx)
        with self.assertRaisesRegex(
            RuntimeError,
            "fee_payer_transferring_funds|unknown_(fourth|fifth|sixth)_instruction|invalid_exact_svm_payload",
        ):
            settle_exact_payment(state, header)

    def test_tampered_details_fee_payer_in_accepted_is_rejected(self):
        """Client mutates accepted.extra.feePayer to point at an attacker
        address. Strict requirement match rejects before any signing."""
        state = self._state()
        client = Keypair()
        attacker = Keypair()
        tampered_requirement = {
            **exact_requirement(state),
            "extra": {
                **exact_requirement(state)["extra"],
                "feePayer": str(attacker.pubkey()),
            },
        }
        header = build_exact_payment_signature(
            requirement=tampered_requirement,
            client_keypair=client,
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )
        with self.assertRaisesRegex(
            RuntimeError,
            "No matching payment requirements",
        ):
            settle_exact_payment(state, header)


class SettlementCacheConcurrencyTest(unittest.TestCase):
    """Regression for the prior Greptile P1: ThreadingHTTPServer dispatches
    each request on its own thread. _claim_settlement_payload must hold the
    cache lock across the check+insert so two concurrent identical payloads
    cannot both pass the duplicate guard."""

    def test_concurrent_duplicate_settlements_yield_exactly_one_success(self):
        state = State()
        client = Keypair()
        header = build_exact_payment_signature(
            requirement=exact_requirement(state),
            client_keypair=client,
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )

        start = threading.Event()
        # Slow the send call so both threads race the claim, not the network.
        def slow_send(_state, _tx):
            start.wait(timeout=2)
            return "broadcast-sig"

        with (
            patch("x402.interop.server._send_transaction", side_effect=slow_send),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
                f1 = pool.submit(settle_exact_payment, state, header)
                f2 = pool.submit(settle_exact_payment, state, header)
                start.set()
                results = []
                for fut in (f1, f2):
                    try:
                        results.append(("ok", fut.result()))
                    except RuntimeError as err:
                        results.append(("err", str(err)))

        successes = [r for r in results if r[0] == "ok"]
        errors = [r for r in results if r[0] == "err"]
        self.assertEqual(len(successes), 1, f"expected exactly one success, got {results}")
        self.assertEqual(len(errors), 1, f"expected exactly one duplicate error, got {results}")
        self.assertIn("duplicate_settlement", errors[0][1])

    def test_signature_verify_failure_releases_duplicate_claim(self):
        """Codex P3 #6: a structurally valid payload whose client signature
        fails verify_and_hash_message must release the cache so honest retries
        with a valid signature can still settle (within TTL)."""
        state = State()
        client = Keypair()
        header = build_exact_payment_signature(
            requirement=exact_requirement(state),
            client_keypair=client,
            blockhash=str(Hash.default()),
            decimals=6,
            token_program=TOKEN_PROGRAM_ID,
        )

        with patch(
            "x402.interop.server.VersionedTransaction.verify_and_hash_message",
            side_effect=RuntimeError("bad signature"),
        ), self.assertRaisesRegex(RuntimeError, "bad signature"):
            settle_exact_payment(state, header)

        with patch("x402.interop.server._send_transaction", return_value="sig-2"):
            self.assertEqual(settle_exact_payment(state, header), "sig-2")

    def test_claim_settlement_payload_serializes_under_thread_contention(self):
        """Direct stress on the claim helper: 32 threads racing on the same
        payload key — exactly one may insert."""
        state = State()
        payload = "race-key"
        successes = []
        failures = []
        barrier = threading.Barrier(32)

        def worker():
            barrier.wait()
            try:
                _claim_settlement_payload(state, payload)
                successes.append(1)
            except RuntimeError as err:
                failures.append(str(err))

        with ThreadPoolExecutor(max_workers=32) as pool:
            for _ in range(32):
                pool.submit(worker)

        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 31)
        self.assertTrue(all("duplicate_settlement" in f for f in failures))

    def test_claim_settlement_payload_fails_loudly_without_eager_cache(self):
        """Regression: the helpers must refuse to operate on a state object
        missing the eager-init fields. Previously they lazy-initialised a
        per-call Lock, which silently defeated the concurrency guard."""

        class BareState:
            pass

        bare = BareState()
        with self.assertRaisesRegex(RuntimeError, "settlement_cache_lock"):
            _claim_settlement_payload(bare, "payload-key")  # type: ignore[arg-type]

        # Even with a lock present, a missing cache must also fail loudly.
        bare.settlement_cache_lock = threading.Lock()  # type: ignore[attr-defined]
        with self.assertRaisesRegex(RuntimeError, "settlement_cache"):
            _claim_settlement_payload(bare, "payload-key")  # type: ignore[arg-type]


class TokenProgramBindingRegressionTest(unittest.TestCase):
    """Regression: the on-chain transfer's program ID must match the
    requirement's ``extra.tokenProgram``. Without this binding a malicious
    payer could substitute an SPL Token transfer for a Token-2022 requirement
    (or vice versa) whenever the destination ATAs happened to coincide.

    Mirrors the spine binding implemented in PHP, Ruby, and Lua ports.
    """

    def test_mismatch_requirement_spl_transaction_token2022_is_rejected(self):
        """P1: requirement advertises SPL Token, transaction uses Token-2022."""
        state = State()
        client = Keypair()
        requirement = exact_requirement(state)
        # State.mint is an SPL Token mint (not in TOKEN_2022_STABLECOIN_MINTS),
        # so requirement['extra']['tokenProgram'] is the SPL Token program.
        self.assertEqual(
            requirement["extra"]["tokenProgram"],
            str(TOKEN_PROGRAM_ID),
        )
        tx = transaction_from_instructions(
            state.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                set_compute_unit_price(1),
                # Build the transfer with Token-2022 even though the requirement
                # advertises the SPL Token program.
                transfer_checked_instruction(client, requirement, TOKEN_2022_PROGRAM_ID),
            ],
            signers=[client],
        )
        header = header_from_transaction(tx, accepted=requirement)
        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_no_transfer_instruction",
        ):
            settle_exact_payment(state, header)

    def test_mismatch_requirement_token2022_transaction_spl_is_rejected(self):
        """P1 reverse: requirement advertises Token-2022, transaction uses SPL Token."""
        state = MultiCurrencyState()
        client = Keypair()
        # accepts[1] uses the Token-2022 stablecoin mint -> tokenProgram = Token-2022.
        requirement = exact_challenge(state)["accepts"][1]
        self.assertEqual(
            requirement["extra"]["tokenProgram"],
            str(TOKEN_2022_PROGRAM_ID),
        )
        tx = transaction_from_instructions(
            state.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                set_compute_unit_price(1),
                # Build the transfer with the SPL Token program even though the
                # requirement advertises Token-2022.
                transfer_checked_instruction(client, requirement, TOKEN_PROGRAM_ID),
            ],
            signers=[client],
        )
        header = header_from_transaction(tx, accepted=requirement)
        with self.assertRaisesRegex(
            RuntimeError,
            "invalid_exact_svm_payload_no_transfer_instruction",
        ):
            settle_exact_payment(state, header)

    def test_matching_token_program_is_accepted(self):
        """Positive control: matching tokenProgram still settles."""
        state = State()
        client = Keypair()
        requirement = exact_requirement(state)
        tx = transaction_from_instructions(
            state.fee_payer.pubkey(),
            [
                set_compute_unit_limit(20_000),
                set_compute_unit_price(1),
                transfer_checked_instruction(client, requirement, TOKEN_PROGRAM_ID),
            ],
            signers=[client],
        )
        header = header_from_transaction(tx, accepted=requirement)
        with patch("x402.interop.server._send_transaction", return_value="sig-match"):
            self.assertEqual(settle_exact_payment(state, header), "sig-match")


if __name__ == "__main__":
    unittest.main()
