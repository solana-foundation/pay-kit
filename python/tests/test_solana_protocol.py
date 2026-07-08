"""Tests for protocol/solana module."""

from __future__ import annotations

from solana_pay_kit._paycore.solana import (
    ASSOCIATED_TOKEN_PROGRAM,
    MEMO_PROGRAM,
    SYSTEM_PROGRAM,
    TOKEN_2022_PROGRAM,
    TOKEN_PROGRAM,
    CredentialPayload,
    MethodDetails,
    Split,
    default_rpc_url,
    default_token_program_for_currency,
    is_native_sol,
    resolve_mint,
    stablecoin_symbol,
)


class TestDefaultRpcUrl:
    def test_mainnet_canonical(self):
        url = default_rpc_url("mainnet")
        assert "mainnet" in url

    def test_mainnet_beta_alias(self):
        # Backward compat: callers passing the legacy ``mainnet-beta`` slug
        # must resolve to the same RPC host.
        assert default_rpc_url("mainnet-beta") == default_rpc_url("mainnet")

    def test_devnet(self):
        url = default_rpc_url("devnet")
        assert "devnet" in url

    def test_localnet(self):
        url = default_rpc_url("localnet")
        assert "localhost" in url

    def test_unknown_defaults_to_mainnet(self):
        url = default_rpc_url("unknown")
        assert "mainnet" in url


class TestResolveMint:
    def test_sol_returns_empty(self):
        assert resolve_mint("SOL", "mainnet") == ""
        assert resolve_mint("sol", "mainnet") == ""

    def test_usdc_mainnet_canonical(self):
        mint = resolve_mint("USDC", "mainnet")
        assert mint.startswith("EPjFWdd5")

    def test_usdc_mainnet_beta_alias(self):
        # ``mainnet-beta`` callers (TS / Rust pre-L1) must resolve identically.
        assert resolve_mint("USDC", "mainnet-beta") == resolve_mint("USDC", "mainnet")

    def test_usdc_devnet(self):
        mint = resolve_mint("USDC", "devnet")
        assert mint.startswith("4zMMC9")

    def test_usdt_mainnet(self):
        mint = resolve_mint("USDT", "mainnet")
        assert mint.startswith("Es9vMF")

    def test_usdg_devnet(self):
        mint = resolve_mint("USDG", "devnet")
        assert mint.startswith("4F6PM9")

    def test_pyusd_mainnet(self):
        mint = resolve_mint("PYUSD", "mainnet")
        assert mint.startswith("2b1kV6")

    def test_cash_mainnet(self):
        mint = resolve_mint("CASH", "mainnet")
        assert mint.startswith("CASHx9")

    def test_unknown_returns_raw(self):
        assert resolve_mint("SomeCustomMint123", "mainnet") == "SomeCustomMint123"

    def test_no_mainnet_beta_keys(self):
        # L1 lock invariant: ``mainnet-beta`` must not appear as a direct key
        # inside KNOWN_MINTS. Drift here would make a Ruby-mainnet credential
        # resolve to a different mint than its Python-mainnet-beta echo.
        from solana_pay_kit._paycore.solana import KNOWN_MINTS

        for symbol, networks in KNOWN_MINTS.items():
            assert "mainnet-beta" not in networks, (
                f"{symbol} still keys by mainnet-beta; should canonicalize to mainnet"
            )


class TestStablecoinPrograms:
    def test_symbol_detection(self):
        assert stablecoin_symbol("USDG") == "USDG"
        assert stablecoin_symbol("2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH") == "USDG"
        assert stablecoin_symbol("SomeCustomMint123") is None

    def test_token_program_defaults(self):
        assert default_token_program_for_currency("USDC", "mainnet") == TOKEN_PROGRAM
        assert default_token_program_for_currency("USDT", "mainnet") == TOKEN_PROGRAM
        assert default_token_program_for_currency("PYUSD", "devnet") == TOKEN_2022_PROGRAM
        assert default_token_program_for_currency("USDG", "devnet") == TOKEN_2022_PROGRAM
        assert default_token_program_for_currency("CASH", "mainnet") == TOKEN_2022_PROGRAM

    def test_token_program_mainnet_beta_alias(self):
        assert default_token_program_for_currency("USDC", "mainnet-beta") == TOKEN_PROGRAM
        assert default_token_program_for_currency("CASH", "mainnet-beta") == TOKEN_2022_PROGRAM


class TestIsNativeSol:
    def test_sol_variants(self):
        assert is_native_sol("SOL")
        assert is_native_sol("sol")
        assert is_native_sol("Sol")

    def test_non_sol(self):
        assert not is_native_sol("USDC")
        assert not is_native_sol("")


class TestMethodDetails:
    def test_to_dict_minimal(self):
        d = MethodDetails().to_dict()
        assert d["network"] == "mainnet"

    def test_from_dict_mainnet_beta_alias_normalized(self):
        # L1 lock: ``mainnet-beta`` on the wire is normalized to ``mainnet``
        # inside the SDK so cross-language credentials compare equal.
        details = MethodDetails.from_dict({"network": "mainnet-beta"})
        assert details.network == "mainnet"

    def test_to_dict_full(self):
        details = MethodDetails(
            network="devnet",
            decimals=6,
            token_program=TOKEN_PROGRAM,
            fee_payer=True,
            fee_payer_key="abc",
            recent_blockhash="hash123",
            splits=[Split(recipient="addr", amount="100")],
        )
        d = details.to_dict()
        assert d["network"] == "devnet"
        assert d["decimals"] == 6
        assert d["feePayer"] is True
        assert len(d["splits"]) == 1

    def test_from_dict(self):
        d = {
            "network": "devnet",
            "decimals": 9,
            "feePayer": True,
            "splits": [{"recipient": "addr", "amount": "100"}],
        }
        details = MethodDetails.from_dict(d)
        assert details.network == "devnet"
        assert details.decimals == 9
        assert details.fee_payer is True
        assert len(details.splits) == 1
        assert details.splits[0].recipient == "addr"

    def test_split_ata_creation_required_round_trips(self):
        details = MethodDetails(
            splits=[
                Split(
                    recipient="split-recipient",
                    amount="100",
                    ata_creation_required=True,
                )
            ]
        )

        encoded = details.to_dict()
        assert encoded["splits"][0]["ataCreationRequired"] is True

        decoded = MethodDetails.from_dict(encoded)
        assert decoded.splits[0].ata_creation_required is True

    def test_split_omits_false_ata_creation_required(self):
        encoded = Split(recipient="split-recipient", amount="100").to_dict()
        assert "ataCreationRequired" not in encoded


class TestCredentialPayload:
    def test_transaction_payload(self):
        p = CredentialPayload(type="transaction", transaction="base64tx")
        d = p.to_dict()
        assert d["type"] == "transaction"
        assert d["transaction"] == "base64tx"
        assert "signature" not in d

    def test_signature_payload(self):
        p = CredentialPayload(type="signature", signature="sig123")
        d = p.to_dict()
        assert d["type"] == "signature"
        assert d["signature"] == "sig123"
        assert "transaction" not in d

    def test_from_dict(self):
        p = CredentialPayload.from_dict({"type": "signature", "signature": "abc"})
        assert p.type == "signature"
        assert p.signature == "abc"


class TestConstants:
    def test_system_program(self):
        assert len(SYSTEM_PROGRAM) == 32

    def test_token_program(self):
        assert TOKEN_PROGRAM.startswith("Token")

    def test_token_2022_program(self):
        assert TOKEN_2022_PROGRAM.startswith("Token")

    def test_associated_token_program(self):
        assert ASSOCIATED_TOKEN_PROGRAM.startswith("AToken")

    def test_memo_program(self):
        assert MEMO_PROGRAM.startswith("Memo")


class TestValidateNetwork:
    """Audit #37: boot-time network allowlist."""

    def test_accepts_canonical_networks(self):
        from solana_pay_kit._paycore.solana import validate_network

        for net in ("mainnet", "devnet", "localnet"):
            validate_network(net)  # must not raise

    def test_accepts_mainnet_beta_alias(self):
        from solana_pay_kit._paycore.solana import validate_network

        validate_network("mainnet-beta")

    def test_rejects_unknown_network(self):
        import pytest

        from solana_pay_kit._paycore.solana import validate_network

        with pytest.raises(ValueError, match="unknown network"):
            validate_network("testnet")

    def test_rejects_empty_network(self):
        import pytest

        from solana_pay_kit._paycore.solana import validate_network

        with pytest.raises(ValueError, match="network is required"):
            validate_network("")


class TestDeriveDefaultRealm:
    """Audit #15: per-recipient derived default realm."""

    def test_shape(self):
        from solana_pay_kit._paycore.solana import derive_default_realm

        realm = derive_default_realm("11111111111111111111111111111112")
        assert realm.startswith("App Id - #")

    def test_deterministic(self):
        from solana_pay_kit._paycore.solana import derive_default_realm

        r = "11111111111111111111111111111112"
        assert derive_default_realm(r) == derive_default_realm(r)

    def test_differs_across_recipients(self):
        from solana_pay_kit._paycore.solana import derive_default_realm

        a = derive_default_realm("11111111111111111111111111111112")
        b = derive_default_realm("9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ")
        assert a != b


class TestValidateSplits:
    """Audit #21: issuance-time split validation."""

    def _split(self, recipient=None, amount="1000", ata=False):
        from solders.pubkey import Pubkey

        return Split(
            recipient=recipient or str(Pubkey.new_unique()),
            amount=amount,
            ata_creation_required=ata,
        )

    def test_accepts_valid_set(self):
        from solana_pay_kit._paycore.solana import validate_splits

        validate_splits([self._split(), self._split()])

    def test_accepts_empty(self):
        from solana_pay_kit._paycore.solana import validate_splits

        validate_splits([])

    def test_rejects_count_above_max(self):
        import pytest

        from solana_pay_kit._paycore.solana import MAX_SPLITS, validate_splits

        with pytest.raises(ValueError, match="too many splits"):
            validate_splits([self._split() for _ in range(MAX_SPLITS + 1)])

    def test_rejects_invalid_recipient(self):
        import pytest

        from solana_pay_kit._paycore.solana import validate_splits

        with pytest.raises(ValueError, match="not a valid pubkey"):
            validate_splits([self._split(recipient="not-a-pubkey-xxx")])

    def test_rejects_unparseable_amount(self):
        import pytest

        from solana_pay_kit._paycore.solana import validate_splits

        with pytest.raises(ValueError, match="not a valid integer"):
            validate_splits([self._split(amount="abc")])

    def test_rejects_zero_amount(self):
        import pytest

        from solana_pay_kit._paycore.solana import validate_splits

        with pytest.raises(ValueError, match="must be positive"):
            validate_splits([self._split(amount="0")])

    def test_rejects_duplicate_recipient(self):
        import pytest
        from solders.pubkey import Pubkey

        from solana_pay_kit._paycore.solana import validate_splits

        r = str(Pubkey.new_unique())
        with pytest.raises(ValueError, match="duplicate split recipient"):
            validate_splits([self._split(recipient=r), self._split(recipient=r)])


class TestResolveServerTokenProgram:
    """Audit #28: boot-time token-program resolution."""

    def test_sol_returns_none(self):
        from solana_pay_kit._paycore.solana import resolve_server_token_program

        assert resolve_server_token_program("SOL", "mainnet", None) is None

    def test_known_stablecoin_classic_token(self):
        from solana_pay_kit._paycore.solana import resolve_server_token_program

        assert resolve_server_token_program("USDC", "mainnet", None) == TOKEN_PROGRAM

    def test_known_stablecoin_token_2022(self):
        from solana_pay_kit._paycore.solana import resolve_server_token_program

        assert resolve_server_token_program("PYUSD", "mainnet", None) == TOKEN_2022_PROGRAM

    def test_rejects_unparseable_currency(self):
        import pytest

        from solana_pay_kit._paycore.solana import resolve_server_token_program

        with pytest.raises(ValueError, match="neither a known stablecoin"):
            resolve_server_token_program("not-a-symbol-or-mint", "mainnet", None)

    def test_arbitrary_mint_without_rpc_fails_fast(self):
        import pytest
        from solders.pubkey import Pubkey

        from solana_pay_kit._paycore.solana import resolve_server_token_program

        mint = str(Pubkey.new_unique())
        with pytest.raises(ValueError, match="no rpc_url configured"):
            resolve_server_token_program(mint, "mainnet", None)
