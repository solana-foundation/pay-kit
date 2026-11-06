//! Conformance cases for the Musebook credit provider (PR #414 surface).
//!
//! These tests pin the provider policy at the kit's public API boundary so
//! the TypeScript and Python parity ports — and any future SDK — can check
//! the same matrix:
//!
//! * `deployment()` / `resolve()` pinning: devnet only, the reviewed Squads
//!   program, the pinned V2 payment-channels program, and a devnet-only
//!   program override that never moves the channel program.
//! * The startup gate fails closed: Musebook passes only where a deployment
//!   exists; every other provider is unavailable on every network.
//! * Hook derivation is exact (slots, accounts, entrypoint) and
//!   `is_credit_channel` accepts nothing but an exact match.
//! * The server refuses every degraded credit configuration and the client
//!   refuses every degraded credit challenge (fail-closed matrix).
//! * The challenge wire form carries `methodDetails.creditProvider` /
//!   `creditIssuer` exactly when a provider is configured.
//!
//! The live devnet flow itself is covered by `tests/musebook_devnet.rs`.
//! This file lives in the kit crate's tests (not `rust/crates/conformance`)
//! because the conformance crate holds pkc protocol-flow vectors shared
//! across languages, while the functions under test here are kit-internal
//! provider policy — the same reasoning as `tests/musebook_devnet.rs`.
//!
//! Run the full matrix (client/server parts are feature-gated like the
//! devnet test):
//!   cargo test -p solana-pay-kit --features client,server --test musebook_conformance

use solana_pay_kit::core::credit_provider::musebook;
use solana_pay_kit::{
    validate_credit_providers, validate_credit_providers_for_network, CreditProvider,
    CreditProviderError,
};
use solana_pubkey::Pubkey;

const V2_CHANNEL_PROGRAM: &str = "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ";
const V1_CHANNEL_PROGRAM: &str = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX";
const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

fn pk(s: &str) -> Pubkey {
    s.parse().expect("base58 pubkey")
}

// ---------------------------------------------------------------------------
// Deployment pinning
// ---------------------------------------------------------------------------

#[test]
fn deployment_exists_only_on_devnet() {
    assert_eq!(musebook::deployment("devnet"), Some(musebook::DEVNET));
    // A `solana:` CAIP-2 style prefix is stripped before matching.
    assert_eq!(
        musebook::deployment("solana:devnet"),
        Some(musebook::DEVNET)
    );
    for network in ["mainnet", "solana:mainnet", "testnet", "localnet", ""] {
        assert_eq!(musebook::deployment(network), None, "network {network}");
    }
}

#[test]
fn deployment_pins_program_and_channel_program() {
    let d = musebook::DEVNET;
    assert_eq!(d.program(), pk(musebook::DEVNET_PROGRAM_ID));
    assert_eq!(d.channel_program(), pk(V2_CHANNEL_PROGRAM));
    assert_eq!(
        musebook::TOKEN_PROGRAM_ID,
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    );
    assert_eq!(musebook::ENTRYPOINT, *b"musebook");
    assert_eq!(musebook::COMPUTE_UNIT_LIMIT, 400_000);
    assert_eq!(musebook::MAX_AUTHORIZATION_SLOTS, 9_000);
}

#[test]
fn resolve_override_is_devnet_only_and_keeps_the_channel_program_pinned() {
    let other = Pubkey::new_unique();
    // No override: the pinned deployment.
    assert_eq!(musebook::resolve("devnet", None), Some(musebook::DEVNET));
    // Override equal to the pinned program: still the pinned deployment.
    assert_eq!(
        musebook::resolve("devnet", Some(&pk(musebook::DEVNET_PROGRAM_ID))),
        Some(musebook::DEVNET)
    );
    // A different program: a devnet-only override deployment whose channel
    // program stays pinned.
    let overridden = musebook::resolve("devnet", Some(&other)).expect("devnet override");
    assert_eq!(overridden.program(), other);
    assert_eq!(
        overridden.channel_program(),
        musebook::DEVNET.channel_program()
    );
    // Overrides never create a deployment off devnet.
    assert_eq!(musebook::resolve("mainnet", Some(&other)), None);
    assert_eq!(musebook::resolve("mainnet", None), None);
    // The string form parses pubkeys and is devnet-only by construction.
    assert_eq!(
        musebook::devnet_with_program(&other.to_string()).map(|d| d.program()),
        Some(other)
    );
    assert_eq!(musebook::devnet_with_program("not-a-pubkey"), None);
}

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

#[test]
fn gate_passes_only_where_a_deployment_exists() {
    assert!(validate_credit_providers(&[]).is_ok());
    // Without a network the gate fails closed for every provider.
    for provider in [CreditProvider::Musebook, CreditProvider::Coinflow] {
        assert_eq!(
            validate_credit_providers(&[provider]),
            Err(CreditProviderError::Unavailable { provider })
        );
    }
    // Musebook passes only on devnet; Coinflow never passes.
    assert!(validate_credit_providers_for_network(&[CreditProvider::Musebook], "devnet").is_ok());
    for network in ["mainnet", "testnet", "localnet"] {
        assert_eq!(
            validate_credit_providers_for_network(&[CreditProvider::Musebook], network),
            Err(CreditProviderError::Unavailable {
                provider: CreditProvider::Musebook
            }),
            "network {network}"
        );
    }
    assert_eq!(
        validate_credit_providers_for_network(&[CreditProvider::Coinflow], "devnet"),
        Err(CreditProviderError::Unavailable {
            provider: CreditProvider::Coinflow
        })
    );
}

// ---------------------------------------------------------------------------
// Hooks: exact derivation and exact detection
// ---------------------------------------------------------------------------

#[test]
fn hooks_are_derived_exactly_and_detected_exactly() {
    let owner = Pubkey::new_unique();
    let mint = Pubkey::new_unique();
    let hooks = musebook::DEVNET.hooks(&owner, &mint);

    // Only pre_fund and post_distribute are populated, with one descriptor.
    assert!(hooks.post_fund.is_none());
    assert!(hooks.pre_distribute.is_none());
    let descriptor = hooks.pre_fund.clone().expect("pre_fund descriptor");
    assert_eq!(hooks.post_distribute.as_ref(), Some(&descriptor));
    assert_eq!(descriptor.program_id, musebook::DEVNET_PROGRAM_ID);
    assert_eq!(descriptor.entrypoint, musebook::ENTRYPOINT);
    assert!(descriptor.static_data.is_empty());

    // Accounts: [ledger PDA (w), ATA(ledger, mint) (w), ATA(owner, mint) (w),
    // SPL Token program (ro)].
    assert_eq!(descriptor.accounts.len(), 4);
    assert_eq!(
        descriptor.accounts[0].address,
        musebook::DEVNET.ledger_address(&owner, &mint).to_string()
    );
    assert!(descriptor.accounts[0].writable);
    assert!(descriptor.accounts[1].writable);
    assert!(descriptor.accounts[2].writable);
    assert_eq!(descriptor.accounts[3].address, musebook::TOKEN_PROGRAM_ID);
    assert!(!descriptor.accounts[3].writable);

    // Detection is exact equality: the derived hooks match, look-alikes do
    // not.
    assert!(musebook::DEVNET.is_credit_channel(&hooks, &owner, &mint));
    assert!(!musebook::DEVNET.is_credit_channel(&hooks, &Pubkey::new_unique(), &mint));
    assert!(!musebook::DEVNET.is_credit_channel(&hooks, &owner, &Pubkey::new_unique()));

    let mut wrong_slot = hooks.clone();
    wrong_slot.post_fund = wrong_slot.pre_fund.clone();
    assert!(!musebook::DEVNET.is_credit_channel(&wrong_slot, &owner, &mint));

    let mut wrong_program = hooks.clone();
    wrong_program.pre_fund.as_mut().unwrap().program_id = owner.to_string();
    assert!(!musebook::DEVNET.is_credit_channel(&wrong_program, &owner, &mint));

    let mut wrong_writable = hooks.clone();
    wrong_writable.pre_fund.as_mut().unwrap().accounts[3].writable = true;
    assert!(!musebook::DEVNET.is_credit_channel(&wrong_writable, &owner, &mint));
}

// ---------------------------------------------------------------------------
// Server + client fail-closed matrix, challenge wire form
// ---------------------------------------------------------------------------

#[cfg(all(feature = "client", feature = "server"))]
mod session_matrix {
    use super::*;
    use solana_pay_kit::core::blockhash::BlockhashCache;
    use solana_pay_kit::core::store::MemoryChannelStore;
    use solana_pay_kit::mpp::client::session::{
        derive_payment_channel_open, DerivePaymentChannelOpenParams, PaymentChannelOpenOptions,
        SessionOpenAuthorization,
    };
    use solana_pay_kit::mpp::protocol::intents::session::SessionRequest;
    use solana_pay_kit::mpp::server::session::{SessionConfig, SessionServer};
    use solana_pay_kit::solana_keychain::memory::MemorySigner;
    use solana_pay_kit::solana_keychain::TransactionSigner;
    use std::sync::Arc;

    fn signer(seed: u8) -> Arc<dyn solana_keychain::TransactionSigner> {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(key.as_bytes());
        bytes[32..].copy_from_slice(key.verifying_key().as_bytes());
        Arc::new(MemorySigner::from_bytes(&bytes).unwrap())
    }

    fn musebook_config() -> SessionConfig {
        SessionConfig {
            network: "devnet".into(),
            channel_program: Some(musebook::DEVNET.channel_program()),
            channel_version: Some(2),
            credit_provider: Some(CreditProvider::Musebook),
            credit_issuer_signer: Some(signer(11)),
            credit_max_cap: Some(5_000),
            ..SessionConfig::default()
        }
    }

    fn challenge(config: SessionConfig) -> SessionRequest {
        let cache = BlockhashCache::new();
        cache.set(musebook::DEVNET.channel_program().to_string(), 314, 42);
        SessionServer::new(config, MemoryChannelStore::new())
            .with_blockhash_cache(cache)
            .build_challenge_request()
            .expect("challenge")
    }

    #[test]
    fn server_credit_deployment_accepts_only_the_pinned_configuration() {
        assert_eq!(
            musebook_config().credit_deployment().unwrap(),
            musebook::DEVNET
        );

        type Mutation = Box<dyn Fn(&mut SessionConfig)>;
        let broken: Vec<(&str, Mutation)> = vec![
            ("wrong network", Box::new(|c| c.network = "mainnet".into())),
            (
                "other provider",
                Box::new(|c| c.credit_provider = Some(CreditProvider::Coinflow)),
            ),
            ("no provider", Box::new(|c| c.credit_provider = None)),
            (
                "v1 channel program",
                Box::new(|c| c.channel_program = Some(pk(V1_CHANNEL_PROGRAM))),
            ),
            (
                "unset channel program",
                Box::new(|c| c.channel_program = None),
            ),
            (
                "channel version 1",
                Box::new(|c| c.channel_version = Some(1)),
            ),
            (
                "static channel hooks",
                Box::new(|c| c.channel_hooks = Some(Default::default())),
            ),
            (
                "token-2022",
                Box::new(|c| c.token_program = Some(pk(TOKEN_2022_PROGRAM))),
            ),
            (
                "sponsored (fee payer signer)",
                Box::new(|c| c.fee_payer_signer = Some(signer(8))),
            ),
            (
                "missing issuer signer",
                Box::new(|c| c.credit_issuer_signer = None),
            ),
        ];
        for (label, mutate) in broken {
            let mut config = musebook_config();
            mutate(&mut config);
            assert!(config.credit_deployment().is_err(), "{label}");
        }
    }

    #[test]
    fn challenge_carries_credit_fields_exactly_when_configured() {
        let request = challenge(musebook_config());
        assert_eq!(
            request.method_details.credit_provider,
            Some(CreditProvider::Musebook)
        );
        assert_eq!(
            request.method_details.credit_issuer.as_deref(),
            Some(signer(11).pubkey().to_string().as_str())
        );
        assert_eq!(request.method_details.channel_version, Some(2));
        assert!(request.method_details.channel_hooks.is_none());

        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["methodDetails"]["creditProvider"], "musebook");
        assert_eq!(
            json["methodDetails"]["creditIssuer"],
            signer(11).pubkey().to_string()
        );

        // Without a provider the keys are absent from the wire form entirely.
        let plain = challenge(SessionConfig {
            network: "devnet".into(),
            ..SessionConfig::default()
        });
        assert_eq!(plain.method_details.credit_provider, None);
        assert_eq!(plain.method_details.credit_issuer, None);
        let json = serde_json::to_value(&plain).unwrap();
        assert!(json["methodDetails"].get("creditProvider").is_none());
        assert!(json["methodDetails"].get("creditIssuer").is_none());
    }

    #[test]
    fn client_derives_hooks_and_refuses_degraded_challenges() {
        let payer = Pubkey::new_unique();
        let request = challenge(musebook_config());
        let derive = |request: &SessionRequest| {
            derive_payment_channel_open(DerivePaymentChannelOpenParams {
                request,
                payer,
                authorized_signer: Pubkey::new_unique(),
                authorization: &SessionOpenAuthorization::client_signed(1000),
                options: PaymentChannelOpenOptions {
                    salt: Some(7),
                    ..Default::default()
                },
            })
        };

        let open = derive(&request).unwrap();
        assert_eq!(
            open.channel_hooks,
            Some(musebook::DEVNET.hooks(&payer, &open.mint))
        );
        assert_eq!(open.program_id, musebook::DEVNET.channel_program());

        type Mutation = Box<dyn Fn(&mut SessionRequest)>;
        let broken: Vec<(&str, Mutation)> = vec![
            (
                "wrong network",
                Box::new(|r| r.method_details.network = "mainnet".into()),
            ),
            (
                "other provider",
                Box::new(|r| r.method_details.credit_provider = Some(CreditProvider::Coinflow)),
            ),
            (
                "static hooks alongside provider",
                Box::new(|r| r.method_details.channel_hooks = Some(Default::default())),
            ),
            (
                "v1 abi",
                Box::new(|r| r.method_details.channel_version = None),
            ),
            (
                "v1 channel program",
                Box::new(|r| r.method_details.channel_program = V1_CHANNEL_PROGRAM.into()),
            ),
            (
                "token-2022",
                Box::new(|r| r.method_details.token_program = Some(TOKEN_2022_PROGRAM.into())),
            ),
            (
                "sponsored open",
                Box::new(|r| r.method_details.fee_payer = Some(true)),
            ),
        ];
        for (label, mutate) in broken {
            let mut degraded = request.clone();
            mutate(&mut degraded);
            assert!(derive(&degraded).is_err(), "{label}");
        }
    }
}
