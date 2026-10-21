//! The interop scenario registry: the Rust port of
//! `harness/src/intents/{charge,x402-exact,x402-upto,session}.ts` (ids
//! preserved), plus the fault scenarios that replace the negative cases of
//! `rust/crates/integration-tests/tests/charge_integration.rs`.
//!
//! A scenario is data. `pkc run --tier interop` crosses it with every claimed
//! client and server adapter of its intent (minus [`Participants::Only`]
//! restrictions, each with a reason) and asserts centrally: HTTP outcome,
//! canonical error code, the settled transaction's structure on the
//! validator, balance deltas, and what the fault proxy observed.

use crate::case::SpecRef;

use super::claims::{Intent, Role};

/// The canonical L6 error codes every server emits in a 402 body
/// (`harness/src/canonical-codes.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanonicalCode {
    ChargeRequestMismatch,
    ChallengeRouteMismatch,
    ChallengeVerificationFailed,
    ChallengeExpired,
    PaymentInvalid,
    WrongNetwork,
    SignatureConsumed,
}

impl CanonicalCode {
    pub const ALL: [CanonicalCode; 7] = [
        CanonicalCode::ChargeRequestMismatch,
        CanonicalCode::ChallengeRouteMismatch,
        CanonicalCode::ChallengeVerificationFailed,
        CanonicalCode::ChallengeExpired,
        CanonicalCode::PaymentInvalid,
        CanonicalCode::WrongNetwork,
        CanonicalCode::SignatureConsumed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            CanonicalCode::ChargeRequestMismatch => "charge_request_mismatch",
            CanonicalCode::ChallengeRouteMismatch => "challenge_route_mismatch",
            CanonicalCode::ChallengeVerificationFailed => "challenge_verification_failed",
            CanonicalCode::ChallengeExpired => "challenge_expired",
            CanonicalCode::PaymentInvalid => "payment_invalid",
            CanonicalCode::WrongNetwork => "wrong_network",
            CanonicalCode::SignatureConsumed => "signature_consumed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenProgram {
    Token,
    Token2022,
}

impl TokenProgram {
    pub fn address(self) -> &'static str {
        match self {
            TokenProgram::Token => crate::keys::TOKEN_PROGRAM,
            TokenProgram::Token2022 => crate::keys::TOKEN_2022_PROGRAM,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asset {
    /// A fixed on-chain mint, set once per run. `wire` is what adapters receive as the
    /// currency (the mint address, or a symbol each SDK must resolve to
    /// `mint`).
    Fixed {
        wire: &'static str,
        mint: &'static str,
        decimals: u8,
        program: TokenProgram,
    },
    /// Native SOL: lamports, System Program transfer, decimals 9.
    Sol,
}

impl Asset {
    pub fn decimals(self) -> u8 {
        match self {
            Asset::Fixed { decimals, .. } => decimals,
            Asset::Sol => 9,
        }
    }

    pub fn program(self) -> Option<TokenProgram> {
        match self {
            Asset::Fixed { program, .. } => Some(program),
            Asset::Sol => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Split {
    /// Always the per-case `platform` keypair.
    pub amount: &'static str,
    pub ata_creation_required: Option<bool>,
    pub memo: Option<&'static str>,
}

const fn split(amount: &'static str) -> Split {
    Split {
        amount,
        ata_creation_required: None,
        memo: None,
    }
}

/// Mutations the fault proxy applies to the credential the Rust pivot
/// client sends (client -> server). The server under test must reject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerFault {
    /// The transfer pays 1 base unit instead of the amount
    /// (`charge_integration.rs` `*_wrong_amount_*`).
    WrongAmount,
    /// The transfer pays a fresh attacker key instead of the recipient
    /// (`sol_charge_wrong_recipient_rejected_before_broadcast`).
    WrongRecipient,
}

impl ServerFault {
    pub fn describe(self) -> &'static str {
        match self {
            ServerFault::WrongAmount => {
                "the fault proxy rewrites the credential's transfer to 1 base unit and re-signs it with the client key"
            }
            ServerFault::WrongRecipient => {
                "the fault proxy redirects the credential's transfer to a fresh attacker key and re-signs it with the client key"
            }
        }
    }
}

/// Mutations the fault proxy applies to the first challenge the Rust pivot
/// server emits (server -> client). The client under test must refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientFault {
    /// `expires` moved into the past (`sol_charge_expired_challenge_rejected`).
    ExpiredChallenge,
    /// The challenge names another cluster (MPP `methodDetails.network`,
    /// x402 `accepts[].network`).
    WrongNetwork,
    /// The amount multiplied by 10 000 after the server bound it.
    OverAskingPrice,
    /// The recipient replaced after the server bound the challenge id, so
    /// the id no longer authenticates the request.
    MisSignedChallenge,
}

impl ClientFault {
    pub fn describe(self) -> &'static str {
        match self {
            ClientFault::ExpiredChallenge => "the fault proxy moves the challenge's `expires` into the past",
            ClientFault::WrongNetwork => "the fault proxy rewrites the challenge's network to another cluster",
            ClientFault::OverAskingPrice => "the fault proxy multiplies the challenged amount by 10000",
            ClientFault::MisSignedChallenge => {
                "the fault proxy replaces the challenge's recipient with an attacker key, keeping the server's challenge id"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One client pays one server once.
    Standard,
    /// The client pays `source_path` (cheap); the proxy presents that
    /// credential to the scenario's resource path (expensive) instead.
    CrossRouteReplay {
        source_path: &'static str,
        source_price: &'static str,
        source_amount: &'static str,
    },
    /// The proxy captures the first accepted credential and presents it
    /// again to the same server.
    IdempotentResubmit,
    /// The proxy captures the first accepted credential and presents it to
    /// a second instance of the same server adapter with a different
    /// challenge-binding secret.
    CrossServerPortability,
    ServerFault(ServerFault),
    ClientFault(ClientFault),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// 200, `{ok: true, paid: true}`, a settlement signature, and (when
    /// `onchain`) the settled transaction's structure and balance deltas.
    Paid { onchain: bool },
    /// 402 with no funds moved, and `code` in the body when set. For
    /// resubmit/portability kinds this is the second presentation; the
    /// first must be paid exactly once. `refusing_to_start` accepts a
    /// server that exits before readiness with this configuration.
    Rejected {
        code: Option<CanonicalCode>,
        refusing_to_start: bool,
    },
    /// The client MUST NOT submit a credential for the tampered challenge,
    /// and no funds move.
    NoCredential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Participants {
    All,
    /// Only these adapter ids, for a stated reason: a driver knob only these
    /// adapters implement, the pivot role of a fault scenario, or a policy
    /// that is not a spec requirement. Never used to hide a failing SDK.
    Only(&'static [&'static str], &'static str),
}

impl Participants {
    pub fn admits(self, id: &str) -> bool {
        match self {
            Participants::All => true,
            Participants::Only(ids, _) => ids.contains(&id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spec {
    pub doc: &'static str,
    pub section: &'static str,
    pub quote: &'static str,
}

impl Spec {
    pub fn spec_ref(&self) -> SpecRef {
        crate::case::spec(self.doc, self.section, self.quote)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentMode {
    Pull,
    Push,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scenario {
    pub id: &'static str,
    pub intent: Intent,
    pub description: &'static str,
    pub spec: Spec,
    pub kind: Kind,
    pub network: &'static str,
    pub price: &'static str,
    pub amount: &'static str,
    /// Metered amount for `x402-upto`; settlement asserts it instead of
    /// `amount`.
    pub actual_amount: Option<&'static str>,
    pub asset: Asset,
    pub resource_path: &'static str,
    pub settlement_header: &'static str,
    pub splits: &'static [Split],
    pub payment_mode: PaymentMode,
    pub expect: Expect,
    pub clients: Participants,
    pub servers: Participants,
    pub pre_create_platform_ata: bool,
    pub compute_unit_limit: Option<u32>,
}

impl Scenario {
    pub fn participants(&self, role: Role) -> Participants {
        match role {
            Role::Client => self.clients,
            Role::Server => self.servers,
        }
    }

    /// What the primary recipient must receive.
    pub fn primary_delta(&self) -> u64 {
        if let Some(actual) = self.actual_amount {
            return actual.parse().expect("actual amount");
        }
        let total: u64 = self.amount.parse().expect("amount");
        total
            - self
                .splits
                .iter()
                .map(|s| s.amount.parse::<u64>().expect("split amount"))
                .sum::<u64>()
    }

    pub fn needs_payment_channels(&self) -> bool {
        self.intent == Intent::X402Upto
    }
}

const CHARGE_DOC: &str = "mpp-specs/specs/methods/solana/draft-solana-charge-00.md";
const CORE_DOC: &str = "mpp-specs/specs/core/draft-httpauth-payment-01.md";
const SESSION_DOC: &str = "mpp-specs/specs/methods/solana/draft-solana-session-00.md";
const X402_DOC: &str = "x402/specs/x402-specification-v2.md";
const EXACT_DOC: &str = "x402/specs/schemes/exact/scheme_exact.md";
const EXACT_SVM_DOC: &str = "x402/specs/schemes/exact/scheme_exact_svm.md";
const UPTO_DOC: &str = "x402/specs/schemes/upto/scheme_upto.md";
const UPTO_SVM_DOC: &str = "x402/specs/schemes/upto/scheme_upto_svm.md";

const fn spec(doc: &'static str, section: &'static str, quote: &'static str) -> Spec {
    Spec {
        doc,
        section,
        quote,
    }
}

/// Devnet USDC. It is not incidental: x402 servers price a USD amount in the
/// network's stablecoin (`0.001` on devnet is 1000 of this mint), and several
/// MPP servers resolve decimals and token program for known stablecoins
/// only, so these scenarios keep the mint `e2e.test.ts` used. Isolation
/// between cases comes from fresh owners (every ATA is per case).
const DEVNET_USDC: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const SPL6: Asset = Asset::Fixed {
    wire: DEVNET_USDC,
    mint: DEVNET_USDC,
    decimals: 6,
    program: TokenProgram::Token,
};
const LOCALNET: &str = "localnet";
const SOLANA_DEVNET: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const SOLANA_MAINNET: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
const PAID: Expect = Expect::Paid { onchain: true };

const fn rejected(code: Option<CanonicalCode>) -> Expect {
    Expect::Rejected {
        code,
        refusing_to_start: false,
    }
}

/// Defaults every scenario starts from: one 1000-base-unit SPL charge on
/// localnet, paid by any client to any server.
const BASE: Scenario = Scenario {
    id: "",
    intent: Intent::Charge,
    description: "",
    spec: spec(CHARGE_DOC, "SPL Token Verification", "Verify that at least one matching `transferChecked` instruction uses that derived ATA as `destination` and has `tokenAmount.amount` equal to the primary payment amount."),
    kind: Kind::Standard,
    network: LOCALNET,
    price: "0.001",
    amount: "1000",
    actual_amount: None,
    asset: SPL6,
    resource_path: "/protected",
    settlement_header: "x-fixture-settlement",
    splits: &[],
    payment_mode: PaymentMode::Pull,
    expect: PAID,
    clients: Participants::All,
    servers: Participants::All,
    pre_create_platform_ata: false,
    compute_unit_limit: None,
};

const ONLY_TS_CLIENT_COMPUTE: Participants = Participants::Only(
    &["typescript"],
    "only the TypeScript client adapter can inject a compute budget (MPP_HARNESS_COMPUTE_UNIT_LIMIT)",
);
const ONLY_TS_CLIENT_NO_CHALLENGE: Participants = Participants::Only(
    &["typescript"],
    "the server must refuse to issue this challenge; only the TypeScript client adapter maps a challenge-less 402 into a result instead of exiting",
);
const PIVOT_CLIENT: Participants = Participants::Only(
    &["rust"],
    "server fault: the fault proxy mutates the Rust pivot client's credential, so one honest client covers every server",
);
const PIVOT_SERVER: Participants = Participants::Only(
    &["rust"],
    "client fault: the fault proxy mutates the Rust pivot server's challenge, so one honest server covers every client",
);

const PLATFORM_SPLIT: &[Split] = &[Split {
    amount: "250",
    ata_creation_required: Some(true),
    memo: Some("harness split"),
}];

pub const SCENARIOS: &[Scenario] = &[
    // ── MPP charge (harness/src/intents/charge.ts) ──
    Scenario {
        id: "charge-basic",
        description: "A client pays a 1000-base-unit SPL charge; the settled transaction carries exactly one transferChecked to the recipient's ATA.",
        ..BASE
    },
    Scenario {
        id: "charge-split-ata",
        description: "A 250-unit split with ataCreationRequired: the client creates the split recipient's ATA idempotently and pays it with its memo.",
        spec: spec(CHARGE_DOC, "SPL Tokens", "the client MUST include an idempotent ATA creation instruction for each split recipient whose split entry sets `ataCreationRequired` to `true`"),
        resource_path: "/protected/split-ata",
        splits: PLATFORM_SPLIT,
        ..BASE
    },
    Scenario {
        id: "charge-push",
        description: "Push mode: the client broadcasts and sends a type=signature credential; the server re-fetches and verifies the landed transaction.",
        spec: spec(CHARGE_DOC, "Confirmation Requirements", "For `type=\"signature\"` credentials, clients MUST wait for at least the `confirmed` commitment level before presenting the credential. Servers MUST fetch the transaction with at least `confirmed` commitment."),
        resource_path: "/protected/push",
        payment_mode: PaymentMode::Push,
        clients: Participants::Only(&["typescript"], "only the TypeScript client adapter reads MPP_HARNESS_PAYMENT_MODE and broadcasts itself"),
        ..BASE
    },
    Scenario {
        id: "charge-network-mismatch",
        description: "The route is configured for devnet while the client signs against the localnet validator; the server rejects with wrong_network.",
        spec: spec(CHARGE_DOC, "Request Schema", "Identifies which Solana cluster the payment should be made on."),
        network: "devnet",
        resource_path: "/protected/network-mismatch",
        expect: rejected(Some(CanonicalCode::WrongNetwork)),
        ..BASE
    },
    Scenario {
        id: "charge-cross-route-replay",
        description: "A credential for /protected/cheap (500) is presented to /protected/expensive (1000); the server rejects with charge_request_mismatch.",
        spec: spec(CORE_DOC, "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        kind: Kind::CrossRouteReplay {
            source_path: "/protected/cheap",
            source_price: "0.0005",
            source_amount: "500",
        },
        resource_path: "/protected/expensive",
        expect: rejected(Some(CanonicalCode::ChargeRequestMismatch)),
        ..BASE
    },
    Scenario {
        id: "charge-symbol-usdc-localnet",
        description: "The server is configured with the symbol USDC; it must resolve it to the mint (EPjF...) before it reaches the wire, and the client pays that mint.",
        spec: spec(CHARGE_DOC, "Request Schema", "For SPL tokens, MUST be the base58-encoded mint address"),
        resource_path: "/protected/symbol-usdc",
        asset: Asset::Fixed {
            wire: "USDC",
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            decimals: 6,
            program: TokenProgram::Token,
        },
        ..BASE
    },
    Scenario {
        id: "charge-token2022-split-ata",
        description: "A Token-2022 mint (PYUSD) with a split that requires ATA creation; transfers and ATA creation use the Token-2022 program.",
        spec: spec(CHARGE_DOC, "Request Schema", "If omitted, clients MUST determine the correct token program by fetching the mint account"),
        resource_path: "/protected/token2022-split-ata",
        asset: Asset::Fixed {
            wire: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
            mint: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
            decimals: 6,
            program: TokenProgram::Token2022,
        },
        splits: &[Split {
            amount: "250",
            ata_creation_required: Some(true),
            memo: Some("harness token2022 split"),
        }],
        ..BASE
    },
    Scenario {
        id: "charge-decimals-9",
        description: "A 9-decimal mint: the challenge carries decimals 9 and every transferChecked encodes 9.",
        spec: spec(CHARGE_DOC, "Request Schema", "MUST be present when `currency` is a mint address"),
        resource_path: "/protected/decimals-9",
        asset: Asset::Fixed {
            wire: "KTHzp63RATgvE5RoRRqVbY7hMWntARQ6dPQhMtfY9oA",
            mint: "KTHzp63RATgvE5RoRRqVbY7hMWntARQ6dPQhMtfY9oA",
            decimals: 9,
            program: TokenProgram::Token,
        },
        ..BASE
    },
    Scenario {
        id: "charge-split-ata-idempotent",
        description: "As charge-split-ata, with the split recipient's ATA already created: the idempotent create still settles.",
        spec: spec(CHARGE_DOC, "Request Schema", "When `true`, the client MUST include an idempotent Associated Token Account creation instruction for this split recipient's ATA before the split transfer."),
        resource_path: "/protected/split-ata-idempotent",
        pre_create_platform_ata: true,
        splits: &[Split {
            amount: "250",
            ata_creation_required: Some(true),
            memo: Some("harness split idempotent"),
        }],
        ..BASE
    },
    Scenario {
        id: "charge-compute-budget-over-cap",
        description: "The client sets a compute unit limit of 200001, over the 200000 server cap; the server rejects the credential.",
        spec: spec(CHARGE_DOC, "Transaction Payload Security", "Servers MUST verify that the transaction contains only the expected instructions"),
        resource_path: "/protected/compute-budget-over-cap",
        clients: ONLY_TS_CLIENT_COMPUTE,
        compute_unit_limit: Some(200_001),
        expect: rejected(None),
        ..BASE
    },
    Scenario {
        id: "charge-sol-native",
        description: "Native SOL: currency \"sol\", a System Program transfer of 1000000 lamports.",
        spec: spec(CHARGE_DOC, "Request Schema", "For native SOL, MUST be the lowercase string `\"sol\"`."),
        resource_path: "/protected/sol-native",
        amount: "1000000",
        asset: Asset::Sol,
        ..BASE
    },
    Scenario {
        id: "charge-splits-too-many",
        description: "Nine splits, over the limit of eight: the server refuses to issue the challenge (or to start with that route).",
        spec: spec(CHARGE_DOC, "Request Schema", "An array of at most 8 additional payment splits."),
        resource_path: "/protected/splits-too-many",
        clients: ONLY_TS_CLIENT_NO_CHALLENGE,
        splits: &[
            split("1"),
            split("1"),
            split("1"),
            split("1"),
            split("1"),
            split("1"),
            split("1"),
            split("1"),
            split("1"),
        ],
        expect: Expect::Rejected {
            code: None,
            refusing_to_start: true,
        },
        ..BASE
    },
    Scenario {
        id: "charge-splits-sum-equals-amount",
        description: "One split equal to the amount leaves the primary recipient nothing; the challenge must be refused.",
        spec: spec(CHARGE_DOC, "Request Schema", "Servers MUST reject challenges where splits consume the entire amount."),
        resource_path: "/protected/splits-sum-equals-amount",
        clients: ONLY_TS_CLIENT_NO_CHALLENGE,
        splits: &[split("1000")],
        expect: Expect::Rejected {
            code: None,
            refusing_to_start: true,
        },
        ..BASE
    },
    Scenario {
        id: "charge-cross-server-portability",
        description: "A credential accepted by one server instance is presented to a second instance with a different challenge-binding secret; it rejects with challenge_verification_failed.",
        spec: spec(CORE_DOC, "Challenge Binding", "Servers MUST verify the binding when processing a credential and MUST reject a credential whose echoed challenge parameters do not match the expected binding."),
        kind: Kind::CrossServerPortability,
        expect: rejected(Some(CanonicalCode::ChallengeVerificationFailed)),
        ..BASE
    },
    Scenario {
        id: "charge-idempotent-resubmit",
        description: "An accepted credential is presented again to the same server: 402 signature_consumed, and the payment settles exactly once.",
        spec: spec(CHARGE_DOC, "Replay Protection", "A signature that has been consumed MUST NOT be accepted again, even if presented with a different challenge ID."),
        kind: Kind::IdempotentResubmit,
        expect: rejected(Some(CanonicalCode::SignatureConsumed)),
        ..BASE
    },
    // ── MPP charge faults (charge_integration.rs, now against every server) ──
    Scenario {
        id: "charge-fault-wrong-amount",
        description: "The credential's transfer pays 1 base unit instead of 1000: the server rejects before broadcast and no funds move.",
        spec: spec(CHARGE_DOC, "SPL Token Verification", "If any required `transferChecked` instruction is missing, the server MUST reject the credential."),
        kind: Kind::ServerFault(ServerFault::WrongAmount),
        clients: PIVOT_CLIENT,
        expect: rejected(Some(CanonicalCode::PaymentInvalid)),
        ..BASE
    },
    Scenario {
        id: "charge-fault-wrong-recipient",
        description: "The credential's transfer pays an attacker instead of the recipient: the server rejects before broadcast and no funds move.",
        spec: spec(CHARGE_DOC, "SPL Token Verification", "If any required `transferChecked` instruction is missing, the server MUST reject the credential."),
        kind: Kind::ServerFault(ServerFault::WrongRecipient),
        clients: PIVOT_CLIENT,
        expect: rejected(Some(CanonicalCode::PaymentInvalid)),
        ..BASE
    },
    Scenario {
        id: "charge-client-expired-challenge",
        description: "The client receives a challenge whose expires is in the past and must not submit a credential.",
        spec: spec(CORE_DOC, "Challenge", "Clients MUST NOT submit credentials for expired challenges."),
        kind: Kind::ClientFault(ClientFault::ExpiredChallenge),
        servers: PIVOT_SERVER,
        expect: Expect::NoCredential,
        ..BASE
    },
    Scenario {
        id: "charge-client-wrong-network",
        description: "The client, configured for localnet, receives a challenge for mainnet and must reject it.",
        spec: spec(CHARGE_DOC, "Request Schema", "Clients MUST reject challenges whose network does not match their configured cluster."),
        kind: Kind::ClientFault(ClientFault::WrongNetwork),
        servers: PIVOT_SERVER,
        expect: Expect::NoCredential,
        ..BASE
    },
    Scenario {
        id: "charge-client-over-asking-price",
        description: "The challenged amount is 10000 times what the client was configured to pay; the client must not authorize it.",
        spec: spec(CORE_DOC, "Amount Verification", "Clients MUST verify before authorizing payment: 1. Requested amount is reasonable for the resource"),
        kind: Kind::ClientFault(ClientFault::OverAskingPrice),
        servers: PIVOT_SERVER,
        expect: Expect::NoCredential,
        ..BASE
    },
    Scenario {
        id: "charge-client-mis-signed-challenge",
        description: "The challenge's recipient was replaced after the server bound its id; the client must not pay an unexpected recipient.",
        spec: spec(CORE_DOC, "Amount Verification", "2. Recipient/address is expected"),
        kind: Kind::ClientFault(ClientFault::MisSignedChallenge),
        servers: PIVOT_SERVER,
        expect: Expect::NoCredential,
        ..BASE
    },
    // ── x402 exact (harness/src/intents/x402-exact.ts) ──
    Scenario {
        id: "x402-exact-basic",
        intent: Intent::X402Exact,
        description: "A client pays a 1000-base-unit x402 exact requirement; the sponsor settles exactly one transferChecked to payTo's ATA.",
        spec: spec(EXACT_SVM_DOC, "1.4 Exactly One Matching Transfer (MUST)", "Across all top-level instructions and the full CPI trace, **exactly one** transfer MUST match the requirements"),
        network: SOLANA_DEVNET,
        ..BASE
    },
    Scenario {
        id: "x402-exact-network-mismatch",
        intent: Intent::X402Exact,
        description: "The route is labelled mainnet while the client signs against the localnet validator; the Lua server's blockhash heuristic rejects with wrong_network.",
        spec: spec(X402_DOC, "PaymentRequirements", "Blockchain network identifier in CAIP-2 format"),
        network: SOLANA_MAINNET,
        resource_path: "/protected/network-mismatch",
        expect: rejected(Some(CanonicalCode::WrongNetwork)),
        servers: Participants::Only(&["lua"], "a pay-kit policy heuristic, not an x402 requirement (x402 binds the network only by its CAIP-2 label): only the Lua server implements it"),
        ..BASE
    },
    Scenario {
        id: "x402-exact-cross-route-replay",
        intent: Intent::X402Exact,
        description: "A payment for /protected/cheap (500) is presented to /protected/expensive (1000); the server rejects with charge_request_mismatch.",
        spec: spec(X402_DOC, "PaymentPayload", "PaymentRequirements object indicating the payment method chosen"),
        kind: Kind::CrossRouteReplay {
            source_path: "/protected/cheap",
            source_price: "0.0005",
            source_amount: "500",
        },
        network: SOLANA_DEVNET,
        resource_path: "/protected/expensive",
        expect: rejected(Some(CanonicalCode::ChargeRequestMismatch)),
        ..BASE
    },
    Scenario {
        id: "x402-exact-cross-server-portability",
        intent: Intent::X402Exact,
        description: "A payment accepted by one server instance is presented to a second instance; of two presentations exactly one succeeds.",
        spec: spec(EXACT_DOC, "Upfront methods", "of two concurrent presentations, exactly one MUST succeed."),
        kind: Kind::CrossServerPortability,
        network: SOLANA_DEVNET,
        expect: rejected(None),
        ..BASE
    },
    Scenario {
        id: "x402-exact-idempotent-resubmit",
        intent: Intent::X402Exact,
        description: "An accepted payment is presented again to the same server: 402 signature_consumed, and it settles exactly once.",
        spec: spec(EXACT_DOC, "Upfront methods", "A consumed primitive MUST produce a settlement failure, never a success."),
        kind: Kind::IdempotentResubmit,
        network: SOLANA_DEVNET,
        expect: rejected(Some(CanonicalCode::SignatureConsumed)),
        ..BASE
    },
    // ── x402 exact faults ──
    Scenario {
        id: "x402-exact-fault-wrong-amount",
        intent: Intent::X402Exact,
        description: "The payment's transfer pays 1 base unit instead of 1000: the server rejects and no funds move.",
        spec: spec(EXACT_SVM_DOC, "1.4 Exactly One Matching Transfer (MUST)", "MUST reject if zero matching transfers are found."),
        kind: Kind::ServerFault(ServerFault::WrongAmount),
        network: SOLANA_DEVNET,
        clients: PIVOT_CLIENT,
        // x402 servers name this reject differently (no shared code table
        // for x402 yet); the rejection and no funds moving are asserted.
        expect: rejected(None),
        ..BASE
    },
    Scenario {
        id: "x402-exact-fault-wrong-recipient",
        intent: Intent::X402Exact,
        description: "The payment's transfer pays an attacker instead of payTo: the server rejects and no funds move.",
        spec: spec(EXACT_SVM_DOC, "1.4 Exactly One Matching Transfer (MUST)", "MUST reject if zero matching transfers are found."),
        kind: Kind::ServerFault(ServerFault::WrongRecipient),
        network: SOLANA_DEVNET,
        clients: PIVOT_CLIENT,
        expect: rejected(None),
        ..BASE
    },
    Scenario {
        id: "x402-exact-client-wrong-network",
        intent: Intent::X402Exact,
        description: "The client, configured for the devnet CAIP-2 network, receives requirements for mainnet only and must not pay.",
        spec: spec(X402_DOC, "PaymentRequirements", "Blockchain network identifier in CAIP-2 format"),
        kind: Kind::ClientFault(ClientFault::WrongNetwork),
        network: SOLANA_DEVNET,
        servers: PIVOT_SERVER,
        expect: Expect::NoCredential,
        ..BASE
    },
    // ── x402 upto (harness/src/intents/x402-upto.ts) ──
    Scenario {
        id: "x402-upto-basic",
        intent: Intent::X402Upto,
        description: "The client opens a payment channel for a 100000 ceiling; the server settles the metered 50000 with settle_and_seal and distribute.",
        spec: spec(UPTO_SVM_DOC, "Overview", "Settlement uses `settle_and_seal` followed by a final `distribute`"),
        network: SOLANA_DEVNET,
        price: "0.10",
        amount: "100000",
        actual_amount: Some("50000"),
        resource_path: "/usage",
        settlement_header: "x-payment-settlement-signature",
        ..BASE
    },
    Scenario {
        id: "x402-upto-zero-actual",
        intent: Intent::X402Upto,
        description: "Zero metered usage: the server closes the channel with a voucher-less settle_and_seal and refunds the deposit.",
        spec: spec(UPTO_DOC, "Core Properties (MUST)", "Each authorization MUST be settled at most once."),
        network: SOLANA_DEVNET,
        price: "0.10",
        amount: "100000",
        actual_amount: Some("0"),
        resource_path: "/usage",
        settlement_header: "x-payment-settlement-signature",
        servers: Participants::Only(&["rust"], "PayKit's public usage middleware (Go, Python) fail-closes on a zero charge by design; the low-level Rust upto server settles zero"),
        ..BASE
    },
    // ── MPP session (harness/src/intents/session.ts) ──
    Scenario {
        id: "session-basic",
        intent: Intent::Session,
        description: "A session client opens a channel and pays 700 base units with a voucher; the server serves the resource.",
        spec: spec(SESSION_DOC, "Voucher Verification", "The server MUST verify each voucher:"),
        price: "0.0007",
        amount: "700",
        asset: Asset::Fixed {
            wire: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            decimals: 6,
            program: TokenProgram::Token,
        },
        resource_path: "/session",
        settlement_header: "x-session-settlement-signature",
        expect: Expect::Paid { onchain: false },
        ..BASE
    },
];

pub fn find(id: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|s| s.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::adapters;
    use crate::reqlint::{normalise, quote_found};
    use std::collections::BTreeSet;

    /// The 23 scenario ids of `harness/src/intents/*.ts` before the port.
    const PORTED: [&str; 23] = [
        "charge-basic",
        "charge-split-ata",
        "charge-push",
        "charge-network-mismatch",
        "charge-cross-route-replay",
        "charge-symbol-usdc-localnet",
        "charge-token2022-split-ata",
        "charge-decimals-9",
        "charge-split-ata-idempotent",
        "charge-compute-budget-over-cap",
        "charge-sol-native",
        "charge-splits-too-many",
        "charge-splits-sum-equals-amount",
        "charge-cross-server-portability",
        "charge-idempotent-resubmit",
        "x402-exact-basic",
        "x402-exact-network-mismatch",
        "x402-exact-cross-route-replay",
        "x402-exact-cross-server-portability",
        "x402-exact-idempotent-resubmit",
        "session-basic",
        "x402-upto-basic",
        "x402-upto-zero-actual",
    ];

    #[test]
    fn every_ported_scenario_id_is_preserved() {
        for id in PORTED {
            assert!(find(id).is_some(), "{id} was not ported");
        }
    }

    #[test]
    fn ids_are_unique_and_prefixed_by_their_intent() {
        let mut seen = BTreeSet::new();
        for s in SCENARIOS {
            assert!(seen.insert(s.id), "duplicate {}", s.id);
            assert!(
                s.id.starts_with(&format!("{}-", s.intent.id())),
                "{} is not prefixed by {}",
                s.id,
                s.intent
            );
            assert!(!s.description.is_empty(), "{}", s.id);
        }
    }

    #[test]
    fn every_spec_quote_appears_in_the_pinned_text() {
        let root = crate::repo_root();
        for s in SCENARIOS {
            let r = s.spec.spec_ref();
            let path = root.join(r.repo().checkout()).join(r.path());
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("{} ({}): {e}", s.id, path.display()));
            assert!(
                quote_found(&normalise(&text), r.quote()),
                "{}: quote not found in {}: {:?}",
                s.id,
                r.doc(),
                r.quote()
            );
        }
    }

    #[test]
    fn restrictions_name_real_adapters_and_leave_a_pair() {
        for s in SCENARIOS {
            for role in [Role::Client, Role::Server] {
                if let Participants::Only(ids, reason) = s.participants(role) {
                    assert!(!reason.is_empty(), "{}", s.id);
                    for id in ids {
                        assert!(
                            adapters::find(s.intent, role, id).is_some(),
                            "{} restricts {role}s to unknown adapter {id}",
                            s.id
                        );
                    }
                }
                assert!(
                    adapters::of(s.intent, role).any(|a| s.participants(role).admits(a.id)),
                    "{} admits no {role}",
                    s.id
                );
            }
        }
    }

    #[test]
    fn fault_scenarios_pin_the_pivot_on_the_honest_side() {
        for s in SCENARIOS {
            match s.kind {
                Kind::ServerFault(_) => assert_eq!(s.clients, PIVOT_CLIENT, "{}", s.id),
                Kind::ClientFault(_) => {
                    assert_eq!(s.servers, PIVOT_SERVER, "{}", s.id);
                    assert_eq!(s.expect, Expect::NoCredential, "{}", s.id);
                }
                _ => {}
            }
        }
    }

    #[test]
    fn primary_delta_subtracts_splits_or_uses_the_metered_amount() {
        assert_eq!(find("charge-split-ata").unwrap().primary_delta(), 750);
        assert_eq!(find("x402-upto-basic").unwrap().primary_delta(), 50_000);
        assert_eq!(
            find("charge-sol-native").unwrap().primary_delta(),
            1_000_000
        );
    }
}
