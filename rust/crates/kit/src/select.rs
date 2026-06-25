//! Cross-protocol payment selection.
//!
//! A 402 response can advertise charge options across *both* protocols — MPP
//! charge challenges and x402 `accepts` entries — often in different
//! stablecoins (e.g. USDG over MPP, USDC over x402). Picking which one to pay
//! is a wallet decision, not a protocol decision: the client should settle in
//! a token it actually holds, in its own priority order, regardless of which
//! protocol carries that token.
//!
//! [`select_payment`] takes the funded tokens the caller is willing to spend
//! (with available balances) and an [`OrderingStrategy`], enumerates every
//! advertised option from both protocols, keeps only the ones the wallet can
//! fund, ranks them, and returns the winner — or a [`SelectError`] that names
//! what was offered versus what the wallet holds.
//!
//! Balance/RPC knowledge stays with the caller (it fills `funded`); all the
//! cross-protocol matching and ranking lives here.

use crate::mpp::client::is_solana_charge_challenge;
use crate::mpp::protocol::solana::MethodDetails;
use crate::mpp::{
    parse_www_authenticate_all, resolve_stablecoin_mint, ChargeRequest, PaymentChallenge,
};
use crate::x402::client::exact::parse_x402_accepts;
use crate::x402::exact::{cluster_for_caip2_network, PaymentRequirements};

/// A token the caller is willing to spend, with the balance currently available.
///
/// `mint` and `network` identify the asset; `available` is the spendable
/// balance in base units (the same units challenge amounts use). The order of
/// a `&[AcceptableToken]` slice is only meaningful for
/// [`OrderingStrategy::FixedPriority`] callers who pre-sort — the built-in
/// strategies rank by balance or amount, not slice order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptableToken {
    /// SPL mint address of the token.
    pub mint: String,
    /// Network slug: `mainnet`, `devnet`, `testnet`, or `localnet`.
    pub network: String,
    /// Spendable balance in base units.
    pub available: u64,
}

/// How to rank the advertised options the wallet can fund.
#[derive(Debug, Clone)]
pub enum OrderingStrategy {
    /// Prefer the token the wallet holds the most of (by available balance).
    HighestBalance,
    /// Prefer the option that costs the least (decimals-adjusted amount).
    CheapestPayable,
    /// Prefer tokens in an explicit order — symbols (`"USDC"`) or mint
    /// addresses, highest priority first. Options whose token isn't listed
    /// rank last.
    FixedPriority(Vec<String>),
    /// Legacy behavior: prefer MPP over x402, otherwise server order. Lets
    /// callers opt out of token-aware selection.
    MppFirst,
}

/// The option [`select_payment`] chose, carrying everything needed to settle.
#[derive(Debug, Clone)]
pub enum SelectedPayment {
    /// Settle via an MPP charge challenge.
    Mpp {
        challenge: Box<PaymentChallenge>,
        mint: String,
        network: String,
        amount: u64,
    },
    /// Settle via an x402 payment requirement.
    X402 {
        requirement: Box<PaymentRequirements>,
        mint: String,
        network: String,
        amount: u64,
    },
}

impl SelectedPayment {
    /// `"mpp"` or `"x402"` — which protocol the winning option uses.
    pub fn protocol(&self) -> &'static str {
        match self {
            Self::Mpp { .. } => "mpp",
            Self::X402 { .. } => "x402",
        }
    }

    /// Resolved mint of the selected option.
    pub fn mint(&self) -> &str {
        match self {
            Self::Mpp { mint, .. } | Self::X402 { mint, .. } => mint,
        }
    }
}

/// A single advertised option, recorded for diagnostics when nothing matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferedOption {
    /// `"mpp"` or `"x402"`.
    pub protocol: &'static str,
    /// The currency string the server advertised (symbol or mint).
    pub currency: String,
    /// Resolved mint, when the currency mapped to a known/explicit mint.
    pub mint: Option<String>,
    /// Network slug.
    pub network: String,
    /// Amount in base units.
    pub amount: u64,
}

/// Returned when no advertised option matches a funded token.
///
/// Carries the full picture — every option the server offered and every token
/// the wallet was willing to spend — so the caller can render an actionable
/// message instead of a bare "insufficient balance".
#[derive(Debug, Clone)]
pub struct SelectError {
    /// Every charge option advertised across both protocols.
    pub offered: Vec<OfferedOption>,
    /// The funded tokens the caller offered to spend.
    pub funded: Vec<AcceptableToken>,
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let offered = self
            .offered
            .iter()
            .map(|o| {
                // Show the advertised currency and the mint it resolved to, so
                // a symbol-vs-mint mismatch is visible at a glance.
                let mint = match &o.mint {
                    Some(m) if m != &o.currency => format!(" [{m}]"),
                    _ => String::new(),
                };
                format!(
                    "{} {}{} ({} on {})",
                    o.amount, o.currency, mint, o.protocol, o.network
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let held = self
            .funded
            .iter()
            .map(|t| format!("{} ({} on {})", t.available, t.mint, t.network))
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "no advertised payment option matches a funded token. \
             offered: [{offered}]; wallet holds: [{held}]"
        )
    }
}

impl std::error::Error for SelectError {}

/// One normalized candidate from either protocol.
///
/// `currency` is the raw advertised string (symbol *or* mint, as the server
/// sent it); `mint` is the canonical mint it resolved to. All matching and
/// ranking happens on `mint` — `currency` is kept only for diagnostics.
struct Candidate {
    source: Source,
    currency: String,
    mint: String,
    network: String,
    amount: u64,
    decimals: u8,
    /// Server enumeration order, for stable tie-breaking.
    order: usize,
}

enum Source {
    Mpp(Box<PaymentChallenge>),
    X402(Box<PaymentRequirements>),
}

impl Source {
    fn protocol(&self) -> &'static str {
        match self {
            Self::Mpp(_) => "mpp",
            Self::X402(_) => "x402",
        }
    }
    /// MPP sorts before x402 on ties — it's the native one-shot Solana path.
    fn rank(&self) -> u8 {
        match self {
            Self::Mpp(_) => 0,
            Self::X402(_) => 1,
        }
    }
}

/// Select a payment option the wallet can fund, across MPP and x402.
///
/// `headers`/`body` are the raw 402 response. `funded` lists the tokens the
/// caller will spend with their available balances. `order` decides ranking
/// among the fundable options. Returns the winner, or [`SelectError`] when no
/// advertised option matches a funded token.
///
/// ## Token language
///
/// One language crosses the boundary: the **mint address**. Advertised
/// currencies (MPP `currency`, x402 `currency`) may arrive as a symbol
/// (`"USDC"`) or a mint; both are resolved to a mint here via the shared
/// [`crate::mpp::resolve_stablecoin_mint`] registry before any comparison.
/// `funded[].mint` MUST therefore be canonical mint addresses (matching is
/// exact string equality on the mint), and callers should resolve symbols
/// through that *same* registry so both sides agree. Only
/// [`OrderingStrategy::FixedPriority`] accepts symbols, and it resolves them
/// through the same path.
pub fn select_payment(
    headers: &[(String, String)],
    body: Option<&str>,
    funded: &[AcceptableToken],
    order: &OrderingStrategy,
) -> Result<SelectedPayment, SelectError> {
    select_from_candidates(collect_candidates(headers, body), funded, order)
}

/// Like [`select_payment`], but from already-parsed challenges.
///
/// For callers that have decoded the 402 themselves — e.g. a classifier that
/// already pulled the MPP charge challenges and x402 `accepts` — and want to
/// avoid re-parsing raw headers. Same matching, normalization, and ranking as
/// [`select_payment`]; see its docs for the token-language contract.
pub fn select_payment_parsed(
    mpp_challenges: &[PaymentChallenge],
    x402_accepts: &[PaymentRequirements],
    funded: &[AcceptableToken],
    order: &OrderingStrategy,
) -> Result<SelectedPayment, SelectError> {
    let mut candidates = Vec::new();
    for challenge in mpp_challenges {
        if let Some(c) = mpp_candidate(challenge, candidates.len()) {
            candidates.push(c);
        }
    }
    for requirement in x402_accepts {
        if let Some(c) = x402_candidate(requirement, candidates.len()) {
            candidates.push(c);
        }
    }
    select_from_candidates(candidates, funded, order)
}

/// Filter normalized candidates to the fundable ones, rank, and return the winner.
fn select_from_candidates(
    candidates: Vec<Candidate>,
    funded: &[AcceptableToken],
    order: &OrderingStrategy,
) -> Result<SelectedPayment, SelectError> {
    // Keep only options the wallet can fund, pairing each with the matching
    // token so balance-aware strategies can rank by it.
    let mut fundable: Vec<(usize, &Candidate, &AcceptableToken)> = candidates
        .iter()
        .filter_map(|c| {
            funded
                .iter()
                .find(|t| t.mint == c.mint && t.network == c.network && t.available >= c.amount)
                .map(|token| (c.order, c, token))
        })
        .collect();

    if fundable.is_empty() {
        return Err(SelectError {
            offered: candidates.iter().map(OfferedOption::from).collect(),
            funded: funded.to_vec(),
        });
    }

    rank(&mut fundable, order);

    let (_, winner, _) = fundable.into_iter().next().expect("non-empty after check");
    Ok(winner.to_selected())
}

/// Sort fundable candidates in-place so the best option is first.
fn rank(fundable: &mut [(usize, &Candidate, &AcceptableToken)], order: &OrderingStrategy) {
    match order {
        OrderingStrategy::HighestBalance => {
            fundable.sort_by(|a, b| {
                // Highest available balance first, then native protocol, then
                // server order — stable sort keeps server order on full ties.
                b.2.available
                    .cmp(&a.2.available)
                    .then(a.1.source.rank().cmp(&b.1.source.rank()))
                    .then(a.0.cmp(&b.0))
            });
        }
        OrderingStrategy::CheapestPayable => {
            fundable.sort_by(|a, b| {
                human_amount(a.1)
                    .partial_cmp(&human_amount(b.1))
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.1.source.rank().cmp(&b.1.source.rank()))
                    .then(a.0.cmp(&b.0))
            });
        }
        OrderingStrategy::FixedPriority(prio) => {
            fundable.sort_by(|a, b| {
                priority_index(a.1, prio)
                    .cmp(&priority_index(b.1, prio))
                    .then(a.1.source.rank().cmp(&b.1.source.rank()))
                    .then(a.0.cmp(&b.0))
            });
        }
        OrderingStrategy::MppFirst => {
            fundable.sort_by(|a, b| {
                a.1.source
                    .rank()
                    .cmp(&b.1.source.rank())
                    .then(a.0.cmp(&b.0))
            });
        }
    }
}

/// Decimals-adjusted amount, for comparing cost across tokens.
fn human_amount(c: &Candidate) -> f64 {
    c.amount as f64 / 10f64.powi(c.decimals as i32)
}

/// Position of a candidate's token in a fixed-priority list (`usize::MAX` if
/// absent). Matches by mint or by symbol resolved against the candidate's
/// network.
fn priority_index(c: &Candidate, prio: &[String]) -> usize {
    prio.iter()
        .position(|entry| {
            entry.eq_ignore_ascii_case(&c.mint)
                || resolve_stablecoin_mint(entry, Some(&c.network)) == Some(c.mint.as_str())
        })
        .unwrap_or(usize::MAX)
}

impl Candidate {
    fn to_selected(&self) -> SelectedPayment {
        match &self.source {
            Source::Mpp(challenge) => SelectedPayment::Mpp {
                challenge: challenge.clone(),
                mint: self.mint.clone(),
                network: self.network.clone(),
                amount: self.amount,
            },
            Source::X402(requirement) => SelectedPayment::X402 {
                requirement: requirement.clone(),
                mint: self.mint.clone(),
                network: self.network.clone(),
                amount: self.amount,
            },
        }
    }
}

impl From<&Candidate> for OfferedOption {
    fn from(c: &Candidate) -> Self {
        OfferedOption {
            protocol: c.source.protocol(),
            currency: c.currency.clone(),
            mint: Some(c.mint.clone()),
            network: c.network.clone(),
            amount: c.amount,
        }
    }
}

/// Enumerate every charge option from both protocols, parsed from the raw 402.
fn collect_candidates(headers: &[(String, String)], body: Option<&str>) -> Vec<Candidate> {
    let mut out = Vec::new();

    let www = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("www-authenticate"))
        .map(|(_, value)| value.as_str());
    for challenge in parse_www_authenticate_all(www).into_iter().flatten() {
        if let Some(c) = mpp_candidate(&challenge, out.len()) {
            out.push(c);
        }
    }

    for requirement in parse_x402_accepts(headers, body) {
        if let Some(c) = x402_candidate(&requirement, out.len()) {
            out.push(c);
        }
    }

    out
}

/// Normalize one MPP charge challenge to a [`Candidate`]. Returns `None` for
/// non-charge, SOL-denominated, or unparseable challenges.
fn mpp_candidate(challenge: &PaymentChallenge, order: usize) -> Option<Candidate> {
    if !is_solana_charge_challenge(challenge) {
        return None;
    }
    let request = challenge.request.decode::<ChargeRequest>().ok()?;
    if request.currency.eq_ignore_ascii_case("SOL") {
        return None;
    }
    let details: MethodDetails = request
        .method_details
        .clone()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    let network = normalize_network(details.network.as_deref().unwrap_or("mainnet"));
    let mint = resolve_mint(&request.currency, &network)?;
    let amount = request.amount.parse::<u64>().ok()?;
    Some(Candidate {
        currency: request.currency,
        mint,
        network,
        amount,
        decimals: details.decimals.unwrap_or(6),
        source: Source::Mpp(Box::new(challenge.clone())),
        order,
    })
}

/// Normalize one x402 accept to a [`Candidate`]. Returns `None` for
/// SOL-denominated, unparseable, or non-Solana requirements.
fn x402_candidate(requirement: &PaymentRequirements, order: usize) -> Option<Candidate> {
    if requirement.currency.eq_ignore_ascii_case("SOL") {
        return None;
    }
    // Resolve the canonical CAIP-2 `network` (e.g. "solana:EtWT…" for devnet)
    // — or an explicit `cluster` — to a cluster slug. A plain substring scan
    // would miss CAIP-2 genesis-hash ids and mislabel them mainnet, so go
    // through `cluster_for_caip2_network`, which also handles the short forms.
    // `None` means the offer isn't on a recognized Solana network → skip it.
    let cluster = cluster_for_caip2_network(&requirement.network).or_else(|| {
        requirement
            .cluster
            .as_deref()
            .and_then(cluster_for_caip2_network)
    })?;
    let network = normalize_network(cluster);
    let mint = resolve_mint(&requirement.currency, &network)?;
    let amount = requirement.amount.parse::<u64>().ok()?;
    Some(Candidate {
        currency: requirement.currency.clone(),
        mint,
        network,
        amount,
        decimals: requirement.decimals.unwrap_or(6),
        source: Source::X402(Box::new(requirement.clone())),
        order,
    })
}

/// Resolve a currency (symbol or mint) to a mint address. A recognized symbol
/// maps to its mint on `network`; an already-mint currency passes through;
/// `SOL` (or anything resolving to native) yields `None`.
fn resolve_mint(currency: &str, network: &str) -> Option<String> {
    if currency.eq_ignore_ascii_case("SOL") {
        return None;
    }
    resolve_stablecoin_mint(currency, Some(network))
        .map(str::to_string)
        .or_else(|| Some(currency.to_string()))
}

/// Collapse the various network spellings to a canonical slug.
fn normalize_network(raw: &str) -> String {
    let n = raw.trim().to_ascii_lowercase();
    if n.contains("devnet") {
        "devnet".to_string()
    } else if n.contains("testnet") {
        "testnet".to_string()
    } else if n.contains("localnet") || n.contains("local") {
        "localnet".to_string()
    } else {
        "mainnet".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpp::{format_www_authenticate, mints, Base64UrlJson, PaymentChallenge};

    const RECIPIENT: &str = "11111111111111111111111111111111";

    /// A `WWW-Authenticate: Payment …` value carrying one Solana charge challenge.
    fn mpp_charge(currency: &str, amount: u64) -> (String, String) {
        let request = serde_json::json!({
            "amount": amount.to_string(),
            "currency": currency,
            "recipient": RECIPIENT,
            "methodDetails": { "network": "mainnet" },
        });
        let challenge = PaymentChallenge::new(
            "id-1",
            "realm",
            "solana",
            "charge",
            Base64UrlJson::from_value(&request).unwrap(),
        );
        (
            "www-authenticate".to_string(),
            format_www_authenticate(&challenge).unwrap(),
        )
    }

    /// An x402 `PAYMENT-REQUIRED` JSON body advertising one `accepts` entry.
    fn x402_body(currency: &str, amount: u64) -> String {
        serde_json::json!({
            "x402Version": 1,
            "accepts": [{
                "network": "solana:mainnet",
                "cluster": "mainnet-beta",
                "recipient": RECIPIENT,
                "amount": amount.to_string(),
                "currency": currency,
                "decimals": 6,
                "resource": "https://example.com/r",
            }],
        })
        .to_string()
    }

    fn token(mint: &str, available: u64) -> AcceptableToken {
        AcceptableToken {
            mint: mint.to_string(),
            network: "mainnet".to_string(),
            available,
        }
    }

    // The reported bug: USDG over MPP, USDC over x402, wallet holds only USDC.
    // Must settle the USDC x402 accept instead of erroring on the unfunded MPP.
    #[test]
    fn usdc_x402_chosen_when_only_usdc_funded() {
        let headers = vec![mpp_charge("USDG", 1000)];
        let body = x402_body("USDC", 1000);
        let funded = vec![token(mints::USDC_MAINNET, 1_000_000)];

        let selected = select_payment(
            &headers,
            Some(&body),
            &funded,
            &OrderingStrategy::HighestBalance,
        )
        .expect("a fundable option exists");

        assert_eq!(selected.protocol(), "x402");
        assert_eq!(selected.mint(), mints::USDC_MAINNET);
    }

    #[test]
    fn fixed_priority_picks_listed_token_across_protocols() {
        let headers = vec![mpp_charge("USDC", 1000)];
        let body = x402_body("USDG", 1000);
        let funded = vec![
            token(mints::USDC_MAINNET, 1_000_000),
            token(mints::USDG_MAINNET, 1_000_000),
        ];

        let usdg_first = select_payment(
            &headers,
            Some(&body),
            &funded,
            &OrderingStrategy::FixedPriority(vec!["USDG".to_string()]),
        )
        .unwrap();
        assert_eq!(usdg_first.protocol(), "x402");
        assert_eq!(usdg_first.mint(), mints::USDG_MAINNET);

        let usdc_first = select_payment(
            &headers,
            Some(&body),
            &funded,
            &OrderingStrategy::FixedPriority(vec!["USDC".to_string()]),
        )
        .unwrap();
        assert_eq!(usdc_first.protocol(), "mpp");
        assert_eq!(usdc_first.mint(), mints::USDC_MAINNET);
    }

    #[test]
    fn highest_balance_prefers_larger_holding() {
        let headers = vec![mpp_charge("USDC", 1000)];
        let body = x402_body("USDG", 1000);
        let funded = vec![
            token(mints::USDC_MAINNET, 10_000),
            token(mints::USDG_MAINNET, 5_000_000),
        ];

        let selected = select_payment(
            &headers,
            Some(&body),
            &funded,
            &OrderingStrategy::HighestBalance,
        )
        .unwrap();
        assert_eq!(selected.mint(), mints::USDG_MAINNET);
    }

    #[test]
    fn cheapest_payable_prefers_lower_amount() {
        let headers = vec![mpp_charge("USDC", 5000)];
        let body = x402_body("USDG", 1000);
        let funded = vec![
            token(mints::USDC_MAINNET, 1_000_000),
            token(mints::USDG_MAINNET, 1_000_000),
        ];

        let selected = select_payment(
            &headers,
            Some(&body),
            &funded,
            &OrderingStrategy::CheapestPayable,
        )
        .unwrap();
        assert_eq!(selected.mint(), mints::USDG_MAINNET);
        assert_eq!(selected.protocol(), "x402");
    }

    #[test]
    fn errors_with_offered_and_held_when_nothing_funded() {
        let headers = vec![mpp_charge("USDG", 1000)];
        let funded = vec![token(mints::USDC_MAINNET, 1_000_000)];

        let err = select_payment(&headers, None, &funded, &OrderingStrategy::HighestBalance)
            .expect_err("USDG not held");

        assert_eq!(err.offered.len(), 1);
        assert_eq!(err.offered[0].mint.as_deref(), Some(mints::USDG_MAINNET));
        assert_eq!(err.funded.len(), 1);
        // Display enumerates both sides for an actionable message.
        let msg = err.to_string();
        assert!(msg.contains(mints::USDG_MAINNET));
        assert!(msg.contains(mints::USDC_MAINNET));
    }

    #[test]
    fn amount_exceeding_balance_is_not_fundable() {
        let headers = vec![mpp_charge("USDC", 1_000_000)];
        let funded = vec![token(mints::USDC_MAINNET, 10)]; // holds USDC, but too little

        let err = select_payment(&headers, None, &funded, &OrderingStrategy::HighestBalance)
            .expect_err("balance below required amount");
        assert_eq!(err.offered.len(), 1);
    }

    #[test]
    fn mpp_first_keeps_legacy_bias() {
        let headers = vec![mpp_charge("USDC", 1000)];
        let body = x402_body("USDC", 1000);
        let funded = vec![token(mints::USDC_MAINNET, 1_000_000)];

        let selected =
            select_payment(&headers, Some(&body), &funded, &OrderingStrategy::MppFirst).unwrap();
        assert_eq!(selected.protocol(), "mpp");
    }

    // Regression: an x402 offer that carries a canonical CAIP-2 devnet network
    // id and *no* human `cluster` field must be recognized as devnet (not
    // silently mislabeled mainnet and dropped). Uses the real devnet genesis
    // hash so the deserializer copies it into `cluster`.
    #[test]
    fn caip2_devnet_network_without_cluster_is_recognized() {
        // solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1 == devnet (x402 SOLANA_DEVNET).
        let body = serde_json::json!({
            "x402Version": 1,
            "accepts": [{
                "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
                "recipient": RECIPIENT,
                "amount": "1000",
                "currency": "USDC",
                "decimals": 6,
                "resource": "https://example.com/r",
            }],
        })
        .to_string();
        let funded = vec![AcceptableToken {
            mint: mints::USDC_DEVNET.to_string(),
            network: "devnet".to_string(),
            available: 1_000_000,
        }];

        let selected = select_payment(&[], Some(&body), &funded, &OrderingStrategy::HighestBalance)
            .expect("CAIP-2 devnet offer should be fundable with devnet USDC");
        assert_eq!(selected.protocol(), "x402");
        assert_eq!(selected.mint(), mints::USDC_DEVNET);
    }
}
