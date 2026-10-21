//! `pkc run --tier interop`: start one validator, build the native adapters
//! once, run every selected case (fresh accounts each, several in parallel),
//! assert centrally, reconcile against both SDKs' expectations files and
//! write `harness/results/interop[-<shard>].json` plus JUnit.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::run::driver::{self, Record, SdkReport};
use crate::run::expectations::{self, Decision, Expectations, Observed};

use super::adapters;
use super::cases::{self, Case};
use super::chain::{Accounts, Chain, PAYMENT_CHANNELS_PROGRAM};
use super::claims::{Intent, Role};
use super::plan;
use super::process::{ClientResult, Launcher};
use super::proxy::{self, FaultContext, Mode, Proxy};
use super::scenarios::{Asset, CanonicalCode, Expect, Kind, PaymentMode, Scenario};
use super::settle;

const SECRET_A: &str = "mpp-harness-secret-key-with-32b-pad";
const SECRET_B: &str = "mpp-harness-secret-key-server-b-pad";
const SETTLEMENT_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct Options {
    pub root: PathBuf,
    /// Languages to include (a case runs when both of its languages are
    /// selected); empty means every language.
    pub sdks: Vec<String>,
    pub shard: Option<String>,
    /// Case ids (`<scenario>/<client>/<server>`) or scenario ids.
    pub cases: Vec<String>,
    pub require: bool,
    pub discover: bool,
    pub jobs: usize,
    pub timeout: Duration,
    /// Prebuilt native adapters; `None` builds them into
    /// `rust/target/pkc-adapters` first.
    pub prebuilt: Option<PathBuf>,
    pub program_so: Option<PathBuf>,
    pub results_dir: PathBuf,
    pub write: bool,
    pub verbose: bool,
}

impl Options {
    pub fn new(root: &Path) -> Self {
        let env_on = |k: &str| std::env::var(k).is_ok_and(|v| v == "1");
        Self {
            root: root.to_path_buf(),
            sdks: Vec::new(),
            shard: None,
            cases: Vec::new(),
            require: env_on("HARNESS_REQUIRE"),
            discover: env_on("HARNESS_EXPECTATIONS_DISCOVER"),
            jobs: 4,
            timeout: Duration::from_secs(120),
            prebuilt: std::env::var("HARNESS_PREBUILT_DIR")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
            program_so: std::env::var("PAYMENT_CHANNELS_PROGRAM_SO")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .map(PathBuf::from),
            results_dir: root.join("harness/results"),
            write: true,
            verbose: false,
        }
    }

    fn label(&self) -> String {
        match &self.shard {
            Some(s) => format!("interop-{s}"),
            None => "interop".into(),
        }
    }
}

struct Ctx<'a> {
    chain: &'a Chain,
    rt: &'a tokio::runtime::Runtime,
    launcher: Launcher<'a>,
}

/// Why a case passed or failed, for the record and the failure report.
#[derive(Default)]
struct Log {
    notes: Vec<String>,
    client: Option<Value>,
    client_stderr: String,
    server_stderr: String,
    proxy: Option<Value>,
}

impl Log {
    fn render(&self) -> String {
        let mut out = String::new();
        for n in &self.notes {
            out.push_str(&format!("\nnote: {n}"));
        }
        if let Some(c) = &self.client {
            out.push_str(&format!(
                "\nclient result: {}",
                truncate(&c.to_string(), 2000)
            ));
        }
        if let Some(p) = &self.proxy {
            out.push_str(&format!("\nproxy: {}", truncate(&p.to_string(), 3000)));
        }
        out
    }

    fn stderr(&self) -> String {
        let mut out = String::new();
        if !self.server_stderr.trim().is_empty() {
            out.push_str(&format!(
                "--- server stderr (tail) ---\n{}\n",
                self.server_stderr.trim_end()
            ));
        }
        if !self.client_stderr.trim().is_empty() {
            out.push_str(&format!(
                "--- client stderr (tail) ---\n{}\n",
                self.client_stderr.trim_end()
            ));
        }
        out
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} bytes)", &text[..end], text.len())
}

/// `environmentForScenario` from `e2e.test.ts`, with per-case keys.
pub fn environment(s: &Scenario, acc: &Accounts, rpc_url: &str) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    let mut set = |k: &str, v: String| {
        env.insert(k.to_string(), v);
    };
    set("MPP_HARNESS_RPC_URL", rpc_url.into());
    set("MPP_HARNESS_NETWORK", s.network.into());
    set("MPP_HARNESS_MINT", acc.wire_currency.clone());
    set("MPP_HARNESS_PRICE", s.price.into());
    set("MPP_HARNESS_SECRET_KEY", SECRET_A.into());
    set("MPP_HARNESS_PAY_TO", acc.pay_to.pubkey.clone());
    set("MPP_HARNESS_CLIENT_SECRET_KEY", acc.client.secret_json());
    set(
        "MPP_HARNESS_FEE_PAYER_SECRET_KEY",
        acc.fee_payer.secret_json(),
    );
    set("X402_HARNESS_RPC_URL", rpc_url.into());
    set("X402_HARNESS_PAY_TO", acc.pay_to.pubkey.clone());
    set("X402_HARNESS_CLIENT_SECRET_KEY", acc.client.secret_json());
    set(
        "X402_HARNESS_FACILITATOR_SECRET_KEY",
        acc.fee_payer.secret_json(),
    );
    set("X402_HARNESS_UPTO_PAY_TO", acc.upto_pay_to.pubkey.clone());
    set(
        "X402_HARNESS_UPTO_FEE_PAYER_SECRET_KEY",
        acc.upto_pay_to.secret_json(),
    );
    set(
        "X402_HARNESS_UPTO_RECEIVER_AUTHORIZER_SECRET_KEY",
        acc.upto_pay_to.secret_json(),
    );
    set(
        "PAYMENT_CHANNELS_PROGRAM_ID",
        PAYMENT_CHANNELS_PROGRAM.into(),
    );
    set("MPP_HARNESS_AMOUNT", s.amount.into());
    set(
        "MPP_HARNESS_PAYMENT_MODE",
        match s.payment_mode {
            PaymentMode::Pull => "pull",
            PaymentMode::Push => "push",
        }
        .into(),
    );
    set("MPP_HARNESS_RESOURCE_PATH", s.resource_path.into());
    set("MPP_HARNESS_DECIMALS", s.asset.decimals().to_string());
    set(
        "MPP_HARNESS_ASSET_KIND",
        if s.asset == Asset::Sol { "sol" } else { "spl" }.into(),
    );
    set("MPP_HARNESS_SETTLEMENT_HEADER", s.settlement_header.into());
    let splits: Vec<Value> = s
        .splits
        .iter()
        .map(|sp| {
            let mut v = json!({"recipient": acc.platform.pubkey, "amount": sp.amount});
            if let Some(a) = sp.ata_creation_required {
                v["ataCreationRequired"] = json!(a);
            }
            if let Some(m) = sp.memo {
                v["memo"] = json!(m);
            }
            v
        })
        .collect();
    set("MPP_HARNESS_SPLITS", Value::Array(splits).to_string());
    if let Some(limit) = s.compute_unit_limit {
        set("MPP_HARNESS_COMPUTE_UNIT_LIMIT", limit.to_string());
    }
    match s.intent {
        Intent::X402Exact | Intent::X402Upto => {
            set(
                "PAY_KIT_HARNESS_PROTOCOL",
                if s.intent == Intent::X402Upto {
                    "x402-upto"
                } else {
                    "x402"
                }
                .into(),
            );
            set("X402_HARNESS_AMOUNT", s.amount.into());
            if let Some(actual) = s.actual_amount {
                set("X402_HARNESS_ACTUAL_AMOUNT", actual.into());
            }
            set("X402_HARNESS_MINT", acc.wire_currency.clone());
            set("X402_HARNESS_NETWORK", s.network.into());
            set("X402_HARNESS_PRICE", s.price.into());
            set("X402_HARNESS_RESOURCE_PATH", s.resource_path.into());
            set("X402_HARNESS_SETTLEMENT_HEADER", s.settlement_header.into());
            if s.intent == Intent::X402Upto {
                set("X402_HARNESS_PAY_TO", acc.upto_pay_to.pubkey.clone());
                set(
                    "X402_HARNESS_FEE_PAYER_SECRET_KEY",
                    acc.upto_pay_to.secret_json(),
                );
                set(
                    "X402_HARNESS_RECEIVER_AUTHORIZER_SECRET_KEY",
                    acc.upto_pay_to.secret_json(),
                );
                // Legacy name some upto servers still read.
                set(
                    "X402_HARNESS_FACILITATOR_SECRET_KEY",
                    acc.upto_pay_to.secret_json(),
                );
            }
        }
        Intent::Session => set("PAY_KIT_HARNESS_PROTOCOL", "session".into()),
        Intent::Charge => set("PAY_KIT_HARNESS_PROTOCOL", "mpp".into()),
    }
    env
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Balances {
    primary: u64,
    splits: u64,
    client: u64,
}

fn balances(ctx: &Ctx<'_>, s: &Scenario, acc: &Accounts) -> Result<Balances, String> {
    let primary_owner = if s.intent == Intent::X402Upto {
        &acc.upto_pay_to.pubkey
    } else {
        &acc.pay_to.pubkey
    };
    let read = |owner: &str| -> Result<u64, String> {
        match (&acc.mint, acc.token_program) {
            (Some(mint), Some(program)) => ctx.chain.token_balance(owner, mint, program),
            _ => ctx.chain.lamports(owner),
        }
    };
    Ok(Balances {
        primary: read(primary_owner)?,
        splits: if s.splits.is_empty() {
            0
        } else {
            read(&acc.platform.pubkey)?
        },
        // Lamports move with fees, so only token balances are compared.
        client: if acc.mint.is_some() {
            read(&acc.client.pubkey)?
        } else {
            0
        },
    })
}

fn expect_code(code: Option<CanonicalCode>, body: &Value, who: &str) -> Result<(), String> {
    let Some(code) = code else { return Ok(()) };
    match body["code"].as_str() {
        Some(c) if c == code.as_str() => Ok(()),
        other => Err(format!(
            "{who} did not emit the canonical code {} on its 402; got {}",
            code.as_str(),
            other
                .map(|c| format!("{c:?}"))
                .unwrap_or_else(|| format!("body {body}"))
        )),
    }
}

fn no_funds_moved(before: &Balances, after: &Balances) -> Result<(), String> {
    if before == after {
        Ok(())
    } else {
        Err(format!(
            "funds moved on a rejected payment: recipient {} -> {}, splits {} -> {}, client {} -> {}",
            before.primary, after.primary, before.splits, after.splits, before.client, after.client
        ))
    }
}

fn paid_once(s: &Scenario, before: &Balances, after: &Balances) -> Result<(), String> {
    let primary = after.primary.wrapping_sub(before.primary);
    let splits = after.splits.wrapping_sub(before.splits);
    let want_splits: u64 = s
        .splits
        .iter()
        .map(|sp| sp.amount.parse::<u64>().expect("split"))
        .sum();
    if primary != s.primary_delta() || splits != want_splits {
        return Err(format!(
            "balance deltas: recipient +{primary} (expected +{}), splits +{splits} (expected +{want_splits})",
            s.primary_delta()
        ));
    }
    Ok(())
}

fn settled(ctx: &Ctx<'_>, s: &Scenario, acc: &Accounts, signature: &str) -> Result<(), String> {
    let tx = ctx.chain.transaction(signature, SETTLEMENT_DEADLINE)?;
    let message = settle::decode(&tx)?;
    settle::assert_shape(s, acc, &message)
}

fn assert_paid(
    ctx: &Ctx<'_>,
    s: &Scenario,
    acc: &Accounts,
    result: &ClientResult,
    before: &Balances,
    onchain: bool,
) -> Result<(), String> {
    if result.status != 200 || !result.ok {
        return Err(format!(
            "expected 200, got {} (ok={})",
            result.status, result.ok
        ));
    }
    if result.body["ok"] != true || result.body["paid"] != true {
        return Err(format!(
            "expected body {{ok: true, paid: true}}, got {}",
            result.body
        ));
    }
    let signature = result
        .settlement
        .as_deref()
        .ok_or("the client reported no settlement")?;
    if onchain {
        settled(ctx, s, acc, signature)?;
        paid_once(s, before, &balances(ctx, s, acc)?)?;
    }
    Ok(())
}

fn fault_context(case: &Case, acc: &Accounts) -> FaultContext {
    FaultContext {
        intent: case.scenario.intent,
        client_seed: acc.client.seed,
        attacker: acc.attacker.pubkey.clone(),
        amount: case.scenario.primary_delta(),
    }
}

fn execute(ctx: &Ctx<'_>, case: &Case, log: &mut Log) -> Result<(), String> {
    let s = case.scenario;
    let acc = ctx.chain.accounts(s)?;
    let env = environment(s, &acc, &ctx.chain.rpc_url);
    let mut server_env = env.clone();
    let mut target_path = s.resource_path;
    if let Kind::CrossRouteReplay {
        source_path,
        source_price,
        source_amount,
    } = s.kind
    {
        server_env.insert("MPP_HARNESS_REPLAY_SOURCE_PATH".into(), source_path.into());
        server_env.insert(
            "MPP_HARNESS_REPLAY_SOURCE_PRICE".into(),
            source_price.into(),
        );
        server_env.insert(
            "MPP_HARNESS_REPLAY_SOURCE_AMOUNT".into(),
            source_amount.into(),
        );
        target_path = source_path;
    }
    let before = balances(ctx, s, &acc)?;
    let (mut server, port) = match ctx.launcher.start_server(case.server, &server_env) {
        Ok(v) => v,
        Err(e) => {
            if let Expect::Rejected {
                refusing_to_start: true,
                ..
            } = s.expect
            {
                if e.message.contains("before readiness") {
                    log.notes
                        .push(format!("the server refused to start: {}", e.message));
                    log.server_stderr = e.stderr;
                    return Ok(());
                }
            }
            log.server_stderr = e.stderr.clone();
            return Err(format!("server adapter: {}", e.message));
        }
    };
    let upstream = format!("http://127.0.0.1:{port}");
    let mode = match s.kind {
        Kind::Standard => Mode::PassThrough,
        Kind::IdempotentResubmit | Kind::CrossServerPortability => Mode::Capture,
        Kind::CrossRouteReplay { source_path, .. } => Mode::RouteRewrite {
            from: source_path.into(),
            to: s.resource_path.into(),
        },
        Kind::ServerFault(f) => Mode::ServerFault(f, fault_context(case, &acc)),
        Kind::ClientFault(f) => Mode::ClientFault(f, fault_context(case, &acc)),
    };
    let proxy = Proxy::start(ctx.rt, &upstream, mode)?;
    let client =
        ctx.launcher
            .run_client(case.client, &format!("{}{target_path}", proxy.base), &env);
    let observed = proxy.observed();
    log.proxy = Some(observed.summary());
    match &client {
        Ok(r) => {
            log.client = Some(r.raw.clone());
            log.client_stderr = r.stderr.clone();
        }
        Err(e) => {
            log.client_stderr = e.stderr.clone();
            log.notes.push(format!("client adapter: {}", e.message));
        }
    }
    let outcome = judge(ctx, case, &acc, &before, &client, &observed, &upstream);
    log.server_stderr = server.stderr();
    server.stop();
    drop(proxy);
    outcome
}

fn judge(
    ctx: &Ctx<'_>,
    case: &Case,
    acc: &Accounts,
    before: &Balances,
    client: &Result<ClientResult, super::process::AdapterError>,
    observed: &proxy::Observed,
    upstream: &str,
) -> Result<(), String> {
    let s = case.scenario;
    let need_client = || -> Result<&ClientResult, String> {
        client
            .as_ref()
            .map_err(|e| format!("client adapter failed: {}", e.message))
    };
    match (s.kind, s.expect) {
        (Kind::Standard, Expect::Paid { onchain }) => {
            assert_paid(ctx, s, acc, need_client()?, before, onchain)
        }
        (Kind::Standard, Expect::Rejected { code, .. }) => {
            let r = need_client()?;
            if r.status != 402 || r.ok {
                return Err(format!("expected 402, got {} (ok={})", r.status, r.ok));
            }
            no_funds_moved(before, &balances(ctx, s, acc)?)?;
            expect_code(code, &r.body, &format!("server {}", case.server.id))
        }
        (Kind::CrossRouteReplay { .. } | Kind::ServerFault(_), Expect::Rejected { code, .. }) => {
            if let Some(e) = &observed.fault_error {
                return Err(format!("the fault proxy could not apply the fault: {e}"));
            }
            let faulted = observed.faulted_exchange().ok_or(
                "the client never presented a credential the proxy could fault (see the client adapter note)",
            )?;
            if faulted.status != 402 {
                return Err(format!(
                    "server {} answered the faulted presentation with {}, expected 402",
                    case.server.id, faulted.status
                ));
            }
            no_funds_moved(before, &balances(ctx, s, acc)?)?;
            expect_code(code, &faulted.body, &format!("server {}", case.server.id))
        }
        (
            Kind::IdempotentResubmit | Kind::CrossServerPortability,
            Expect::Rejected { code, .. },
        ) => {
            let r = need_client()?;
            if r.status != 200 {
                return Err(format!("the first payment must succeed; got {}", r.status));
            }
            let captured = observed
                .captured
                .as_ref()
                .ok_or("the proxy saw no credential the server accepted")?;
            let (status, body) = if s.kind == Kind::CrossServerPortability {
                let mut env_b = environment(s, acc, &ctx.chain.rpc_url);
                env_b.insert("MPP_HARNESS_SECRET_KEY".into(), SECRET_B.into());
                let (mut b, port_b) = ctx
                    .launcher
                    .start_server(case.server, &env_b)
                    .map_err(|e| format!("server B: {e}"))?;
                let out = proxy::replay(ctx.rt, captured, &format!("http://127.0.0.1:{port_b}"));
                b.stop();
                out?
            } else {
                proxy::replay(ctx.rt, captured, upstream)?
            };
            if status != 402 {
                return Err(format!(
                    "the second presentation of an accepted credential got {status}, expected 402 (body {body})"
                ));
            }
            if let Some(sig) = &r.settlement {
                ctx.chain.transaction(sig, SETTLEMENT_DEADLINE)?;
            }
            paid_once(s, before, &balances(ctx, s, acc)?)?;
            let who = if s.kind == Kind::CrossServerPortability {
                format!("server B ({})", case.server.id)
            } else {
                format!("server {}", case.server.id)
            };
            expect_code(code, &body, &who)
        }
        (Kind::ClientFault(_), Expect::NoCredential) => {
            // A refusal is a result, or a non-zero exit before one; a hung
            // or broken client did not refuse anything.
            if let Err(e) = client {
                if !e.refused {
                    return Err(format!(
                        "client {} did not refuse the tampered challenge cleanly: {}",
                        case.client.id, e.message
                    ));
                }
            }
            if let Some(e) = &observed.fault_error {
                return Err(format!(
                    "the fault proxy could not tamper with the challenge: {e}"
                ));
            }
            if !observed.fault_applied {
                return Err(
                    "the pivot server emitted no challenge for the proxy to tamper with".into(),
                );
            }
            let submitted = observed.credentials_after_fault();
            if !submitted.is_empty() {
                return Err(format!(
                    "client {} submitted {} credential(s) for the tampered challenge",
                    case.client.id,
                    submitted.len()
                ));
            }
            no_funds_moved(before, &balances(ctx, s, acc)?)
        }
        (kind, expect) => Err(format!("unsupported scenario shape {kind:?} / {expect:?}")),
    }
}

struct Outcome {
    observed: Observed,
    stderr: String,
    duration: Duration,
}

fn run_case(ctx: &Ctx<'_>, case: &Case) -> Outcome {
    let started = Instant::now();
    let mut log = Log::default();
    let result = execute(ctx, case, &mut log);
    let observed = match result {
        Ok(()) => Observed::Pass,
        Err(e) => Observed::Fail {
            detail: format!("{e}{}", log.render()),
        },
    };
    Outcome {
        observed,
        stderr: log.stderr(),
        duration: started.elapsed(),
    }
}

/// The cases a run selects, with their decisions.
pub fn select(
    opts: &Options,
    exps: &BTreeMap<String, Expectations>,
) -> Result<Vec<(Case, cases::PairDecision)>, String> {
    let shard_cases: Option<BTreeSet<String>> = match &opts.shard {
        Some(id) => {
            let plan = plan::plan(exps)?;
            let shard = plan.find(id).ok_or_else(|| {
                format!("no interop shard {id:?} (pkc plan --tier interop lists them)")
            })?;
            Some(shard.cases.iter().cloned().collect())
        }
        None => None,
    };
    let sdks: BTreeSet<&str> = opts.sdks.iter().map(String::as_str).collect();
    for sdk in &sdks {
        if !adapters::languages().contains(sdk) {
            return Err(format!("no interop adapter for --sdk {sdk}"));
        }
    }
    for c in &opts.cases {
        if !cases::all()
            .iter()
            .any(|k| k.id() == *c || k.key() == *c || k.scenario.id == c)
        {
            return Err(format!("no interop case or scenario {c:?}"));
        }
    }
    let mut out = Vec::new();
    for case in cases::all() {
        if !sdks.is_empty() && !case.languages().iter().all(|l| sdks.contains(l)) {
            continue;
        }
        if let Some(keys) = &shard_cases {
            if !keys.contains(&case.key()) {
                continue;
            }
        }
        if !opts.cases.is_empty()
            && !opts
                .cases
                .iter()
                .any(|c| case.id() == *c || case.key() == *c || case.scenario.id == c)
        {
            continue;
        }
        let decision = cases::decide(exps, &case)?;
        if decision.decision == Decision::Unclaimed && !opts.discover {
            continue;
        }
        out.push((case, decision));
    }
    Ok(out)
}

fn reconcile(
    exps: &BTreeMap<String, Expectations>,
    case: &Case,
    d: &cases::PairDecision,
    observed: &Observed,
) -> Result<(), String> {
    if let Some(holder) = &d.holder {
        let exp = &exps[holder];
        let role = if case.client.language == holder {
            Role::Client
        } else {
            Role::Server
        };
        let reference = expectations::CaseRef {
            suite: expectations::Suite::Interop,
            id: case.id(),
            capability: match role {
                Role::Client => case.client.claim().to_string(),
                Role::Server => case.server.claim().to_string(),
            },
        };
        return exp.reconcile(&reference, &d.decision, observed);
    }
    match observed {
        Observed::Pass => Ok(()),
        Observed::Fail { detail } => Err(format!(
            "{} failed: {detail}\n(if this is a known gap, add it to known_failing in harness/expectations/{}.toml or {}.toml, on the side the gap belongs to, with tracking)",
            case.key(),
            case.client.language,
            case.server.language
        )),
        Observed::Unsupported { detail } => Err(format!("{}: {detail}", case.key())),
    }
}

pub fn run(opts: &Options) -> Result<SdkReport, String> {
    let started = Instant::now();
    let exps = expectations::load_all(&opts.root.join("harness/expectations"))?;
    let selected = select(opts, &exps)?;
    let mut report = SdkReport {
        suite: "interop",
        language: opts.label(),
        discovery: opts.discover,
        tier: "interop",
        abi: "process",
        capabilities: None,
        duration_ms: 0,
        problems: Vec::new(),
        cases: Vec::new(),
        diff: None,
    };
    if !opts.discover {
        report.problems.extend(cases::dangling(&exps)?);
    }
    if selected.is_empty() {
        report
            .problems
            .push("the selection contains no claimed interop case".into());
        return Ok(report);
    }

    // Native adapters: built once, never inside a case.
    let prebuilt = match &opts.prebuilt {
        Some(dir) => dir.clone(),
        None => {
            let dir = opts.root.join("rust/target/pkc-adapters");
            let targets =
                adapters::native_targets(selected.iter().flat_map(|(c, _)| [c.client, c.server]));
            adapters::build(&opts.root, &targets, &dir, true)?;
            dir
        }
    };
    let scenarios: Vec<&Scenario> = {
        let mut seen = BTreeSet::new();
        selected
            .iter()
            .map(|(c, _)| c.scenario)
            .filter(|s| seen.insert(s.id))
            .collect()
    };
    let program_so = if scenarios.iter().any(|s| s.needs_payment_channels()) {
        match &opts.program_so {
            Some(p) if p.is_file() => Some(p.clone()),
            Some(p) => return Err(format!("payment-channels program {} does not exist", p.display())),
            None => {
                return Err("x402-upto cases need the payment-channels program: pass --program-so <payment_channels.so> or set PAYMENT_CHANNELS_PROGRAM_SO (built by .github/actions/build-payment-channels)".into())
            }
        }
    } else {
        None
    };
    let rt = driver::runtime();
    let chain = Chain::start(&rt, program_so.as_deref(), &scenarios)?;
    eprintln!(
        "pkc interop: surfpool at {}, {} case(s), {} job(s)",
        chain.rpc_url,
        selected.len(),
        opts.jobs
    );
    let harness = opts.root.join("harness");
    let ctx = Ctx {
        chain: &chain,
        rt: &rt,
        launcher: Launcher {
            harness: &harness,
            prebuilt: &prebuilt,
            timeout: opts.timeout,
        },
    };
    let queue: Mutex<VecDeque<usize>> = Mutex::new((0..selected.len()).collect());
    let results: Mutex<Vec<Option<Outcome>>> =
        Mutex::new((0..selected.len()).map(|_| None).collect());
    let total = selected.len();
    let done = Mutex::new(0usize);
    std::thread::scope(|scope| {
        for _ in 0..opts.jobs.max(1) {
            scope.spawn(|| loop {
                let Some(i) = queue.lock().expect("queue").pop_front() else {
                    return;
                };
                let (case, _) = &selected[i];
                let outcome = run_case(&ctx, case);
                {
                    let mut n = done.lock().expect("done");
                    *n += 1;
                    eprintln!(
                        "  [{}/{total}] {} {} ({:.1}s)",
                        *n,
                        case.key(),
                        outcome.observed.kind(),
                        outcome.duration.as_secs_f64()
                    );
                }
                results.lock().expect("results")[i] = Some(outcome);
            });
        }
    });
    let results = results.into_inner().expect("results");
    let mut observed_keys = BTreeSet::new();
    for ((case, d), outcome) in selected.iter().zip(results) {
        let outcome = outcome.expect("every case ran");
        observed_keys.insert(case.key());
        let verdict = if opts.discover {
            Ok(())
        } else {
            reconcile(&exps, case, d, &outcome.observed)
        };
        report.cases.push(Record {
            key: case.key(),
            capability: case.scenario.intent.id().to_string(),
            decision: if opts.discover {
                "pass"
            } else {
                d.decision.kind()
            },
            observed: Some(outcome.observed.kind()),
            detail: outcome.observed.detail().map(str::to_string),
            duration_ms: Some(outcome.duration.as_millis() as u64),
            reject_code: match case.scenario.expect {
                Expect::Rejected { code: Some(c), .. } => Some(c.as_str().to_string()),
                _ => None,
            },
            bug_type: None,
            requirements: vec![case.scenario.spec.spec_ref().doc()],
            ok: verdict.is_ok(),
            problem: verdict.err(),
            stderr: (!matches!(outcome.observed, Observed::Pass)
                && !outcome.stderr.trim().is_empty())
            .then(|| truncate(&outcome.stderr, 8000)),
            explanation: None,
        });
    }
    if opts.require && !opts.discover {
        // Completeness within the selection: every claimed case selected by
        // --shard / --sdk must have executed.
        let missing: Vec<String> = select(opts, &exps)?
            .iter()
            .filter(|(c, d)| d.decision != Decision::Unclaimed && !observed_keys.contains(&c.key()))
            .map(|(c, _)| c.key())
            .collect();
        if !missing.is_empty() {
            report.problems.push(format!(
                "{} claimed interop case(s) were not executed under --require:\n  {}",
                missing.len(),
                missing.join("\n  ")
            ));
        }
    }
    report.duration_ms = started.elapsed().as_millis() as u64;
    if opts.write {
        write(opts, &report)?;
    }
    Ok(report)
}

fn write(opts: &Options, report: &SdkReport) -> Result<(), String> {
    std::fs::create_dir_all(&opts.results_dir).map_err(|e| e.to_string())?;
    let mut sorted = report.clone();
    sorted.cases.sort_by(|a, b| a.key.cmp(&b.key));
    std::fs::write(
        opts.results_dir.join(format!("{}.json", report.language)),
        format!(
            "{}\n",
            serde_json::to_string_pretty(&sorted).map_err(|e| e.to_string())?
        ),
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(
        opts.results_dir
            .join(format!("junit-{}.xml", report.language)),
        driver::junit(std::slice::from_ref(report)),
    )
    .map_err(|e| e.to_string())
}

/// Summary, then every reconciliation failure (with GitHub annotations).
pub fn print(report: &SdkReport) {
    let counts = report.counts();
    let failed_obs = report
        .cases
        .iter()
        .filter(|c| c.observed == Some("fail"))
        .count();
    println!(
        "{}: {} cases: {} pass, {} known_failing (decision), {} observed failing, {:.1}s, {}",
        report.language,
        report.cases.len(),
        counts.get("pass").unwrap_or(&0),
        counts.get("known_failing").unwrap_or(&0),
        failed_obs,
        report.duration_ms as f64 / 1000.0,
        if report.discovery {
            "discovery (not judged)"
        } else if report.failed() {
            "FAILED"
        } else {
            "ok"
        }
    );
    let ci = std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true");
    for p in &report.problems {
        eprintln!("  FAIL {p}");
        if ci {
            println!("::error title=pkc interop::{}", p.replace('\n', "%0A"));
        }
    }
    for c in report.cases.iter().filter(|c| !c.ok) {
        let problem = c.problem.as_deref().unwrap_or("failed");
        eprintln!("  FAIL {problem}");
        if let Some(stderr) = &c.stderr {
            eprintln!(
                "{}",
                stderr
                    .lines()
                    .map(|l| format!("    {l}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        if ci {
            println!(
                "::error title=pkc {}::{}",
                c.key,
                problem.replace('\n', "%0A")
            );
        }
    }
    if report.discovery {
        for c in &report.cases {
            println!("  {} {}", c.observed.unwrap_or("?"), c.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::chain::Key;
    use super::*;

    #[test]
    fn x402_upto_environment_points_every_merchant_role_at_one_key() {
        let s = super::super::scenarios::find("x402-upto-basic").unwrap();
        let k = |n: u8| {
            let mut bytes = [n; 64];
            bytes[32..].copy_from_slice(&[n; 32]);
            Key {
                seed: [n; 32],
                bytes,
                pubkey: format!("key{n}"),
            }
        };
        let acc = Accounts {
            client: k(1),
            pay_to: k(2),
            platform: k(3),
            fee_payer: k(4),
            upto_pay_to: k(5),
            attacker: k(6),
            mint: Some("M".into()),
            wire_currency: "M".into(),
            token_program: Some(crate::keys::TOKEN_PROGRAM),
            decimals: 6,
        };
        let env = environment(s, &acc, "http://rpc");
        assert_eq!(env["X402_HARNESS_PAY_TO"], "key5");
        assert_eq!(
            env["X402_HARNESS_FEE_PAYER_SECRET_KEY"],
            acc.upto_pay_to.secret_json()
        );
        assert_eq!(
            env["X402_HARNESS_FACILITATOR_SECRET_KEY"],
            acc.upto_pay_to.secret_json()
        );
        assert_eq!(env["PAY_KIT_HARNESS_PROTOCOL"], "x402-upto");
        assert_eq!(env["X402_HARNESS_ACTUAL_AMOUNT"], "50000");
        assert_eq!(env["MPP_HARNESS_MINT"], "M");
    }
}
