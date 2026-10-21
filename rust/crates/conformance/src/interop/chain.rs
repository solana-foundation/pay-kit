//! One local surfpool per `pkc run --tier interop` (surfpool-sdk, the rev
//! pinned in `rust/crates/integration-tests/Cargo.toml`), offline: no remote
//! fork. Scenario mints and the payment-channels program are deployed at
//! start; every case then gets fresh keypairs instead of a validator restart.
//!
//! Cheatcodes use a blocking RPC client, so every method here must be called
//! from a plain thread, never from inside the tokio runtime.

use std::path::Path;

use serde_json::{json, Value};
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::request::RpcRequest;
use surfpool_sdk::cheatcodes::builders::DeployProgram;
use surfpool_sdk::{BlockProductionMode, Keypair, Pubkey, Signer, Surfnet};

use crate::fixture_rpc::mint_account_data;

use super::scenarios::{Asset, Scenario};

/// The canonical payment-channels program id (the localnet build declares
/// the same id).
pub const PAYMENT_CHANNELS_PROGRAM: &str = "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX";
/// Treasury owner baked into the deployed (mainnet-build) payment-channels
/// program, which `.github/actions/build-payment-channels` patches into the
/// localnet build too. A localnet build with a different `TREASURY_OWNER`
/// would settle to another treasury ATA and fail the upto shape assertion
/// (README "Limitations").
pub const PAYMENT_CHANNEL_TREASURY_OWNER: &str = "Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP";

const MINT_RENT_LAMPORTS: u64 = 1_461_600;
const WALLET_LAMPORTS: u64 = 5_000_000_000;
const CLIENT_TOKENS: u64 = 1_000_000;

/// A keypair the harness holds: adapters get the 64-byte secret as a JSON
/// array, the fault proxy re-signs with the seed.
#[derive(Clone)]
pub struct Key {
    pub seed: [u8; 32],
    pub bytes: [u8; 64],
    pub pubkey: String,
}

impl Key {
    pub fn fresh() -> Self {
        Self::from_keypair(&Keypair::new())
    }

    fn from_keypair(k: &Keypair) -> Self {
        let bytes = k.to_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        Self {
            seed,
            bytes,
            pubkey: k.pubkey().to_string(),
        }
    }

    /// `[1,2,...]`, the `*_SECRET_KEY` env format.
    pub fn secret_json(&self) -> String {
        serde_json::to_string(&self.bytes.to_vec()).expect("bytes serialise")
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.pubkey)
    }
}

/// Per-case accounts, funded on the shared validator.
#[derive(Debug, Clone)]
pub struct Accounts {
    pub client: Key,
    pub pay_to: Key,
    pub platform: Key,
    pub fee_payer: Key,
    /// The x402 upto merchant: payTo, fee payer and receiver authorizer at
    /// once (as `e2e.test.ts` configured it).
    pub upto_pay_to: Key,
    /// Destination of the wrong-recipient and mis-signed faults.
    pub attacker: Key,
    /// On-chain mint (`None` for SOL).
    pub mint: Option<String>,
    /// What adapters receive as the currency (`MPP_HARNESS_MINT`).
    pub wire_currency: String,
    pub token_program: Option<&'static str>,
    pub decimals: u8,
}

pub struct Chain {
    surfnet: Surfnet,
    pub rpc_url: String,
}

fn pk(address: &str) -> Result<Pubkey, String> {
    address
        .parse()
        .map_err(|e| format!("invalid address {address}: {e}"))
}

impl Chain {
    /// Start the validator, deploy the payment-channels program when
    /// `program_so` is given, and set every fixed scenario mint.
    pub fn start(
        rt: &tokio::runtime::Runtime,
        program_so: Option<&Path>,
        scenarios: &[&Scenario],
    ) -> Result<Self, String> {
        let surfnet = rt
            // Clock-driven blocks: some servers wait for commitment levels
            // that never arrive when slots only advance on transactions.
            .block_on(
                Surfnet::builder()
                    .offline(true)
                    .block_production_mode(BlockProductionMode::Clock)
                    .slot_time_ms(50)
                    .start(),
            )
            .map_err(|e| format!("surfpool failed to start: {e}"))?;
        // Drain simnet events so the channel never backs up over a long run.
        let events = surfnet.events().clone();
        std::thread::spawn(move || while events.recv().is_ok() {});
        let chain = Self {
            rpc_url: surfnet.rpc_url().to_string(),
            surfnet,
        };
        if let Some(so) = program_so {
            chain
                .surfnet
                .cheatcodes()
                .deploy(DeployProgram::new(pk(PAYMENT_CHANNELS_PROGRAM)?).so_path(so))
                .map_err(|e| format!("deploy {}: {e}", so.display()))?;
        }
        let mut fixed = std::collections::BTreeMap::new();
        for s in scenarios {
            if let Asset::Fixed {
                mint,
                decimals,
                program,
                ..
            } = s.asset
            {
                if let Some((d, p)) = fixed.insert(mint, (decimals, program)) {
                    if (d, p) != (decimals, program) {
                        return Err(format!(
                            "scenarios disagree on mint {mint}: decimals/program {d}/{p:?} vs {decimals}/{program:?}"
                        ));
                    }
                }
            }
        }
        for (mint, (decimals, program)) in fixed {
            chain.set_mint(mint, decimals, program.address())?;
        }
        Ok(chain)
    }

    pub fn rpc(&self) -> RpcClient {
        RpcClient::new(self.rpc_url.clone())
    }

    fn set_mint(&self, mint: &str, decimals: u8, program: &str) -> Result<(), String> {
        self.surfnet
            .cheatcodes()
            .set_account(
                &pk(mint)?,
                MINT_RENT_LAMPORTS,
                &mint_account_data(decimals),
                &pk(program)?,
            )
            .map_err(|e| format!("set mint {mint}: {e}"))
    }

    pub fn fund_sol(&self, owner: &str, lamports: u64) -> Result<(), String> {
        self.surfnet
            .cheatcodes()
            .fund_sol(&pk(owner)?, lamports)
            .map_err(|e| format!("fund {owner} with SOL: {e}"))
    }

    pub fn fund_token(
        &self,
        owner: &str,
        mint: &str,
        amount: u64,
        program: &str,
    ) -> Result<(), String> {
        self.surfnet
            .cheatcodes()
            .fund_token(&pk(owner)?, &pk(mint)?, amount, Some(&pk(program)?))
            .map_err(|e| format!("fund {owner} with {amount} of {mint}: {e}"))
    }

    /// Fresh keys and funding for one case.
    pub fn accounts(&self, scenario: &Scenario) -> Result<Accounts, String> {
        let (mint, wire_currency, program) = match scenario.asset {
            Asset::Fixed {
                wire,
                mint,
                program,
                ..
            } => (
                Some(mint.to_string()),
                wire.to_string(),
                Some(program.address()),
            ),
            Asset::Sol => (None, "sol".to_string(), None),
        };
        let acc = Accounts {
            client: Key::fresh(),
            pay_to: Key::fresh(),
            platform: Key::fresh(),
            fee_payer: Key::fresh(),
            upto_pay_to: Key::fresh(),
            attacker: Key::fresh(),
            mint,
            wire_currency,
            token_program: program,
            decimals: scenario.asset.decimals(),
        };
        // A pull-mode server may leave transaction fees to the client.
        self.fund_sol(&acc.client.pubkey, WALLET_LAMPORTS)?;
        self.fund_sol(&acc.fee_payer.pubkey, WALLET_LAMPORTS)?;
        self.fund_sol(&acc.upto_pay_to.pubkey, WALLET_LAMPORTS)?;
        if let (Some(mint), Some(program)) = (&acc.mint, acc.token_program) {
            self.fund_token(&acc.client.pubkey, mint, CLIENT_TOKENS, program)?;
            // The top-level recipient's ATA must exist: clients MUST NOT
            // create it (draft-solana-charge-00 "SPL Tokens").
            self.fund_token(&acc.pay_to.pubkey, mint, 1, program)?;
            self.fund_token(&acc.upto_pay_to.pubkey, mint, 1, program)?;
            if scenario.pre_create_platform_ata {
                self.fund_token(&acc.platform.pubkey, mint, 0, program)?;
            }
        }
        Ok(acc)
    }

    fn send(&self, method: &'static str, params: Value) -> Result<Value, String> {
        self.rpc()
            .send::<Value>(RpcRequest::Custom { method }, params)
            .map_err(|e| format!("{method}: {e}"))
    }

    /// Token balance of `owner`'s ATA; a missing account reads as zero.
    pub fn token_balance(&self, owner: &str, mint: &str, program: &str) -> Result<u64, String> {
        let ata = crate::keys::ata(owner, mint, program).to_string();
        match self.send(
            "getTokenAccountBalance",
            json!([ata, {"commitment": "confirmed"}]),
        ) {
            Ok(v) => v["value"]["amount"]
                .as_str()
                .and_then(|a| a.parse().ok())
                .ok_or_else(|| format!("getTokenAccountBalance {ata}: {v}")),
            Err(e)
                if e.contains("could not find account")
                    || e.contains("Invalid param")
                    || e.contains("not found") =>
            {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }

    pub fn lamports(&self, owner: &str) -> Result<u64, String> {
        let v = self.send("getBalance", json!([owner, {"commitment": "confirmed"}]))?;
        v["value"]
            .as_u64()
            .ok_or_else(|| format!("getBalance {owner}: {v}"))
    }

    /// The confirmed transaction for `signature` (base64), polling until it
    /// is visible or `deadline` passes. Returns the `result` object.
    pub fn transaction(
        &self,
        signature: &str,
        deadline: std::time::Duration,
    ) -> Result<Value, String> {
        let until = std::time::Instant::now() + deadline;
        loop {
            let v = self.send(
                "getTransaction",
                json!([signature, {"commitment": "confirmed", "encoding": "base64", "maxSupportedTransactionVersion": 0}]),
            );
            match v {
                Ok(v) if !v.is_null() => return Ok(v),
                Ok(_) | Err(_) if std::time::Instant::now() < until => {
                    std::thread::sleep(std::time::Duration::from_millis(250))
                }
                Ok(_) => {
                    return Err(format!(
                        "getTransaction {signature}: not found within {:.0}s",
                        deadline.as_secs_f64()
                    ))
                }
                Err(e) => return Err(e),
            }
        }
    }
}
