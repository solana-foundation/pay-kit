//! DEVNET-ONLY integration test for the Musebook credit adapter.
//!
//! Ignored by default. Run with:
//!   MUSEBOOK_DEVNET_PAYER=/path/payer.json MUSEBOOK_DEVNET_ISSUER=/path/issuer.json \
//!   cargo test -p solana-pay-kit --test musebook_devnet -- --ignored --nocapture
//! Keys are read from files and never printed; only pubkeys and signatures are.
//! The test refuses to run unless the RPC's genesis hash is devnet's.

use solana_keypair::Keypair;
use solana_pay_kit::core::payment_channel::v1;
use solana_pay_kit::core::rpc::send_and_confirm_transaction;
use solana_pay_kit::musebook;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};

const DEVNET_RPC: &str = "https://api.devnet.solana.com";
const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";

fn load(var: &str) -> Keypair {
    let path = std::env::var(var).unwrap_or_else(|_| panic!("{var} not set"));
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(path).expect("read key"))
        .expect("keypair json");
    Keypair::try_from(bytes.as_slice()).expect("keypair")
}

fn pk(k: &Keypair) -> Pubkey {
    v1::from_address(&k.pubkey())
}

/// Sweeps every throwaway wallet's lamports back to the deployer when
/// dropped, including when the test panics. Runs on its own thread with its
/// own blocking client so it works from sync and async tests alike.
struct Sweeper {
    to: Pubkey,
    wallets: Vec<Vec<u8>>,
}

impl Sweeper {
    fn new(to: &Keypair, wallets: &[&Keypair]) -> Self {
        Self {
            to: pk(to),
            wallets: wallets.iter().map(|k| k.to_bytes().to_vec()).collect(),
        }
    }
}

impl Drop for Sweeper {
    fn drop(&mut self) {
        let (to, wallets) = (self.to, std::mem::take(&mut self.wallets));
        let joined = std::thread::spawn(move || {
            let rpc = RpcClient::new_with_commitment(
                DEVNET_RPC.to_string(),
                solana_commitment_config::CommitmentConfig::confirmed(),
            );
            for bytes in wallets {
                let kp = Keypair::try_from(bytes.as_slice()).expect("wallet");
                for _ in 0..3 {
                    let Ok(left) = rpc.get_balance(&kp.pubkey()) else {
                        continue;
                    };
                    if left <= 5_000 {
                        break;
                    }
                    let Ok(hash) = rpc.get_latest_blockhash() else {
                        continue;
                    };
                    let tx = Transaction::new_signed_with_payer(
                        &[system_ix(
                            2,
                            &pk(&kp),
                            &to,
                            &(left - 5_000).to_le_bytes(),
                            None,
                        )],
                        Some(&kp.pubkey()),
                        &[&kp],
                        hash,
                    );
                    match send_and_confirm_transaction(&rpc, &VersionedTransaction::from(tx)) {
                        Ok(sig) => {
                            println!(
                                "SWEEP {} -> deployer {} lamports: {sig}",
                                kp.pubkey(),
                                left - 5_000
                            );
                            break;
                        }
                        Err(e) => println!("sweep {} retry: {e}", kp.pubkey()),
                    }
                }
            }
        })
        .join();
        if joined.is_err() {
            println!("sweep thread panicked");
        }
    }
}

struct Net {
    rpc: RpcClient,
    sigs: Vec<(String, String)>,
}

impl Net {
    fn send(
        &mut self,
        label: &str,
        ixs: &[solana_instruction::Instruction],
        payer: &Keypair,
        signers: &[&Keypair],
    ) {
        let hash = self.rpc.get_latest_blockhash().expect("blockhash");
        let tx = Transaction::new_signed_with_payer(ixs, Some(&payer.pubkey()), signers, hash);
        let sig = send_and_confirm_transaction(&self.rpc, &VersionedTransaction::from(tx))
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        println!("PASS {label}: {sig}");
        self.sigs.push((label.to_string(), sig.to_string()));
    }
    fn token_balance(&self, account: &Pubkey) -> u64 {
        let a = self
            .rpc
            .get_account(&v1::to_address(account))
            .expect("account");
        u64::from_le_bytes(a.data[64..72].try_into().unwrap())
    }
}

fn system_ix(
    op: u32,
    from: &Pubkey,
    to: &Pubkey,
    tail: &[u8],
    owner: Option<&Pubkey>,
) -> solana_instruction::Instruction {
    use solana_instruction::AccountMeta;
    let mut data = op.to_le_bytes().to_vec();
    data.extend(tail);
    if let Some(o) = owner {
        data.extend(o.to_bytes());
    }
    solana_instruction::Instruction {
        program_id: v1::to_address(&v1::system_program_id()),
        accounts: vec![
            AccountMeta::new(v1::to_address(from), true),
            AccountMeta::new(v1::to_address(to), op == 0),
        ],
        data,
    }
}

fn token_ix(
    op: u8,
    amount: Option<u64>,
    accounts: Vec<(Pubkey, bool, bool)>,
) -> solana_instruction::Instruction {
    let mut data = vec![op];
    if let Some(a) = amount {
        data.extend(a.to_le_bytes());
    }
    solana_instruction::Instruction {
        program_id: v1::to_address(&v1::parse_pubkey(musebook::TOKEN_PROGRAM_ID).unwrap()),
        accounts: accounts
            .into_iter()
            .map(|(k, w, s)| solana_instruction::AccountMeta {
                pubkey: v1::to_address(&k),
                is_writable: w,
                is_signer: s,
            })
            .collect(),
        data,
    }
}

#[test]
#[ignore = "devnet; needs MUSEBOOK_DEVNET_PAYER and MUSEBOOK_DEVNET_ISSUER"]
fn musebook_credit_channel_lifecycle_on_devnet() {
    let rpc = RpcClient::new_with_commitment(
        DEVNET_RPC.to_string(),
        solana_commitment_config::CommitmentConfig::confirmed(),
    );
    assert_eq!(
        rpc.get_genesis_hash().unwrap().to_string(),
        DEVNET_GENESIS,
        "devnet only"
    );
    let mut net = Net { rpc, sigs: vec![] };
    let d = musebook::deployment("devnet").expect("devnet deployment");
    assert!(musebook::deployment("mainnet").is_none());
    solana_pay_kit::validate_credit_providers_for_network(
        &[solana_pay_kit::CreditProvider::Musebook],
        "devnet",
    )
    .unwrap();

    let funder = load("MUSEBOOK_DEVNET_PAYER");
    let issuer = load("MUSEBOOK_DEVNET_ISSUER");
    let owner = Keypair::new();
    let payee = Keypair::new();
    let mint_kp = Keypair::new();
    let _sweep = Sweeper::new(&funder, &[&owner, &payee]);
    let (o, p, mint) = (pk(&owner), pk(&payee), pk(&mint_kp));
    let token = v1::parse_pubkey(musebook::TOKEN_PROGRAM_ID).unwrap();
    let ata = |w: &Pubkey| v1::find_associated_token_address(w, &mint, &token).0;
    let start = net.rpc.get_balance(&funder.pubkey()).unwrap();
    println!("funder {} balance {start}", funder.pubkey());

    net.send(
        "fund throwaway owner from deployer",
        &[system_ix(
            2,
            &pk(&funder),
            &o,
            &60_000_000u64.to_le_bytes(),
            None,
        )],
        &funder,
        &[&funder],
    );
    let rent = net.rpc.get_minimum_balance_for_rent_exemption(82).unwrap();
    let mut create = rent.to_le_bytes().to_vec();
    create.extend(82u64.to_le_bytes());
    let mut init_mint = vec![20, 0];
    init_mint.extend(o.to_bytes());
    init_mint.push(0);
    net.send(
        "create SPL mint",
        &[
            system_ix(0, &o, &mint, &create, Some(&token)),
            solana_instruction::Instruction {
                program_id: v1::to_address(&token),
                accounts: vec![solana_instruction::AccountMeta::new(
                    v1::to_address(&mint),
                    false,
                )],
                data: init_mint,
            },
        ],
        &owner,
        &[&owner, &mint_kp],
    );
    let ledger = d.ledger_address(&o, &mint);
    let treasury = v1::treasury_owner_for_cluster("devnet");
    let atas: Vec<_> = [o, ledger, p, treasury]
        .iter()
        .map(|w| v1::build_create_associated_token_account_instruction(&o, w, &mint, &token))
        .collect();
    net.send(
        "create ATAs (owner, ledger vault, payee, treasury)",
        &atas,
        &owner,
        &[&owner],
    );
    net.send(
        "mint backing tokens",
        &[token_ix(
            7,
            Some(10_000),
            vec![
                (mint, true, false),
                (ata(&o), true, false),
                (o, false, true),
            ],
        )],
        &owner,
        &[&owner],
    );

    net.send(
        "pay-kit initialize_ledger (config account last)",
        &[d.initialize_ledger_instruction(&o, &mint, &pk(&issuer))],
        &owner,
        &[&owner, &issuer],
    );
    net.send(
        "pay-kit deposit 1000",
        &[d.deposit_instruction(&o, &mint, 1_000)],
        &owner,
        &[&owner],
    );
    assert_eq!(net.token_balance(&ata(&ledger)), 1_000);

    let recipients = v1::sole_recipient(&p);
    let salt = v1::random_salt();
    let open_slot = net.rpc.get_slot().unwrap();
    let cap = 1_000;
    let auth = d.authorization_for_channel(
        &p,
        &o,
        &recipients,
        salt,
        open_slot,
        cap,
        1,
        open_slot + 1_000,
    );
    net.send(
        "approve ledger refund delegate + pay-kit authorize",
        &[
            token_ix(
                4,
                Some(cap),
                vec![
                    (ata(&o), true, false),
                    (ledger, false, false),
                    (o, false, true),
                ],
            ),
            d.authorize_instruction(&o, &mint, &pk(&issuer), &auth),
        ],
        &owner,
        &[&owner, &issuer],
    );

    let params = v1::OpenChannelParams {
        payer: o,
        rent_payer: o,
        payee: p,
        mint,
        authorized_signer: o,
        salt,
        open_slot,
        deposit: 600,
        grace_period: 3_600,
        recipients: recipients.clone(),
        token_program: token,
        program_id: d.channel_program(),
    };
    let channel = v1::derive_channel_addresses(&params).channel;
    let open = d.open_channel_instructions(&params).unwrap();
    assert_eq!(open[1].data[0], 10, "OpenWithHooks");
    net.send(
        "pay-kit OpenWithHooks (400k CU, pre_fund hook)",
        &open,
        &owner,
        &[&owner],
    );
    assert!(d.is_credit_channel(&d.hooks(&o, &mint), &o, &mint));
    net.send(
        "pay-kit TopUpWithHooks 400",
        &d.top_up_instructions(&o, &channel, &mint, 400).unwrap(),
        &owner,
        &[&owner],
    );
    let escrow = ata(&channel);
    assert_eq!(net.token_balance(&escrow), 1_000);

    let msg = v1::voucher_message_bytes(&channel, 300, 0).unwrap();
    let sig: [u8; 64] = owner.sign_message(&msg).into();
    let seal = v1::build_settle_and_seal_instructions(
        &p,
        &channel,
        &o,
        Some(&sig),
        300,
        0,
        &d.channel_program(),
    )
    .unwrap();
    net.send(
        "voucher 300 + settle_and_seal",
        &seal,
        &owner,
        &[&owner, &payee],
    );
    net.send(
        "pay-kit DistributeWithHooks (post_distribute hook)",
        &d.distribute_instructions(&channel, &o, &o, &p, &treasury, &mint, &recipients)
            .unwrap(),
        &owner,
        &[&owner],
    );
    let payee_got = net.token_balance(&ata(&p));
    let treasury_got = net.token_balance(&ata(&treasury));
    assert_eq!(
        payee_got + treasury_got,
        300,
        "payee+treasury receive the settled 300"
    );
    println!(
        "payee {payee_got} treasury {treasury_got} owner_ata {}",
        net.token_balance(&ata(&o))
    );

    let end = net.rpc.get_balance(&funder.pubkey()).unwrap();
    println!("funder balance {end} (spent {})", start - end);
    println!(
        "SIGNATURES_JSON {}",
        serde_json::to_string(&net.sigs).unwrap()
    );
}

/// Session path on devnet: a `SessionServer` configured with
/// `credit_provider = Musebook` issues the challenge, the kit client builds
/// the hooked open from it, the server verifies + broadcasts it, accepts a
/// voucher, and closes; the operator then settles and distributes with the
/// server's `SealParams`. A second channel exercises the hooked
/// `WithdrawPayerWithHooks` after `request_close` and the grace period.
#[cfg(all(feature = "client", feature = "server"))]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "devnet; needs MUSEBOOK_DEVNET_PAYER and MUSEBOOK_DEVNET_ISSUER"]
async fn musebook_session_spends_credits_and_withdraws_on_devnet() {
    use solana_pay_kit::core::blockhash::BlockhashCache;
    use solana_pay_kit::core::credit_provider::CreditProvider;
    use solana_pay_kit::core::store::MemoryChannelStore;
    use solana_pay_kit::mpp::client::session::{
        build_credit_authorization_transaction, create_payment_channel_session_opener,
        derive_payment_channel_open, DerivePaymentChannelOpenParams, OpenBlockhash,
        PaymentChannelOpenOptions, PaymentChannelSessionOpenOptions, SessionOpenAuthorization,
    };
    use solana_pay_kit::mpp::protocol::intents::session::SessionAction;
    use solana_pay_kit::mpp::server::session::{
        SessionConfig, SessionOpenContext, SessionServer, VoucherSigner,
    };
    use solana_pay_kit::solana_keychain::memory::MemorySigner;

    const GRACE: u32 = 5;
    let rpc = RpcClient::new_with_commitment(
        DEVNET_RPC.to_string(),
        solana_commitment_config::CommitmentConfig::confirmed(),
    );
    let rpc = tokio::task::spawn_blocking(move || {
        assert_eq!(
            rpc.get_genesis_hash().unwrap().to_string(),
            DEVNET_GENESIS,
            "devnet only"
        );
        rpc
    })
    .await
    .unwrap();
    let mut net = Net { rpc, sigs: vec![] };
    // Blocking RPC inside the multi-thread runtime.
    macro_rules! blocking {
        ($e:expr) => {
            tokio::task::block_in_place(|| $e)
        };
    }
    let d = musebook::deployment("devnet").unwrap();
    let funder = load("MUSEBOOK_DEVNET_PAYER");
    let issuer = load("MUSEBOOK_DEVNET_ISSUER");
    let owner = Keypair::new();
    let payee = Keypair::new();
    let mint_kp = Keypair::new();
    let _sweep = Sweeper::new(&funder, &[&owner, &payee]);
    let (o, p, mint) = (pk(&owner), pk(&payee), pk(&mint_kp));
    let token = v1::parse_pubkey(musebook::TOKEN_PROGRAM_ID).unwrap();
    let ata = |w: &Pubkey| v1::find_associated_token_address(w, &mint, &token).0;
    let start = blocking!(net.rpc.get_balance(&funder.pubkey()).unwrap());
    println!("funder {} balance {start}", funder.pubkey());

    blocking!({
        net.send(
            "fund owner + payee from deployer",
            &[
                system_ix(2, &pk(&funder), &o, &60_000_000u64.to_le_bytes(), None),
                system_ix(2, &pk(&funder), &p, &5_000_000u64.to_le_bytes(), None),
            ],
            &funder,
            &[&funder],
        );
        let rent = net.rpc.get_minimum_balance_for_rent_exemption(82).unwrap();
        let mut create = rent.to_le_bytes().to_vec();
        create.extend(82u64.to_le_bytes());
        let mut init_mint = vec![20, 0];
        init_mint.extend(o.to_bytes());
        init_mint.push(0);
        net.send(
            "create SPL mint",
            &[
                system_ix(0, &o, &mint, &create, Some(&token)),
                solana_instruction::Instruction {
                    program_id: v1::to_address(&token),
                    accounts: vec![solana_instruction::AccountMeta::new(
                        v1::to_address(&mint),
                        false,
                    )],
                    data: init_mint,
                },
            ],
            &owner,
            &[&owner, &mint_kp],
        );
        let ledger = d.ledger_address(&o, &mint);
        let treasury = v1::treasury_owner_for_cluster("devnet");
        let atas: Vec<_> = [o, ledger, p, treasury]
            .iter()
            .map(|w| v1::build_create_associated_token_account_instruction(&o, w, &mint, &token))
            .collect();
        net.send("create ATAs", &atas, &owner, &[&owner]);
        net.send(
            "mint backing tokens",
            &[token_ix(
                7,
                Some(10_000),
                vec![
                    (mint, true, false),
                    (ata(&o), true, false),
                    (o, false, true),
                ],
            )],
            &owner,
            &[&owner],
        );
        net.send(
            "pay-kit initialize_ledger",
            &[d.initialize_ledger_instruction(&o, &mint, &pk(&issuer))],
            &owner,
            &[&owner, &issuer],
        );
        net.send(
            "pay-kit deposit 1500",
            &[d.deposit_instruction(&o, &mint, 1_500)],
            &owner,
            &[&owner],
        );
    });
    let ledger = d.ledger_address(&o, &mint);

    // ── Server: devnet Musebook credit session ──
    let cfg = SessionConfig {
        operator: p.to_string(),
        recipient: p.to_string(),
        amount: 100,
        suggested_deposit: Some(1_000),
        minimum_deposit: Some(100),
        currency: mint.to_string(),
        decimals: 0,
        network: "devnet".into(),
        channel_program: Some(d.channel_program()),
        channel_version: Some(2),
        credit_provider: Some(CreditProvider::Musebook),
        credit_issuer_signer: Some(std::sync::Arc::new(
            MemorySigner::from_bytes(&issuer.to_bytes()).unwrap(),
        )),
        credit_max_cap: Some(1_300),
        token_program: Some(token),
        voucher_signer: VoucherSigner::Client,
        grace_period_seconds: GRACE,
        rpc_url: Some(DEVNET_RPC.into()),
        ..SessionConfig::default()
    };
    let challenge = |server_cfg: SessionConfig, net: &Net| {
        let latest = blocking!(net
            .rpc
            .get_latest_blockhash_with_commitment(
                solana_commitment_config::CommitmentConfig::confirmed()
            )
            .unwrap());
        let slot = blocking!(net.rpc.get_slot().unwrap());
        let cache = BlockhashCache::new();
        cache.set(latest.0.to_string(), latest.1, slot);
        let server =
            SessionServer::new(server_cfg, MemoryChannelStore::new()).with_blockhash_cache(cache);
        let request = server.build_challenge_request().unwrap();
        (server, request, latest.0, slot)
    };
    let (server, request, blockhash, slot) = challenge(cfg.clone(), &net);
    assert_eq!(
        request.method_details.credit_provider,
        Some(CreditProvider::Musebook)
    );

    let payer_signer = MemorySigner::from_bytes(&owner.to_bytes()).unwrap();
    let session_key = Keypair::new();
    let authorization = SessionOpenAuthorization::client_signed(1_000);
    let salt = v1::random_salt();
    let open_options = PaymentChannelOpenOptions {
        salt: Some(salt),
        ..Default::default()
    };
    let derived = derive_payment_channel_open(DerivePaymentChannelOpenParams {
        request: &request,
        payer: o,
        authorized_signer: pk(&session_key),
        authorization: &authorization,
        options: open_options.clone(),
    })
    .unwrap();
    assert_eq!(derived.channel_hooks, Some(d.hooks(&o, &mint)));
    let authorize = |net: &mut Net,
                     open: &solana_pay_kit::mpp::client::session::PaymentChannelOpen,
                     nonce: u64,
                     label: &str| {
        let auth = d.authorization_for_channel(
            &open.payee,
            &open.authorized_signer,
            &open.recipients,
            open.salt,
            open.open_slot,
            open.deposit,
            nonce,
            open.open_slot + 1_000,
        );
        blocking!(net.send(
            label,
            &[
                token_ix(
                    4,
                    Some(open.deposit),
                    vec![
                        (ata(&o), true, false),
                        (ledger, false, false),
                        (o, false, true)
                    ],
                ),
                d.authorize_instruction(&o, &mint, &pk(&issuer), &auth),
            ],
            &owner,
            &[&owner, &issuer],
        ));
    };

    let opened = create_payment_channel_session_opener(
        &request,
        &payer_signer,
        Box::new(MemorySigner::from_bytes(&session_key.to_bytes()).unwrap()),
        OpenBlockhash::from_client_cluster(blockhash),
        &authorization,
        PaymentChannelSessionOpenOptions {
            open: open_options,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(opened.open.channel_id, derived.channel_id);
    let SessionAction::Open(open_payload) = &opened.action else {
        panic!("open action")
    };
    let blockhash_s = blockhash.to_string();
    let context = SessionOpenContext {
        challenge_id: "devnet",
        expires: None,
        recent_blockhash: &blockhash_s,
        recent_slot: slot,
    };
    // Issuer step through the session server: owner signs [Approve, authorize],
    // server checks it against its policy, co-signs as issuer and broadcasts.
    let ledger_data = blocking!(net.rpc.get_account_data(&v1::to_address(&ledger)).unwrap());
    let terms = musebook::AuthorizationTerms {
        nonce: musebook::ledger_next_nonce(&ledger_data).unwrap(),
        cap: 1_300,
        expires_at_slot: opened.open.open_slot + 1_000,
    };
    let auth_tx = build_credit_authorization_transaction(
        &request,
        &payer_signer,
        &opened.open,
        terms,
        OpenBlockhash::from_client_cluster(blockhash),
    )
    .await
    .unwrap();
    // A cap above the server's credit_max_cap is refused before signing.
    let greedy = build_credit_authorization_transaction(
        &request,
        &payer_signer,
        &opened.open,
        musebook::AuthorizationTerms {
            cap: 1_301,
            ..terms
        },
        OpenBlockhash::from_client_cluster(blockhash),
    )
    .await
    .unwrap();
    assert!(server
        .process_credit_authorization(open_payload, &greedy, context)
        .await
        .is_err());
    let sig = server
        .process_credit_authorization(open_payload, &auth_tx, context)
        .await
        .expect("server issuer co-signs + broadcasts authorize");
    println!("PASS server issuer co-sign authorize (session API): {sig}");
    net.sigs
        .push(("session issuer authorize".into(), sig.to_string()));
    let state = server
        .process_open(open_payload, context)
        .await
        .expect("server verifies + broadcasts hooked open");
    println!(
        "PASS session server process_open (OpenWithHooks via SessionServer): channel {} deposit {}",
        derived.channel_id, state.deposit
    );
    let channel = derived.channel_id;
    let escrow = ata(&channel);
    assert_eq!(blocking!(net.token_balance(&escrow)), 1_000);
    let escrow_check = escrow;

    // Top-up through the session API: client builds the hooked top-up, the
    // server verifies hooks + CU policy, broadcasts and credits the deposit.
    let mut session = opened.session;
    let topup_ix = opened.open.top_up_instruction(300).unwrap();
    let topup_hash = blocking!(net.rpc.get_latest_blockhash().unwrap());
    let mut topup_tx = solana_pay_kit::core::tx::build_unsigned(
        solana_pay_kit::core::tx::TxVersion::V0,
        &o,
        &[topup_ix],
        topup_hash,
        Some(&solana_pay_kit::core::tx::ComputeBudget::new(
            musebook::COMPUTE_UNIT_LIMIT,
            0,
        )),
    )
    .unwrap();
    solana_pay_kit::core::signing::sign_versioned_transaction_slot(&payer_signer, &mut topup_tx)
        .await
        .unwrap();
    let topup_b64 = solana_pay_kit::core::tx::encode(&topup_tx).unwrap();
    let SessionAction::TopUp(topup) = session.topup_action(300, &topup_b64) else {
        panic!("topup")
    };
    let after_topup = server.process_topup(&topup).await.expect("server top-up");
    println!(
        "PASS session process_topup 300 (TopUpWithHooks via SessionServer): deposit {}",
        after_topup.deposit
    );
    net.sigs
        .push(("session top-up".into(), topup_tx.signatures[0].to_string()));
    assert_eq!(after_topup.deposit, 1_300);
    let SessionAction::Voucher(voucher) = session.voucher_action(200).await.unwrap() else {
        panic!("voucher")
    };
    server
        .verify_voucher(&voucher)
        .await
        .expect("server accepts credit voucher");
    println!("PASS session voucher 200 accepted");
    let SessionAction::Close(close) = session.close_action(Some(100)).await.unwrap() else {
        panic!("close")
    };
    assert_eq!(blocking!(net.token_balance(&escrow_check)), 1_300);
    let seal = server.process_close(&close).await.expect("server close");
    assert_eq!(seal.settled, 300);
    assert_eq!(seal.channel_hooks, Some(d.hooks(&o, &mint)));
    let treasury = v1::treasury_owner_for_cluster("devnet");
    blocking!({
        net.send(
            "operator settle_and_seal from SealParams",
            &seal.settle_instructions(&p).unwrap(),
            &payee,
            &[&payee],
        );
        let recipients: Vec<_> = seal
            .splits
            .iter()
            .map(|s| v1::Distribution {
                recipient: s.recipient,
                bps: s.bps,
            })
            .collect();
        net.send(
            "DistributeWithHooks for session channel",
            &d.distribute_instructions(&channel, &o, &o, &p, &treasury, &mint, &recipients)
                .unwrap(),
            &payee,
            &[&payee],
        );
    });
    let payee_got = blocking!(net.token_balance(&ata(&p)));
    let treasury_got = blocking!(net.token_balance(&ata(&treasury)));
    assert_eq!(payee_got + treasury_got, 300);
    println!("payee {payee_got} treasury {treasury_got}");

    // ── Second channel: hooked withdraw after request_close + grace ──
    let (_server2, request2, _, _) = challenge(cfg.clone(), &net);
    let salt2 = v1::random_salt();
    let mut open2 = derive_payment_channel_open(DerivePaymentChannelOpenParams {
        request: &request2,
        payer: o,
        authorized_signer: o,
        authorization: &SessionOpenAuthorization::client_signed(200),
        options: PaymentChannelOpenOptions {
            salt: Some(salt2),
            ..Default::default()
        },
    })
    .unwrap();
    open2.deposit = 200;
    authorize(
        &mut net,
        &open2,
        2,
        "approve + issuer authorize withdraw channel",
    );
    let params = v1::OpenChannelParams {
        payer: o,
        rent_payer: o,
        payee: open2.payee,
        mint,
        authorized_signer: o,
        salt: salt2,
        open_slot: open2.open_slot,
        deposit: 200,
        grace_period: GRACE,
        recipients: open2.recipients.clone(),
        token_program: token,
        program_id: d.channel_program(),
    };
    let channel2 = v1::derive_channel_addresses(&params).channel;
    assert_eq!(channel2, open2.channel_id);
    let owner_before = blocking!(net.token_balance(&ata(&o)));
    blocking!({
        net.send(
            "OpenWithHooks withdraw channel (200)",
            &d.open_channel_instructions(&params).unwrap(),
            &owner,
            &[&owner],
        );
        net.send(
            "request_close",
            &[v1::build_request_close_instruction(
                &o,
                &channel2,
                &d.channel_program(),
            )],
            &owner,
            &[&owner],
        );
    });
    tokio::time::sleep(std::time::Duration::from_secs(u64::from(GRACE) + 10)).await;
    // After the grace period anyone may seal; withdrawPayer requires SEALED.
    let mut sealed = false;
    for attempt in 0..6 {
        let result = blocking!({
            let hash = net.rpc.get_latest_blockhash().unwrap();
            let tx = Transaction::new_signed_with_payer(
                &[v1::build_seal_instruction(&channel2, &d.channel_program())],
                Some(&owner.pubkey()),
                &[&owner],
                hash,
            );
            send_and_confirm_transaction(&net.rpc, &VersionedTransaction::from(tx))
        });
        match result {
            Ok(sig) => {
                println!("PASS permissionless seal after grace: {sig}");
                net.sigs.push(("seal after grace".into(), sig.to_string()));
                sealed = true;
                break;
            }
            Err(e) => {
                println!("seal attempt {attempt} not yet: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    }
    assert!(sealed, "grace-period seal landed");
    let mut withdrew = false;
    for attempt in 0..3 {
        let result = blocking!({
            let hash = net.rpc.get_latest_blockhash().unwrap();
            let tx = Transaction::new_signed_with_payer(
                &d.withdraw_payer_instructions(&o, &channel2, &mint).unwrap(),
                Some(&owner.pubkey()),
                &[&owner],
                hash,
            );
            send_and_confirm_transaction(&net.rpc, &VersionedTransaction::from(tx))
        });
        match result {
            Ok(sig) => {
                println!("PASS WithdrawPayerWithHooks after grace: {sig}");
                net.sigs
                    .push(("WithdrawPayerWithHooks".into(), sig.to_string()));
                withdrew = true;
                break;
            }
            Err(e) => {
                println!("withdraw attempt {attempt} not yet: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        }
    }
    assert!(withdrew, "hooked withdraw landed");
    let owner_after = blocking!(net.token_balance(&ata(&o)));
    println!(
        "owner ATA before open2 {owner_before} after withdraw {owner_after}; ledger vault {}",
        blocking!(net.token_balance(&ata(&ledger)))
    );
    assert_eq!(
        blocking!(net.token_balance(&ata(&channel2))),
        0,
        "withdraw emptied the escrow"
    );

    println!(
        "SIGNATURES_JSON {}",
        serde_json::to_string(&net.sigs).unwrap()
    );
    drop(_sweep);
    let end = blocking!(net.rpc.get_balance(&funder.pubkey()).unwrap());
    println!("funder balance after sweep {end} (spent {})", start - end);
    println!(
        "SIGNATURES_JSON {}",
        serde_json::to_string(&net.sigs).unwrap()
    );
}
