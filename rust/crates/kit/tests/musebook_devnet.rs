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
