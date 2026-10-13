//! Real SBF -> SBF hook execution through the client and server RPC contract.
use super::*;
use solana_account::Account;

/// Snapshots surround one isolated SVM execution, exactly as an RPC bank does.
/// Successful payouts are never synthesized from intended instructions.
pub(super) fn token_snapshot(
    svm: &litesvm::LiteSVM,
    tx: &VersionedTransaction,
) -> Vec<serde_json::Value> {
    let token = key(crate::mpp::protocol::solana::programs::TOKEN_PROGRAM).unwrap();
    tx.message.static_account_keys().iter().enumerate().filter_map(|(index, key)| {
        let account = svm.get_account(key)?;
        if account.owner != token || account.data.len() != 165 { return None; }
        Some(serde_json::json!({
            "accountIndex":index,
            "mint":Pubkey::new_from_array(account.data[0..32].try_into().unwrap()).to_string(),
            "owner":Pubkey::new_from_array(account.data[32..64].try_into().unwrap()).to_string(),
            "programId":token.to_string(),
            "uiTokenAmount":{"amount":u64::from_le_bytes(account.data[64..72].try_into().unwrap()).to_string(),"decimals":6}
        }))
    }).collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires devnet PAYMENT_CHANNELS_V2_SO and CHANNEL_HOOK_TEST_ADAPTER_SO built as SBF v3"]
async fn channel_charge_sbf_atomic_workflow_and_rollback() {
    let program = key(v2::PAYMENT_CHANNELS_PROGRAM_ID).unwrap();
    let adapter = Pubkey::new_from_array([77; 32]);
    let recorder = Pubkey::new_from_array([78; 32]);
    let token = key(crate::mpp::protocol::solana::programs::TOKEN_PROGRAM).unwrap();
    let mint = key(MINT).unwrap();
    let payer = signer(1);
    let merchant = signer(3);
    let sponsor = signer(4);
    let ata = |owner: &Pubkey| v1::find_associated_token_address(owner, &mint, &token).0;
    let hooks = v2::ChannelHooks {
        pre_fund: Some(v2::HookDescriptor {
            program_id: adapter.to_string(),
            entrypoint: *b"record!!",
            accounts: vec![v2::HookAccount {
                address: recorder.to_string(),
                writable: true,
            }],
            static_data: vec![],
        }),
        post_distribute: Some(v2::HookDescriptor {
            program_id: adapter.to_string(),
            entrypoint: *b"record!!",
            accounts: vec![v2::HookAccount {
                address: recorder.to_string(),
                writable: true,
            }],
            static_data: vec![],
        }),
        ..Default::default()
    };
    for scenario in ["success", "post-hook-failure", "frozen-recipient"] {
        let mut svm = litesvm::LiteSVM::new();
        svm.warp_to_slot(42);
        for (program, env) in [
            (program, "PAYMENT_CHANNELS_V2_SO"),
            (adapter, "CHANNEL_HOOK_TEST_ADAPTER_SO"),
        ] {
            let bytes =
                std::fs::read(std::env::var(env).expect("SBF fixture path required")).unwrap();
            assert_eq!(
                u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
                3,
                "SBF v3 required"
            );
            svm.add_program(program, &bytes).unwrap();
        }
        svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
        svm.airdrop(&sponsor.pubkey(), 10_000_000_000).unwrap();
        let mut mint_data = vec![0; 82];
        mint_data[36..44].copy_from_slice(&10_000_000_u64.to_le_bytes());
        mint_data[44] = 6;
        mint_data[45] = 1;
        svm.set_account(
            mint,
            Account {
                lamports: 10_000_000,
                data: mint_data,
                owner: token,
                ..Default::default()
            },
        )
        .unwrap();
        for (owner, amount) in [
            (payer.pubkey(), 10_000_000_u64),
            (merchant.pubkey(), 7),
            (sponsor.pubkey(), 0),
            (v1::treasury_owner_for_cluster("devnet"), 0),
        ] {
            let mut data = vec![0; 165];
            data[..32].copy_from_slice(mint.as_ref());
            data[32..64].copy_from_slice(owner.as_ref());
            data[64..72].copy_from_slice(&amount.to_le_bytes());
            data[108] = if scenario == "frozen-recipient" && owner == merchant.pubkey() {
                2
            } else {
                1
            };
            svm.set_account(
                ata(&owner),
                Account {
                    lamports: 10_000_000,
                    data,
                    owner: token,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let mut record_data = vec![0; 8 + 428 * 16];
        if scenario == "post-hook-failure" {
            record_data[0] = 4;
        }
        svm.set_account(
            recorder,
            Account {
                lamports: 100_000_000,
                data: record_data.clone(),
                owner: adapter,
                ..Default::default()
            },
        )
        .unwrap();
        let blockhash = svm.latest_blockhash();
        let state = Arc::new(std::sync::Mutex::new(WorkflowState {
            svm: Some(svm),
            ..Default::default()
        }));
        let mut server = workflow_server(state.clone());
        server.network = "devnet".into();
        server.accepted_versions = vec![tx::TxVersion::V0, tx::TxVersion::V1];
        server.channel_charge.as_mut().unwrap().hooks = hooks.clone();
        if scenario != "success" {
            forbid_server_signing(&mut server);
        }
        let mut expected = request(hooks.clone(), true);
        let details = expected.method_details.as_mut().unwrap();
        details["network"] = serde_json::json!("devnet");
        details["transactionVersions"] = serde_json::json!([0, 1]);
        details["recentBlockhash"] = serde_json::json!(blockhash.to_string());
        let challenge = server.charge_challenge(&expected).unwrap();
        let credential = build_channel_charge_credential(
            payer.as_ref(),
            signer(2).as_ref(),
            &challenge,
            &hooks,
            99,
        )
        .await
        .unwrap();
        let CredentialPayload::Transaction { transaction } =
            serde_json::from_value(credential.payload.clone()).unwrap()
        else {
            panic!("transaction credential required")
        };
        let transaction = tx::decode(&transaction).unwrap();
        let accounts_before: Vec<_> = {
            let state = state.lock().unwrap();
            let svm = state.svm.as_ref().unwrap();
            transaction
                .message
                .static_account_keys()
                .iter()
                .map(|key| (*key, svm.get_account(key)))
                .collect()
        };
        let result = server.verify(&credential, &expected).await;
        if scenario == "success" {
            result.unwrap();
            assert!(server.verify(&credential, &expected).await.is_err());
        } else {
            let error = result.unwrap_err();
            let reason = if scenario == "post-hook-failure" {
                "execution failed"
            } else {
                "recipient net credit mismatch"
            };
            assert!(error.message.contains(reason), "{scenario}: {error:?}");
        }
        let state = state.lock().unwrap();
        assert_eq!(state.simulations, 1, "{scenario}");
        let meta = state.simulated_meta.as_ref().unwrap();
        if scenario == "post-hook-failure" {
            assert_eq!(meta["err"], "InstructionError(3, Custom(703))");
        } else {
            assert!(meta["err"].is_null(), "{scenario}: {meta}");
        }
        if scenario == "frozen-recipient" {
            // Frozen beneficiaries are redirected by the program, not execution
            // failures. The server must reject this successful bank execution
            // because the merchant did not receive the authenticated net credit.
            let treasury = v1::treasury_owner_for_cluster("devnet").to_string();
            let balance = |field: &str| {
                meta[field]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["owner"].as_str() == Some(treasury.as_str()))
                    .unwrap()["uiTokenAmount"]["amount"]
                    .as_str()
                    .unwrap()
                    .parse::<u64>()
                    .unwrap()
            };
            assert_eq!(
                balance("postTokenBalances") - balance("preTokenBalances"),
                1_000_000
            );
        }
        let svm = state.svm.as_ref().unwrap();
        let amount = |owner: &Pubkey| -> u64 {
            let data = svm.get_account(&ata(owner)).unwrap().data;
            u64::from_le_bytes(data[64..72].try_into().unwrap())
        };
        assert_eq!(
            amount(&merchant.pubkey()),
            if scenario == "success" { 1_000_007 } else { 7 }
        );
        assert_eq!(
            amount(&payer.pubkey()),
            if scenario == "success" {
                9_000_000
            } else {
                10_000_000
            }
        );
        assert_eq!(amount(&v1::treasury_owner_for_cluster("devnet")), 0);
        if scenario == "success" {
            assert_eq!(state.sends, 1);
            assert_eq!(svm.get_account(&recorder).unwrap().data[1], 2);
        } else {
            assert_eq!(state.sends, 0);
            assert!(state.sent.is_none());
            assert_eq!(svm.get_account(&recorder).unwrap().data, record_data);
            for (key, before) in accounts_before {
                assert_eq!(svm.get_account(&key), before, "{scenario}: {key}");
            }
        }
    }
}
