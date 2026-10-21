//! Structural settlement assertions, ported from `harness/test/e2e.test.ts`:
//! the settled transaction is fetched from the validator and must carry the
//! expected `transferChecked` set (or System transfer), split amounts,
//! idempotent ATA creations, memos, no extra transfers, no lookup tables,
//! and for x402 `upto` the payment-channel `settle_and_seal` + `distribute`
//! shape.

use base64::Engine;
use serde_json::Value;
use solana_message::compiled_instruction::CompiledInstruction;
use solana_message::VersionedMessage;

use crate::keys::{ATA_PROGRAM, MEMO_PROGRAM, SYSTEM_PROGRAM};

use super::chain::{Accounts, PAYMENT_CHANNELS_PROGRAM, PAYMENT_CHANNEL_TREASURY_OWNER};
use super::claims::Intent;
use super::scenarios::{Asset, Scenario};

const ED25519_PROGRAM: &str = "Ed25519SigVerify111111111111111111111111111";

pub struct Message {
    keys: Vec<String>,
    msg: VersionedMessage,
}

impl Message {
    fn account(&self, index: u8) -> &str {
        self.keys
            .get(index as usize)
            .map(String::as_str)
            .unwrap_or("<out of range>")
    }

    fn program(&self, ix: &CompiledInstruction) -> &str {
        self.account(ix.program_id_index)
    }

    fn acc(&self, ix: &CompiledInstruction, n: usize) -> &str {
        ix.accounts
            .get(n)
            .map(|i| self.account(*i))
            .unwrap_or("<missing>")
    }

    fn instructions(&self) -> &[CompiledInstruction] {
        self.msg.instructions()
    }

    pub fn describe(&self) -> String {
        self.instructions()
            .iter()
            .enumerate()
            .map(|(i, ix)| {
                format!(
                    "  #{i} {} accounts=[{}] data={}",
                    self.program(ix),
                    ix.accounts
                        .iter()
                        .map(|a| self.account(*a).to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                    ix.data
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Decode `getTransaction` (base64 encoding) and require `meta.err == null`.
pub fn decode(result: &Value) -> Result<Message, String> {
    if !result["meta"]["err"].is_null() {
        return Err(format!(
            "settled transaction failed on chain: {}",
            result["meta"]["err"]
        ));
    }
    let b64 = result["transaction"][0]
        .as_str()
        .ok_or("getTransaction returned no base64 transaction")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| e.to_string())?;
    let tx = solana_pay_kit::core::tx::decode_bytes(&bytes).map_err(|e| e.to_string())?;
    Ok(Message {
        keys: tx
            .message
            .static_account_keys()
            .iter()
            .map(ToString::to_string)
            .collect(),
        msg: tx.message,
    })
}

fn u64_le(data: &[u8], at: usize) -> Option<u64> {
    data.get(at..at + 8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
}

fn u16_le(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at + 2)
        .map(|b| u16::from_le_bytes(b.try_into().expect("2 bytes")))
}

fn ata(owner: &str, mint: &str, program: &str) -> String {
    crate::keys::ata(owner, mint, program).to_string()
}

struct Checker<'a> {
    m: &'a Message,
    problems: Vec<String>,
}

impl Checker<'_> {
    fn check(&mut self, ok: bool, what: impl FnOnce() -> String) {
        if !ok {
            self.problems.push(what());
        }
    }

    fn transfer_checked(
        &mut self,
        used: &mut Vec<usize>,
        destination: &str,
        mint: &str,
        amount: u64,
        decimals: u8,
        program: &str,
    ) {
        let found = self
            .m
            .instructions()
            .iter()
            .enumerate()
            .position(|(i, ix)| {
                !used.contains(&i)
                    && self.m.program(ix) == program
                    && ix.data.first() == Some(&12)
                    && ix.accounts.len() >= 4
                    && self.m.acc(ix, 1) == mint
                    && self.m.acc(ix, 2) == destination
                    && u64_le(&ix.data, 1) == Some(amount)
                    && ix.data.get(9) == Some(&decimals)
            });
        match found {
            Some(i) => used.push(i),
            None => self.problems.push(format!(
                "missing transferChecked mint={mint} destination={destination} amount={amount} decimals={decimals}"
            )),
        }
    }

    fn idempotent_ata(&mut self, ata: &str, owner: &str, mint: &str, program: &str) {
        let found = self.m.instructions().iter().any(|ix| {
            self.m.program(ix) == ATA_PROGRAM
                && ix.data.first() == Some(&1)
                && self.ata_accounts_match(ix, ata, owner, mint, program)
        });
        self.check(found, || {
            format!("missing idempotent ATA creation ata={ata} owner={owner} mint={mint}")
        });
    }

    fn ata_accounts_match(
        &self,
        ix: &CompiledInstruction,
        ata: &str,
        owner: &str,
        mint: &str,
        program: &str,
    ) -> bool {
        self.m.acc(ix, 1) == ata
            && self.m.acc(ix, 2) == owner
            && self.m.acc(ix, 3) == mint
            && self.m.acc(ix, 4) == SYSTEM_PROGRAM
            && self.m.acc(ix, 5) == program
    }

    fn memo(&mut self, memo: &str) {
        let found = self
            .m
            .instructions()
            .iter()
            .any(|ix| self.m.program(ix) == MEMO_PROGRAM && ix.data == memo.as_bytes());
        self.check(found, || format!("missing memo instruction {memo:?}"));
    }
}

/// Assert the settled transaction's structure for `scenario`.
pub fn assert_shape(scenario: &Scenario, acc: &Accounts, m: &Message) -> Result<(), String> {
    let mut c = Checker {
        m,
        problems: Vec::new(),
    };
    if let VersionedMessage::V0(v0) = &m.msg {
        c.check(v0.address_table_lookups.is_empty(), || {
            "settled transaction uses address lookup tables".into()
        });
    }
    if scenario.intent == Intent::X402Upto {
        upto_shape(&mut c, scenario, acc);
    } else if scenario.asset == Asset::Sol {
        let amount = scenario.primary_delta();
        let found = m.instructions().iter().any(|ix| {
            m.program(ix) == SYSTEM_PROGRAM
                && ix.data.len() >= 12
                && ix.data[..4] == 2u32.to_le_bytes()
                && m.acc(ix, 1) == acc.pay_to.pubkey
                && u64_le(&ix.data, 4) == Some(amount)
        });
        c.check(found, || {
            format!(
                "missing system transfer destination={} amount={amount}",
                acc.pay_to.pubkey
            )
        });
    } else {
        let mint = acc.mint.as_deref().ok_or("SPL scenario without a mint")?;
        let program = acc
            .token_program
            .ok_or("SPL scenario without a token program")?;
        let mut used = Vec::new();
        c.transfer_checked(
            &mut used,
            &ata(&acc.pay_to.pubkey, mint, program),
            mint,
            scenario.primary_delta(),
            acc.decimals,
            program,
        );
        for split in scenario.splits {
            let destination = ata(&acc.platform.pubkey, mint, program);
            c.transfer_checked(
                &mut used,
                &destination,
                mint,
                split.amount.parse().expect("split amount"),
                acc.decimals,
                program,
            );
            if split.ata_creation_required == Some(true) {
                c.idempotent_ata(&destination, &acc.platform.pubkey, mint, program);
            }
            if let Some(memo) = split.memo {
                c.memo(memo);
            }
        }
        let transfers = m
            .instructions()
            .iter()
            .filter(|ix| {
                m.program(ix) == program
                    && ix.data.first() == Some(&12)
                    && ix.accounts.len() >= 4
                    && m.acc(ix, 1) == mint
            })
            .count();
        let expected = 1 + scenario.splits.len();
        c.check(transfers == expected, || {
            format!("unexpected transferChecked count for mint {mint}: {transfers}, expected {expected}")
        });
    }
    if c.problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{}\nsettled instructions:\n{}",
            c.problems.join("\n"),
            m.describe()
        ))
    }
}

fn upto_shape(c: &mut Checker<'_>, scenario: &Scenario, acc: &Accounts) {
    let m = c.m;
    let actual = scenario.primary_delta();
    let ixs = m.instructions();
    let expected_len = if actual == 0 { 5 } else { 6 };
    if ixs.len() != expected_len {
        c.problems.push(format!(
            "x402-upto settlement has {} instructions, expected {expected_len}",
            ixs.len()
        ));
        return;
    }
    let (settle, create_payee, create_treasury, create_recipient, distribute) = if actual == 0 {
        (&ixs[0], &ixs[1], &ixs[2], &ixs[3], &ixs[4])
    } else {
        let verify = &ixs[0];
        c.check(m.program(verify) == ED25519_PROGRAM, || {
            "first instruction is not an Ed25519 verify".into()
        });
        c.check(verify.data.first() == Some(&1), || {
            "Ed25519 signature count != 1".into()
        });
        c.check(u16_le(&verify.data, 10) == Some(112), || {
            "voucher message offset != 112".into()
        });
        c.check(u16_le(&verify.data, 12) == Some(50), || {
            "voucher message length != 50".into()
        });
        c.check(verify.data.get(112) == Some(&0x56), || {
            "voucher magic tag != 0x56".into()
        });
        c.check(verify.data.get(113) == Some(&0x01), || {
            "voucher magic version != 0x01".into()
        });
        c.check(u64_le(&verify.data, 112 + 2 + 32) == Some(actual), || {
            format!("voucher cumulative amount != {actual}")
        });
        (&ixs[1], &ixs[2], &ixs[3], &ixs[4], &ixs[5])
    };
    c.check(m.program(settle) == PAYMENT_CHANNELS_PROGRAM, || {
        "settle_and_seal is not a payment-channels instruction".into()
    });
    c.check(settle.data.first() == Some(&4), || {
        "settle_and_seal discriminator != 4".into()
    });
    c.check(settle.data.get(1) == Some(&u8::from(actual != 0)), || {
        "settle_and_seal hasVoucher flag is wrong".into()
    });
    let (Some(mint), Some(program)) = (acc.mint.as_deref(), acc.token_program) else {
        c.problems
            .push("x402-upto scenario without an SPL mint".into());
        return;
    };
    // The fee payer holds the zero-share payee seat and doubles as payTo in
    // the harness, so the payee and recipient ATAs coincide.
    let pay_to = acc.upto_pay_to.pubkey.as_str();
    let recipient_ata = ata(pay_to, mint, program);
    let treasury_ata = ata(PAYMENT_CHANNEL_TREASURY_OWNER, mint, program);
    for (ix, owner, ata_addr, what) in [
        (create_payee, pay_to, recipient_ata.as_str(), "payee"),
        (
            create_treasury,
            PAYMENT_CHANNEL_TREASURY_OWNER,
            treasury_ata.as_str(),
            "treasury",
        ),
        (
            create_recipient,
            pay_to,
            recipient_ata.as_str(),
            "recipient",
        ),
    ] {
        let ok = m.program(ix) == ATA_PROGRAM
            && ix.data.first() == Some(&1)
            && c.ata_accounts_match(ix, ata_addr, owner, mint, program);
        c.check(ok, || {
            format!("{what} ATA creation is not an idempotent create of {ata_addr}")
        });
    }
    c.check(m.program(distribute) == PAYMENT_CHANNELS_PROGRAM, || {
        "distribute is not a payment-channels instruction".into()
    });
    c.check(distribute.data.first() == Some(&7), || {
        "distribute discriminator != 7".into()
    });
    c.check(distribute.accounts.len() == 12, || {
        format!(
            "distribute has {} accounts, expected 12",
            distribute.accounts.len()
        )
    });
    if distribute.accounts.len() == 12 {
        c.check(m.acc(settle, 1) == m.acc(distribute, 0), || {
            "settled channel differs from distributed channel".into()
        });
        c.check(m.acc(distribute, 5) == recipient_ata, || {
            "distribute payee ATA".into()
        });
        c.check(m.acc(distribute, 6) == treasury_ata, || {
            "distribute treasury ATA".into()
        });
        c.check(m.acc(distribute, 7) == mint, || "distribute mint".into());
        c.check(m.acc(distribute, 8) == program, || {
            "distribute token program".into()
        });
        c.check(m.acc(distribute, 10) == PAYMENT_CHANNELS_PROGRAM, || {
            "distribute self program".into()
        });
        c.check(m.acc(distribute, 11) == recipient_ata, || {
            "distribute payTo recipient ATA".into()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::chain::Key;
    use crate::interop::scenarios::find;
    use crate::keys;
    use crate::mutate::Mutation;
    use crate::tx::{encode_b64, x402_static_layout, StaticLayout};
    use serde_json::json;
    use solana_transaction::versioned::VersionedTransaction;

    fn key(pubkey: &str) -> Key {
        Key {
            seed: [0; 32],
            bytes: [0; 64],
            pubkey: pubkey.into(),
        }
    }

    fn accounts() -> Accounts {
        Accounts {
            client: key(keys::CLIENT),
            pay_to: key(keys::X402_PAY_TO),
            platform: key(keys::SPLIT_RECIPIENT),
            fee_payer: key(keys::X402_SERVER_FEE_PAYER),
            upto_pay_to: key(keys::X402_OTHER_PAY_TO),
            attacker: key(keys::X402_OTHER_PAY_TO),
            mint: Some(keys::MINT.into()),
            wire_currency: keys::MINT.into(),
            token_program: Some(keys::TOKEN_PROGRAM),
            decimals: 6,
        }
    }

    fn settled_tx() -> VersionedTransaction {
        x402_static_layout(&StaticLayout {
            fee_payer: keys::X402_SERVER_FEE_PAYER,
            mint: keys::MINT,
            pay_to: keys::X402_PAY_TO,
            amount: 1000,
            decimals: 6,
            memo: "0123456789abcdef0123456789abcdef",
        })
        .unwrap()
    }

    fn result(tx: &VersionedTransaction, err: Value) -> Value {
        json!({"meta": {"err": err}, "transaction": [encode_b64(tx).unwrap(), "base64"]})
    }

    fn check(tx: &VersionedTransaction) -> Result<(), String> {
        let m = decode(&result(tx, Value::Null))?;
        assert_shape(find("charge-basic").unwrap(), &accounts(), &m)
    }

    #[test]
    fn the_expected_settlement_passes_positive_control() {
        check(&settled_tx()).unwrap();
    }

    #[test]
    fn an_extra_transfer_fails() {
        let tx = Mutation::ExtraTransfer { transfer: 0 }
            .apply(&settled_tx(), &[keys::CLIENT_SEED])
            .unwrap();
        let err = check(&tx).unwrap_err();
        assert!(err.contains("unexpected transferChecked count"), "{err}");
    }

    #[test]
    fn a_short_transfer_fails() {
        let tx = Mutation::BumpAmount {
            transfer: 0,
            delta: -1,
        }
        .apply(&settled_tx(), &[keys::CLIENT_SEED])
        .unwrap();
        let err = check(&tx).unwrap_err();
        assert!(err.contains("missing transferChecked"), "{err}");
    }

    #[test]
    fn a_transfer_to_another_recipient_fails() {
        let tx = Mutation::SwapRecipient {
            transfer: 0,
            owner: keys::X402_OTHER_PAY_TO,
        }
        .apply(&settled_tx(), &[keys::CLIENT_SEED])
        .unwrap();
        assert!(check(&tx).is_err());
    }

    #[test]
    fn a_transaction_that_failed_on_chain_fails() {
        let err = decode(&result(
            &settled_tx(),
            json!({"InstructionError": [2, "InvalidAccountData"]}),
        ))
        .err()
        .unwrap();
        assert!(err.contains("failed on chain"), "{err}");
    }

    #[test]
    fn a_missing_split_ata_creation_fails() {
        // charge-split-ata expects a 750 + 250 split with an idempotent ATA
        // creation; the single 1000 transfer satisfies neither.
        let m = decode(&result(&settled_tx(), Value::Null)).unwrap();
        let err = assert_shape(find("charge-split-ata").unwrap(), &accounts(), &m).unwrap_err();
        assert!(err.contains("idempotent ATA creation"), "{err}");
        assert!(err.contains("memo"), "{err}");
    }
}
