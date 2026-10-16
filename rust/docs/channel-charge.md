# Atomic V2 channel charges

Use this opt-in profile when an MPP charge needs reviewed payment-channel callbacks. Ordinary `charge_with_options` and direct-transfer client builders keep their existing behavior.

## Configure and issue a challenge

Set `server::Config.channel_charge` to `Some(ChannelChargeConfig { payee_signer, hooks })`. The signer must implement `TransactionSigner`:

- Sponsored: use the existing fee-payer signer. The channel payee is `feePayerKey`, not the merchant's receiving wallet. Its economic share is zero when it differs from the recipient.
- Unsponsored: provide the recipient's transaction signer. The client pays fees and rent.

Call `Mpp::charge_channel_with_options(amount, options)` instead of `charge_with_options`. This issues the first 402 without knowing the payer or voucher key. It reuses a paired blockhash/slot cache entry, or fetches both from one `getLatestBlockhash` response.

The profile adds one method-details field:

```json
{
  "channelCharge": {
    "channelProgram": "CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ",
    "channelVersion": 2,
    "channelHooks": {},
    "recentSlot": 42
  }
}
```

`recentSlot` is an example; use the observed RPC slot. Existing network, token program, fee-payer, recent blockhash, transaction-version and pricing fields still apply.

## Build and verify

After approving the amount, network, recipient and callback policy, call:

```text
client::build_channel_charge_credential_with_options(
    payer,
    voucher_signer,
    challenge,
    expected_hooks,
    salt,
    max_tx_version,
)
```

`expected_hooks` is your trusted configuration, not a copy of an untrusted challenge. The client checks it and the packet size before requesting signatures. The client chooses its payer, voucher key and salt; the server derives those values from the payer-signed transaction.

The returned `PaymentCredential` uses the existing transaction payload and authorization-header formatter. It contains a real payer signature and leaves the required payee/sponsor slot unsigned. The canonical transaction has exactly five instructions:

1. V2 `open`, including configured pre-funding callbacks.
2. Ed25519 verification of the exact voucher.
3. Payee-authorized `settleAndSeal`.
4. V2 `distribute`, including configured distribution callbacks.
5. Memo `mpp-charge:<challenge.id>`.

The voucher and deposit equal the request's **total** amount. The primary recipient receives `amount - sum(splits)`. Splits must be exactly representable in basis points; the builder rejects rounding rather than paying dust to treasury. The fixed grace period is one second; cooperative `settleAndSeal` does not wait for it.

Call the existing `Mpp::verify` or `verify_credential_with_expected`. Build expected prices, recipient, splits and callback policy from your route. A fresh expectation may have a different slot/blockhash: verification authenticates the original challenge and uses its original context for exact message reconstruction.

The verifier checks the payer and voucher signatures locally, simulates before requesting any server signature, and requires exact beneficiary **net credits** in that execution's token-balance snapshots. After co-signing and broadcast, it requires the exact submitted message/signatures and successful confirmed metadata with the same net-credit proof before returning a receipt. A successful channel instruction alone is insufficient: the channel can redirect invalid beneficiary accounts to treasury.

## Supported scope

- Original SPL Token only; use a mint address, not a symbol.
- Positive total and primary amounts; no duplicate beneficiaries, zero splits, split memos or requested beneficiary-ATA creation.
- Beneficiary ATAs must already exist. The channel instruction creates its own escrow ATA.
- V0 defaults remain unchanged. Enable the existing V1 server capability when needed and pass the client's supported version cap. A minimal sponsored two-hook charge exceeds V0's 1,232-byte limit; V1 is still explicitly gated. Address lookup tables are not accepted.
- `externalId` is bound by the authenticated challenge-ID memo; this profile does not add a separate external-ID memo.
- Callback programs, account permissions and data must match explicit client and server configuration. This is not a provider registry or a Coinflow-specific ABI.
- The outcome rule proves final net credits. It does not claim that callbacks made no intermediate token movements.

RPC providers must return `preTokenBalances` and `postTokenBalances` from the **same simulation execution**, and complete confirmed transaction metadata. Missing evidence fails closed. Separate account reads are not substituted.

## Recovery and rent

Use a durable `Store` in production. The existing `put_if_absent` contract must be atomic. Channel charges write an immutable submission marker containing the original credential transaction and fully signed bytes before broadcast, then claim a receipt atomically after outcome verification.

Retry the same credential after a pending outcome. The server checks the recorded transaction; if necessary, it can resend only the exact stored signed bytes while the challenge remains valid. It never refreshes the blockhash, signs a replacement, or treats missing confirmation evidence as a new payment authorization. After HTTP expiry, retries may reconcile an already-landed transaction but cannot start or resend an execution.

Persist the challenge ID and call `Mpp::channel_charge_settlement(challenge_id)` to obtain `ChannelChargeSettlement`: channel, program/version, rent payer, opening slot and signature. This is operational metadata, not payment proof.

The atomic charge closes the escrow ATA, but leaves the 1,121-byte channel account in `Distributed` state until `current_slot > open_slot + 1500`. **Schedule permissionless channel reclaim after that window to return its rent to `rent_payer`.** The SDK does not run a background reclaim worker. Do not invent a session authorization to perform this cleanup.

Keep submitted and receipt markers through your reconciliation/retention window. Do not delete a pending marker to make a payment retryable.

## Offline runtime test

Build the payment-channels V2 program with its `devnet` treasury configuration and the test-only hook adapter as SBF v3. No deployed funds are needed. From `rust/`, supply their paths:

```sh
PAYMENT_CHANNELS_V2_SO=/path/to/devnet/payment_channels.so \
CHANNEL_HOOK_TEST_ADAPTER_SO=/path/to/hook_test_adapter.so \
cargo test -p solana-pay-kit --features client,server --lib \
  channel_charge_sbf_atomic_workflow_and_rollback -- --ignored
```

The test exercises real Ed25519 verification, open, settle-and-seal, distribution and both callback CPIs. It checks merchant credit, sponsor co-signing, receipt replay, post-hook rollback and frozen-recipient rejection.
