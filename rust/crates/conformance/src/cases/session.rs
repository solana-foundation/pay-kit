//! Session cases: voucher preimage bytes, wire round trips, voucher verify.

use serde_json::json;

use crate::case::{
    spec, BugType, CaseBuilder, Expect, Input, Intent, Mode, Pin, RejectCode, Role, SpecRef, Suite,
};

const SESSION: &str = "mpp-specs/specs/methods/solana/draft-solana-session-00.md";

fn layout_spec() -> SpecRef {
    spec(
        SESSION,
        "Voucher Signing",
        "The signed voucher payload is 50 bytes in fixed Borsh layout:",
    )
}

fn verify_spec() -> SpecRef {
    spec(SESSION, "Voucher Verification", "If expiresAt is present and non-zero, verify now < expiresAt (with configurable clock skew tolerance).")
}

fn wire_request_spec() -> SpecRef {
    spec(SESSION, "Method Details", "Conditionally REQUIRED when channelId is absent and MUST be absent when resuming an existing channel.")
}

fn wire_action_spec() -> SpecRef {
    spec(
        SESSION,
        "Action: \"voucher\"",
        "| voucher | object | REQUIRED | Signed voucher (see {{voucher-format}}) |",
    )
}

/// MPP-ec9e85084d "The server MUST verify each voucher:"; MPP-4acddd43ce
/// magic must match; MPP-69c0a4f95f recentBlockhash/recentSlot presence;
/// MPP-dc4603ccd4 openSlot REQUIRED; MPP-503cb2e52e / MPP-ebee0156c7 voucher
/// action fields.
const VERIFY_EACH: &str = "MPP-ec9e85084d";
const MAGIC: &str = "MPP-4acddd43ce";
const RECENT_PAIR: &str = "MPP-69c0a4f95f";
const OPEN_SLOT: &str = "MPP-dc4603ccd4";
const VOUCHER_FIELD: &str = "MPP-ebee0156c7";

crate::registry! {
    session_voucher_preimage_frozen => CaseBuilder::new(
        "session-voucher-preimage-frozen",
        "session-voucher.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        layout_spec(),
        "50-byte Ed25519 voucher preimage magic(0x56,0x01)||channelId(32)||cumulative LE u64||expiresAt LE i64. Frozen cross-SDK vector (matches the rust/Go/Python unit vectors). Pins the single most load-bearing session invariant byte-for-byte.",
        Input::Static(json!({"voucherPreimage": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "42", "expiresAt": 1234}})),
        Expect::Accept(Pin::ExactBytes(vec!["bytes", "base64Url"])),
    )
    .requirements(&[MAGIC])
    .build();
    session_voucher_preimage_large_cumulative => CaseBuilder::new(
        "session-voucher-preimage-large-cumulative",
        "session-voucher.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        layout_spec(),
        "Voucher preimage with a near-u64-max cumulative, asserting little-endian u64 packing has no precision loss.",
        Input::Static(json!({"voucherPreimage": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "18446744073709551607", "expiresAt": 4102444800_i64}})),
        Expect::Accept(Pin::ExactBytes(vec!["bytes"])),
    )
    .requirements(&[MAGIC])
    .build();
    session_voucher_preimage_no_expiry => CaseBuilder::new(
        "session-voucher-preimage-no-expiry",
        "session-voucher.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        layout_spec(),
        "50-byte Ed25519 voucher preimage with expiresAt OMITTED: 0-or-omitted means never-expires and the SDK must encode 0 verbatim into the trailing LE i64 — substituting any sentinel (e.g. a default expiry) makes the reconstructed bytes diverge from what the counterparty signed, breaking cross-SDK signature verification. Frozen after the Python SDK was caught substituting DEFAULT_SESSION_EXPIRES_AT here.",
        Input::Static(json!({"voucherPreimage": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "42"}})),
        Expect::Accept(Pin::ExactBytes(vec!["bytes", "base64Url"])),
    )
    .requirements(&[MAGIC])
    .build();
    session_wire_request_new_channel_frozen => CaseBuilder::new(
        "session-wire-request-new-channel-frozen",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_request_spec(),
        "New-channel session challenge SessionRequest (mpp-specs e702dd8): methodDetails has NO channelId, so recentBlockhash (base58, the open transaction's blockhash) and recentSlot (decimal-string u64 from the same getLatestBlockhash response's context.slot, the client's default openSlot) are REQUIRED and frozen here byte-for-byte. Round-tripped through the production wire parser and JCS-canonicalized; a rename, retype (e.g. numeric recentSlot on encode), or drop of either field diverges from the frozen bytes. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "request", "value": {"amount": "100", "currency": "USDC", "description": "metered inference", "methodDetails": {"channelProgram": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX", "decimals": 6, "gracePeriodSeconds": 900, "idleTimeoutOptionsSeconds": [60, 300, 900], "network": "devnet", "recentBlockhash": "EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N", "recentSlot": "250000000", "tokenProgram": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "voucherSigner": "operator"}, "minimumDeposit": "1000", "recipient": "11111111111111111111111111111111", "suggestedDeposit": "5000", "unitType": "request"}}})),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    )
    .requirements(&[RECENT_PAIR])
    .build();
    session_wire_request_resume_frozen => CaseBuilder::new(
        "session-wire-request-resume-frozen",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_request_spec(),
        "Resume session challenge SessionRequest (mpp-specs e702dd8): methodDetails.channelId is present, so recentBlockhash and recentSlot MUST be absent from the wire — the frozen bytes contain neither key. An SDK that emits the pair on resume (or serializes null placeholders) diverges. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "request", "value": {"amount": "100", "currency": "USDC", "methodDetails": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "channelProgram": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX", "network": "devnet"}, "recipient": "11111111111111111111111111111111"}}})),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    )
    .requirements(&[RECENT_PAIR])
    .build();
    session_wire_action_open_frozen => CaseBuilder::new(
        "session-wire-action-open-frozen",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_action_spec(),
        "Session open credential payload (mpp-specs e702dd8): the channel's PDA-seed slot travels as openSlot (decimal-string u64, defaulted by the client from the challenged recentSlot). Frozen byte-for-byte through the production parser; the superseded draft echo name recentSlot must not appear in the open payload. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "action", "value": {"action": "open", "authorizedSigner": "Config1111111111111111111111111111111111111", "channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "depositAmount": "5000", "gracePeriodSeconds": 900, "idleTimeoutSeconds": 300, "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "openSlot": "250000000", "payee": "Stake11111111111111111111111111111111111111", "payer": "Vote111111111111111111111111111111111111111", "salt": "7777", "transaction": "AQID"}}})),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    )
    .requirements(&[OPEN_SLOT])
    .build();
    session_wire_request_superseded_draft_reject => CaseBuilder::new(
        "session-wire-request-superseded-draft-reject",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_request_spec(),
        "Superseded draft SessionRequest shape (top-level cap/programId, no amount/methodDetails). A migrated SDK's wire parser must refuse it — accepting it would mean the SDK still speaks the pre-e702dd8 draft. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "request", "value": {"cap": "5000", "currency": "USDC", "network": "devnet", "programId": "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX", "recipient": "11111111111111111111111111111111"}}})),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("pre-e702dd8 draft request shape: top-level cap/programId with no amount or methodDetails".into()) },
    )
    .requirements(&[RECENT_PAIR])
    .build();
    session_wire_action_open_draft_slot_echo_reject => CaseBuilder::new(
        "session-wire-action-open-draft-slot-echo-reject",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_action_spec(),
        "Open payload carrying the superseded draft echo name recentSlot instead of openSlot (mpp-specs e702dd8 renamed the open payload's slot field). openSlot is required, so a migrated SDK must refuse this payload rather than silently defaulting the PDA-seed slot. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "action", "value": {"action": "open", "authorizedSigner": "Config1111111111111111111111111111111111111", "channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "depositAmount": "5000", "gracePeriodSeconds": 900, "mint": "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", "payee": "Stake11111111111111111111111111111111111111", "payer": "Vote111111111111111111111111111111111111111", "recentSlot": "250000000", "salt": "7777", "transaction": "AQID"}}})),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("draft slot echo: open payload uses recentSlot where the final contract requires openSlot".into()) },
    )
    .requirements(&[OPEN_SLOT])
    .build();
    session_wire_action_unknown_tag_reject => CaseBuilder::new(
        "session-wire-action-unknown-tag-reject",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_action_spec(),
        "Credential payload with an action tag outside the frozen set open/voucher/use/topUp/close (multiDelegate was removed from the final contract). A migrated SDK must refuse unknown action tags. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "action", "value": {"action": "multiDelegate", "channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "transaction": "AQID"}}})),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("unknown credential action tag".into()) },
    )
    .requirements(&[VOUCHER_FIELD])
    .build();
    session_wire_action_voucher_frozen => CaseBuilder::new(
        "session-wire-action-voucher-frozen",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_action_spec(),
        "Voucher action payload (mpp-specs e702dd8): a top-level channelId routing key is REQUIRED next to the signed voucher, and the signed voucher's inner data field is named voucher (not the superseded data). Frozen byte-for-byte through the production parser; servers MUST reject the action when the top-level channelId differs from the signed voucher's inner channelId. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "action", "value": {"action": "voucher", "channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "voucher": {"signature": "AKAh9LUoWFG2sxAMotzmLNpKwPTCiG6Q4YTwAinZMnkvYKPAKVPwYSfoQDp8XLKWzpbCNx66XB1BrcD1ZUPqU39", "signatureType": "ed25519", "signer": "Config1111111111111111111111111111111111111", "voucher": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "250", "expiresAt": 4102444800_i64}}}}})),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    )
    .requirements(&[VOUCHER_FIELD])
    .build();
    session_wire_action_close_frozen => CaseBuilder::new(
        "session-wire-action-close-frozen",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_action_spec(),
        "Close action payload with a nested final voucher (mpp-specs e702dd8): the nested signed voucher uses the same inner voucher key as the voucher action, and this voucher omits expiresAt (never-expires) — the frozen bytes contain no expiresAt key, so a serializer that emits a null/sentinel placeholder diverges. The nested voucher's channelId MUST equal the close channelId; servers reject a divergent pair. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "action", "value": {"action": "close", "channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "voucher": {"signature": "AKAh9LUoWFG2sxAMotzmLNpKwPTCiG6Q4YTwAinZMnkvYKPAKVPwYSfoQDp8XLKWzpbCNx66XB1BrcD1ZUPqU39", "signatureType": "ed25519", "signer": "Config1111111111111111111111111111111111111", "voucher": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "1000"}}}}})),
        Expect::Accept(Pin::ExactBytes(vec!["canonicalJson", "base64Url"])),
    )
    .requirements(&[VOUCHER_FIELD])
    .build();
    session_wire_action_voucher_legacy_inner_data_reject => CaseBuilder::new(
        "session-wire-action-voucher-legacy-inner-data-reject",
        "session-wire.json",
        Suite::Session,
        Intent::Session,
        Mode::CanonicalBytes,
        Role::Both,
        BugType::Wire,
        wire_action_spec(),
        "Superseded voucher action shape: signed voucher nested under inner key data with no top-level channelId. A migrated SDK's wire parser must refuse it — accepting it would mean the SDK still speaks the pre-e702dd8 draft voucher shape, which is exactly how the three SDKs drifted from the spec undetected while the freeze covered challenge/open only. NOTE: Go/Kotlin/Swift have not migrated to the final e702dd8 wire contract and declare an expected unsupported-mode skip for this vector (allowlisted in their seeded conformance tests); until the follow-up migration PR lands, this vector is enforced by the TypeScript and Python parsers only.",
        Input::Static(json!({"sessionWire": {"shape": "action", "value": {"action": "voucher", "voucher": {"data": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "250", "expiresAt": 4102444800_i64}, "signature": "AKAh9LUoWFG2sxAMotzmLNpKwPTCiG6Q4YTwAinZMnkvYKPAKVPwYSfoQDp8XLKWzpbCNx66XB1BrcD1ZUPqU39", "signatureType": "ed25519", "signer": "Config1111111111111111111111111111111111111"}}}})),
        Expect::Reject { code: RejectCode::InvalidPayload, reason: Some("pre-e702dd8 voucher shape: inner key data and no top-level channelId".into()) },
    )
    .requirements(&[VOUCHER_FIELD])
    .build();
    session_voucher_window_one_below => CaseBuilder::new(
        "session-voucher-window-one-below",
        "session-voucher-verify.json",
        Suite::Session,
        Intent::Session,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::Settlement,
        verify_spec(),
        "Fresh channel, now=1000, settlement window=900: expiresAt 1899 does not outlast now+window and is rejected.",
        Input::Static(json!({"signerSecretKey": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 121, 181, 86, 46, 143, 230, 84, 249, 64, 120, 177, 18, 232, 169, 139, 167, 144, 31, 133, 58, 230, 149, 190, 215, 224, 227, 145, 11, 173, 4, 150, 100], "sessionVoucherVerify": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "100", "expiresAt": 1899, "nowSeconds": 1000, "settlementWindowSeconds": 900, "deposit": "1000"}})),
        Expect::Reject { code: RejectCode::VoucherExpiresBeforeSettlement, reason: None },
    )
    .requirements(&[VERIFY_EACH])
    .build();
    session_voucher_window_at_boundary => CaseBuilder::new(
        "session-voucher-window-at-boundary",
        "session-voucher-verify.json",
        Suite::Session,
        Intent::Session,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::Settlement,
        verify_spec(),
        "expiresAt exactly now+window is rejected: the boundary is exclusive, so a close started now cannot reach its deadline with the voucher already unusable.",
        Input::Static(json!({"signerSecretKey": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 121, 181, 86, 46, 143, 230, 84, 249, 64, 120, 177, 18, 232, 169, 139, 167, 144, 31, 133, 58, 230, 149, 190, 215, 224, 227, 145, 11, 173, 4, 150, 100], "sessionVoucherVerify": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "100", "expiresAt": 1900, "nowSeconds": 1000, "settlementWindowSeconds": 900, "deposit": "1000"}})),
        Expect::Reject { code: RejectCode::VoucherExpiresBeforeSettlement, reason: None },
    )
    .requirements(&[VERIFY_EACH])
    .build();
    session_voucher_window_one_above => CaseBuilder::new(
        "session-voucher-window-one-above",
        "session-voucher-verify.json",
        Suite::Session,
        Intent::Session,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::Settlement,
        verify_spec(),
        "expiresAt one second past now+window is the first accepted expiry.",
        Input::Static(json!({"signerSecretKey": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 121, 181, 86, 46, 143, 230, 84, 249, 64, 120, 177, 18, 232, 169, 139, 167, 144, 31, 133, 58, 230, 149, 190, 215, 224, 227, 145, 11, 173, 4, 150, 100], "sessionVoucherVerify": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "100", "expiresAt": 1901, "nowSeconds": 1000, "settlementWindowSeconds": 900, "deposit": "1000"}})),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[VERIFY_EACH])
    .build();
    session_voucher_expired_at_now => CaseBuilder::new(
        "session-voucher-expired-at-now",
        "session-voucher-verify.json",
        Suite::Session,
        Intent::Session,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::Settlement,
        verify_spec(),
        "expiresAt == now is expired (on-chain parity: now >= expires_at), reported as expired rather than the window guard.",
        Input::Static(json!({"signerSecretKey": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 121, 181, 86, 46, 143, 230, 84, 249, 64, 120, 177, 18, 232, 169, 139, 167, 144, 31, 133, 58, 230, 149, 190, 215, 224, 227, 145, 11, 173, 4, 150, 100], "sessionVoucherVerify": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "100", "expiresAt": 1000, "nowSeconds": 1000, "settlementWindowSeconds": 900, "deposit": "1000"}})),
        Expect::Reject { code: RejectCode::VoucherExpired, reason: None },
    )
    .requirements(&[VERIFY_EACH])
    .build();
    session_voucher_never_expires_with_window => CaseBuilder::new(
        "session-voucher-never-expires-with-window",
        "session-voucher-verify.json",
        Suite::Session,
        Intent::Session,
        Mode::VerifyTransaction,
        Role::Server,
        BugType::Settlement,
        verify_spec(),
        "expiresAt 0 never expires and bypasses the settlement-window guard.",
        Input::Static(json!({"signerSecretKey": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 121, 181, 86, 46, 143, 230, 84, 249, 64, 120, 177, 18, 232, 169, 139, 167, 144, 31, 133, 58, 230, 149, 190, 215, 224, 227, 145, 11, 173, 4, 150, 100], "sessionVoucherVerify": {"channelId": "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN", "cumulativeAmount": "100", "expiresAt": 0, "nowSeconds": 1000, "settlementWindowSeconds": 900, "deposit": "1000"}})),
        Expect::Accept(Pin::Outcome),
    )
    .requirements(&[VERIFY_EACH])
    .build();
}
