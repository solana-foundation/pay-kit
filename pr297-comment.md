Addressed all CHANGES_REQUESTED feedback. Implemented fetch-from-mint fallback for `extra.decimals` across all five SDK languages, mirroring the existing `recentBlockhash` pattern.

**What changed (per language):**
- **Python**: `_fetch_mint_decimals(rpc, mint)` helper reads byte 44 of the Mint layout via RPC; errors surface the mint address so the caller can recover
- **Go**: `solanatx.ResolveMintDecimals(ctx, rpc, mint)` plus plumbing ctx/rpc through `buildSPLTransfer`; client updated to call it when decimals absent
- **Swift**: `RpcClient.getMintDecimals(pubkeyBase58:)` plus fallback in `_buildPaymentPayload`; tests use URLProtocol stubs with `drainBody()` for httpBodyStream
- **Kotlin**: `rpcDecimalsProvider: (() -> UByte)? = null` param (same pattern as existing `rpcBlockhashProvider`); absent plus no provider equals clear error
- **Rust**: `verify.rs` skip-compare when `requirements.decimals` is `None` (on-chain `TransferChecked` enforces anyway); `select.rs` `Candidate.decimals: Option<u8>` with `unwrap_or(6)` for ranking heuristic only

**Tests:**
- Python 49/49, Go all pass, Swift 10/10, Rust 382 pass
- Kotlin: locally validated at code level; Gradle not available on dev box, CI runs `gradle test`

**Interop preserved:** when `extra.decimals` is present, it is still used as an RPC-saving hint (no behavior change for compliant callers). The on-chain `TransferChecked` instruction verifies the byte against the mint, so lying values stay fail-closed. Happy to re-review quickly.
