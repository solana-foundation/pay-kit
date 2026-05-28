// Package client implements the Solana MPP client-side charge flow.
// It builds the on-chain transaction (system or SPL transfer + compute
// budget + memo + optional split transfers + optional idempotent ATA
// create), signs it with the caller's signer, and packages either the
// serialized transaction (pull mode) or the broadcast signature (push
// mode) into a payment credential. Behavior mirrors the Rust client in
// rust/src/client/charge.rs so the cross-language interop harness
// exercises identical wire output.
package client
