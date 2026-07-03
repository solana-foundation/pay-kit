# Security Policy

## Reporting Security Problems

**DO NOT CREATE A GITHUB ISSUE** to report a security problem.

Instead please use this [Report a Vulnerability](https://github.com/solana-foundation/pay-kit/security/advisories/new) link.

Provide a helpful title and detailed description of the problem.

If the advisory form is unavailable, email **disclosures@solana.org** with the same detail and a way to reach you.

Expect a response as fast as possible in the advisory, typically within 72 hours.

## Deployment threat model

The SDK's server-side guarantees depend on how you run it. Two invariants are the
operator's responsibility.

### Replay protection needs a shared, atomic store in production

Charge and session verification reject a payment signature that has already been
consumed. The consumed-signature marker lives in a pluggable `Store`. The default
in-memory store, and the in-process `withKeyLock` serialization that backs it, are
**process-local**: they prevent double-settlement only within a single Node (or
Rust) process.

If you run more than one replica, or the process restarts, a signature consumed on
one instance is unknown to the others, so the same payment can be replayed and
accepted again. In production you MUST back the consumed marker with a shared,
persistent store, and ideally one that offers an atomic reserve (for example Redis
`SET key value NX`) so the check-and-mark is atomic across processes rather than
merely serialized in one.

The TypeScript `configure()` enforces this by failing closed outside localnet when
no `replayStore` is provided; set `PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1` only if
you accept single-process replay scope.

### Session opens must be bound to on-chain state

A push-mode session open is only trustworthy when the server can read the on-chain
channel account: the client-supplied deposit, channel id, and signer are not
authoritative. Configure an `rpc_url` for any real deployment so the open is bound
to the program's channel state (the SDK fails closed off localnet without one).

## Acknowledgements

We thank the researchers who have responsibly disclosed issues:

- **Kian Kai Ang** ([kai-kka](https://github.com/kai-kka)), University of Sydney, for reporting the concurrent-signature replay (TOCTOU) in the TypeScript MPP charge push-mode verifier, with a working proof of concept.
