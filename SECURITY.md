# Security Policy

## Reporting Security Problems

**DO NOT CREATE A GITHUB ISSUE** to report a security problem.

Instead please use this [Report a Vulnerability](https://github.com/solana-foundation/pay-kit/security/advisories/new) link.

Provide a helpful title and detailed description of the problem.

If the advisory form is unavailable, email **disclosures@solana.org** with the same detail and a way to reach you.

Expect a response as fast as possible in the advisory, typically within 72 hours.

## Acknowledgements

We thank the researchers who have responsibly disclosed issues:

- **Kian Kai Ang** ([kai-kka](https://github.com/kai-kka)), University of Sydney, for reporting the concurrent-signature replay (TOCTOU) in the TypeScript MPP charge push-mode verifier, with a working proof of concept.
- **Snuff12** ([snuff12](https://github.com/snuff12)), for reporting a payment-credential replay issue in the TypeScript MPP charge flow that allowed multiple handler executions from a single payment.
