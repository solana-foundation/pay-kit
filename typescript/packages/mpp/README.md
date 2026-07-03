# @solana/mpp (deprecated)

> **This package is deprecated.** It is superseded by
> [`@solana/pay-kit`](https://www.npmjs.com/package/@solana/pay-kit), which
> provides the same MPP support alongside x402 and AP2 behind one surface.

`@solana/mpp` is no longer actively developed. New work lands in `@solana/pay-kit`.

## Migrate

```sh
npm remove @solana/mpp
npm install @solana/pay-kit
```

The MPP server and client live under `@solana/pay-kit`. See the
[pay-kit README](https://github.com/solana-foundation/pay-kit/tree/main/typescript)
for the current API.

## Last release

The final `@solana/mpp` release carries the concurrent-signature-replay
(TOCTOU) fix from [#211](https://github.com/solana-foundation/pay-kit/pull/211).
Existing users should take it and then migrate to `@solana/pay-kit`.
