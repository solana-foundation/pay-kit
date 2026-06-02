# Operability caveats

Acceptance criteria every PayKit port has to land, distilled from the
maintainer follow-ups on the first two reference implementations:

- Ruby gem: [PR #142](https://github.com/solana-foundation/pay-kit/pull/142),
  the Sinatra-example-was-broken follow-up.
- Lua rock: [PR #141](https://github.com/solana-foundation/pay-kit/pull/141),
  the OpenResty port that carried the same caveats forward.

Each numbered item below is a hard requirement. PRs that omit one need
an explicit "not applicable" note in the body explaining the
language-specific reason (e.g. "Rack 3 header casing has no analogue
in Go because `net/http` accepts mixed-case writes by default"). No
silent omissions.

### 1. `solana_localnet` falls back to the mainnet mint row

`PayCore::Solana::Mints::MINTS` only ships `mainnet` and `devnet` rows
for each stablecoin. `mint_for(:USDC, :solana_localnet)` used to raise
on the first 402 with "stablecoin :USDC not configured for network
:solana_localnet". Surfpool / the hosted localnet at
`https://402.surfnet.dev:8899` clone mainnet state, so the mainnet
mint exists on them. Resolve `localnet` to the mainnet mint when no
explicit `localnet` row is set, matching `PayCore::Solana::Mints.resolve`
and the Rust spine's `resolve_stablecoin_mint`.

### 2. Default `localnet` RPC = `https://402.surfnet.dev:8899`

`http://localhost:8899` requires the developer to run a local validator
(`solana-test-validator`, Surfpool, …) before the example app does
anything. Default to the hosted Surfpool endpoint so
`configure { c.network = :solana_localnet }` boots against a reachable
RPC with no extra setup.

**Per-language status:**

- **Ruby** — implemented. `config.rb:9` sets `DEFAULT_RPC_URL =
  "https://402.surfnet.dev:8899"` and `config.rb:16` reads it as the
  env-overridable default. Boots out of the box.
- **Lua** — NOT YET IMPLEMENTED. `lua/mpp/protocol/solana.lua:45`
  returns `http://localhost:8899` for `localnet`. The operator must set
  `MPP_RPC_URL` or pass `rpc_url` in config to reach Surfpool. Do not
  imply parity with Ruby until this default is updated.

### 3. Boot-time preflight with Surfnet cheatcode auto-bootstrap

`configure` runs two soundness checks **before locking the config**:

1. **Fee-payer SOL balance** — operator signer's pubkey has at least
   `MIN_FEE_PAYER_LAMPORTS = 1_000_000` (0.001 SOL = ~200 settlement
   txs at 5000 lamports each).
2. **Recipient ATA exists** — for each `c.stablecoins`, the
   operator's recipient owns an ATA for the resolved mint.

When the check fails:

- **On `solana_localnet` with the gem-shipped demo signer**:
  auto-bootstrap via Surfnet's cheatcodes (`surfnet_setAccount`
  funds the fee-payer with `AUTOFUND_LAMPORTS = 10_000_000_000` =
  10 SOL; `surfnet_setTokenAccount` provisions the missing ATA at
  amount 0, state `initialized`). The example app "just works"
  against `https://402.surfnet.dev:8899` with no manual setup.
- **Everywhere else** (real mainnet/devnet, or a non-demo signer
  on any network): raise `ConfigurationError` at boot, naming the
  missing pubkey / ATA and how to create it.

RPC failures during preflight are **logged, not raised** — an
unreachable endpoint never blocks boot; the runtime will resurface
the connection problem on the first request.

**Opt-out**: `c.preflight = false` (in `configure`) or
`PAY_KIT_DISABLE_PREFLIGHT=1` (env var). The test suite sets the env
var in its test helper so the offline suite never tries to hit a
real RPC. The preflight file itself is excluded from the coverage
gate via `add_filter` (or the language equivalent), with a comment
documenting the rationale — it wraps live RPC + cheatcode calls
that don't fit a unit suite.

### 4. MPP HMAC secret auto-resolution

This is a **portable requirement** for every server-side PayKit port.
The HMAC challenge-binding secret must survive process restarts to
avoid invalidating in-flight challenges, and must be operator-injectable
without a code change in production.

The canonical resolution order (first hit wins):

1. `ENV["PAY_KIT_MPP_CHALLENGE_BINDING_SECRET"]` — production
   pattern (orchestrator-supplied env var).
2. `./.env` parsed for the same key — sticky across restarts, shared
   by workers in the same project root.
3. Generate `SecureRandom.hex(32)` (or language-native CSPRNG hex)
   and append to `./.env` (mode `0600` if the file is being created)
   so subsequent boots reuse the same value.

If `./.env` is unwritable (read-only container, etc.), fall back to
the in-memory generated value and log a warning — the server still
boots, but the secret rotates per process and invalidates in-flight
challenges on restart. Point the operator at the env var as the
production override.

The dotenv parser is intentionally a small tolerant reader: blank
lines, `#` comments, and `KEY=value` / `KEY="value"` / `KEY='value'`
forms. No new dependency on a dotenv library.

**Per-language status:**

- **Ruby** — implemented. Preflight resolves the secret via env,
  `.env`, then CSPRNG fallback with `.env` write-back.
- **Lua** — GAP / NOT YET IMPLEMENTED. `lua/mpp/server/init.lua:35`
  reads `config.secret_key or os.getenv('MPP_SECRET_KEY')` and raises
  an error if the value is absent. There is no `.env` file parsing, no
  CSPRNG generation, and no write-back. The operator must supply the
  secret explicitly. Mark this N/A for auto-resolution until the
  preflight/env-file layer is added. PRs porting the Lua server must
  note this gap explicitly in the PR body.

### 5. x402 challenge embeds the server's recent blockhash

The server fetches `getLatestBlockhash` against its own RPC at
challenge-build time and stamps the result into
`accepted.extra.recentBlockhash`. The pay-kit Rust client reads this
field at parse + tx-build time. Closes the surfpool / forked-mainnet
drift where the client called `getLatestBlockhash` against the public
devnet RPC and the server's surfnet ledger had never seen that hash.

Scope note: this is **pay-kit Rust client only**. Canonical x402 SDKs
(TS, Go) ignore `accepted.extra.recentBlockhash` and unconditionally
call `getLatestBlockhash` against their own RPC. Promoting this into
the canonical wire format is an x402-foundation spec discussion. On
real mainnet/devnet the field is harmless (RPCs agree); on localnet
/ surfpool it's the difference between "works end-to-end with pay
curl" and "client gives up with 402 again".

Inject via `recent_blockhash_provider:` (or the language-native kwarg
pattern) so unit tests stay offline.

### 6. Framework-host quirks (per-language; flag in this language's spec)

Each language's web framework has its own friction points that this
port has to absorb. Ruby's were:

- **Rack 3 lint enforces lowercase response header names.** Wire-level
  constants (`PAYMENT-REQUIRED`, `PAYMENT-RESPONSE`, MPP
  `WWW-Authenticate`) stay canonical (uppercase); downcase happens
  only at the Rack response boundary.
- **Sinatra's exception pipeline** dumps backtrace to stderr when an
  exception is raised, before checking for a registered handler.
  `require_payment!` uses Sinatra's `halt` to short-circuit instead
  of raising `PaymentRequired`. Exception class still carries
  `http_status => 402` as belt-and-suspenders.

Land your language's equivalents (Flask exception class, FastAPI
`HTTPException`, Laravel `ResponseFactory::abort`, Go `http.Error`
+ middleware bypass, etc.). Pin them to the issue before shipping.

### 7. Test + coverage gates

- Preflight file excluded from the coverage gate (live RPC + cheatcode
  calls don't fit a unit suite). Document the filter inline so it
  doesn't look arbitrary.
- Unit tests cover both preflight knobs (`c.preflight = false` and the
  env-var kill switch) by stubbing `PayKit::Preflight.run` and asserting
  the spy fires / doesn't fire. No live RPC in the unit suite.
- Branch coverage on the protocol-critical paths (x402 11-rule
  verifier, MPP credential parsing, Ed25519 cosign) regardless of
  language. Filter the lint-but-don't-test files (asset generators,
  re-export shims) from the coverage denominator.

