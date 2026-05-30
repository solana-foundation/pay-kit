# README template

Use this template verbatim; only fill in the placeholders. The
reference implementation is `ruby/README.md` (the structure the
maintainer endorsed in
https://github.com/solana-foundation/pay-kit/issues/122). The Lua
SDK at `lua/README.md` is the second reference; it follows this
same template against an OpenResty surface.

## Section order

Top to bottom, every language README:

1. **Header** (no heading)
   - Centered banner image.
   - One paragraph (3-4 lines): what it does + protocols + framework
     integration. Template:
     > Charge stablecoins (USDC, USDT, PYUSD, ...) for any HTTP
     > endpoint, in `<language>`. `<package-naming>`, one surface,
     > two protocols underneath: [x402] and [MPP]. `<Framework>` rides
     > on top of `<runtime middleware>`.
   - 3 badges: language version, line coverage, branch coverage
     (or tests count if branch coverage isn't gated separately).
   - `---` divider.
2. `## Quick start` -- three progressively-realistic snippets.
3. `## Run the example` -- boot the bundled example + pay it with
   `pay curl`.
4. `## x402` then `## mpp` -- protocols, in that order.
5. `## Server-only` (or `## Client-only`).
6. Reference sections (Vocabulary, Three primitives, Inline pricing,
   Gate DSL, `<Runtime>`-first).
7. Ops sections (Coverage, Harness, Spec).
8. Bottom (Repo layout, Coding convention, License).

## Quick start (three snippets)

Section preamble (one sentence):

> Three progressively-realistic snippets. Each one runs as-is, copy,
> paste, hit the URL.

Then three subsections, each a complete runnable file with a
file-name header comment (`# config.ru`, `// index.ts`, `# nginx.conf`,
etc.):

| # | Title                           | What it shows                                                                                |
|---|---------------------------------|----------------------------------------------------------------------------------------------|
| 1 | Smallest possible app           | Inline-priced route, zero-config (demo signer + Surfpool sandbox), one route                 |
| 2 | Multiple gates via a registry   | Pricing class (or per-language equivalent), two gates, one protocol-locked via `accept:`     |
| 3 | Production-shape config         | Explicit operator key + recipient, real RPC, accepted stablecoins, fee-bearing gate, mainnet |

Each subsection:

- One paragraph preamble: name what's new vs. the previous snippet,
  what's at stake. Don't restate the obvious.
- Code: complete and runnable as the framework's entry-point file.
  First line is a `# <filename>` comment so the reader knows where
  to paste it.
- One paragraph postamble: explain only what's non-obvious.
  Bullets when listing safety rails.

### Per-language framework choice

The framework is the runtime surface the snippet boots against:

| Language | Snippet framework | Entry-point filename |
|---|---|---|
| Ruby | Sinatra | `config.ru` |
| Python | Flask | `app.py` |
| TypeScript | Express | `index.ts` |
| Go | `net/http` | `main.go` |
| PHP | Laravel | `routes/api.php` |
| Lua | OpenResty / nginx | `nginx.conf` |
| Swift / Kotlin | (client-only) | n/a |

## Protocol sections

Each protocol section:

- One paragraph: what the protocol is, link to the spec site.
- One paragraph: when to pick it (x402 is single-recipient; MPP
  supports splits + fee-payer separation). Use a "Use MPP when:"
  bulleted list for the picking-a-protocol guidance.
- Scheme matrix: **two columns only**, Scheme + Status. Notes go in
  the prose above the table, not in a Notes column.

Use `✅` for shipped + tested, `—` for pending. Never mark
aspirational features.

## Server-only / Client-only

One paragraph explaining what's NOT in this package. Bullet list of
pointers: `pay curl` + sibling SDKs by name (so it's a single hop
to find them). If the package is dual (server + client), omit this
section.

## Reference sections (after the welcoming flow)

In order:

- `## Vocabulary` -- table of terms used in the docs (gate, amount,
  total, price, fee_within, fee_on_top, payment, protocol, scheme,
  accept, denom, settlement).
- `## Three primitives` -- the bang form + predicate + accessor.
- `## Inline pricing` -- the no-registry-entry form.
- `## Gate DSL` -- fee patterns (fee_within, fee_on_top, dynamic),
  boot-time validation list.
- `## <Runtime>-first` -- middleware / framework wiring details
  (Rack-first for Ruby, Express-first for TS, OpenResty-first for
  Lua, etc.).

## Ops sections

- `## Coverage` -- gates + commands. Always include the just task.
- `## Harness` -- cross-language test commands (the focused matrix
  trio: TS client / Rust client / language-specific x402 client).
- `## Spec` -- protocol spec links (HTTP Payment Authentication
  Scheme + x402).

## Bottom

- `## Repo layout` -- directory tree (one file per significant
  module + a one-line comment per entry). **Bottom of the file, not
  near the top.**
- `## Coding convention` -- name the style guide + the per-language
  best-practice skill.
- `## License`.

## Tone

Match the [Standard Ruby](https://github.com/standardrb/standard)
voice guide the Ruby README was written to.

**Do:**

- Lead with the action. "Save as `config.ru` and run
  `bundle exec rackup`." Not "The deployment process involves
  several steps."
- Use "you" for the reader, active voice for the SDK. "The
  middleware rescues `PaymentRequired`" not "exceptions are rescued."
- Specific numbers. "Default 60 seconds" not "a reasonable timeout."
- File-name header comment as the first line of every snippet, so
  the reader knows where to paste.
- Each snippet runs as-is. No "...add to your app" hand-waving.

**Don't:**

- Don't put env-var fetches in quick-start snippets. It forces the
  reader to mentally substitute. Use a literal pubkey and mention
  `os.getenv` / `ENV.fetch` / `process.env` as the override pattern
  at the end of snippet 3.
- Don't add a Notes column to the protocol matrix. Notes are prose;
  the table is for quick scanning.
- Don't show `--verbose`-only log lines in the demo terminal output
  if the snippet doesn't pass `--verbose`. Match the output to the
  command.
- Don't mark aspirational features. `✅` only for shipped + tested.
  `—` for pending. Never document a flag that doesn't work.
- Don't put repo layout near the top. It's reference. Bottom of the
  file.
- Don't bury the lede with vague intros. Name what's actually
  different from the previous snippet.
- Don't write "simply" or "just". If it were simple they wouldn't
  be reading the docs.
- Don't use AI transitions. "Furthermore", "It is worth noting that",
  "Let's dive into", "In this section, we will."

Tone check before publishing: read each paragraph out loud. If it
sounds like a senior engineer pair-programming with you, good. If
it sounds like a textbook or a marketing page, rewrite.

## Heuristics specific to pay-kit

- Three snippets is the right number. One is too thin (no
  progression). Five is too many (each language has the same three
  real layers: demo / registry / production). Stick to three.
- The demo-signer-on-mainnet refusal call-out is load-bearing. Every
  language has the same safety rail. Frame it as a bullet under
  "Two safety rails fire at boot" after snippet 3.
- MPP HMAC secret auto-resolution (env → `.env` → generate +
  persist) is a preflight feature shipped in Ruby PR #142. Each
  language needs its equivalent before snippet 3 can ship, and the
  README should describe whichever resolution chain that language
  settled on. The full caveat list lives in
  `references/operability-caveats.md` — read it before drafting
  snippet 3.
- `pay curl` link target: first mention in snippet 1 should link
  forward to `#run-the-example`. Avoids the reader Googling "what is
  pay curl".
- Cross-link sibling READMEs: in the "Server-only" / "Client-only"
  pointer, list the other SDKs by name so it's a single hop to find
  them.

## Package name conventions

Use the platform-native packaging convention. If a scope is
available, use it.

| Language | Package name |
|---|---|
| TypeScript | `@solana/pay-kit` (npm scoped) |
| Python | `solana-pay-kit` (PyPI) |
| Ruby | `solana-pay-kit` (RubyGems) |
| PHP | `solana/pay-kit` (Composer vendor/name) |
| Go | `github.com/solana-foundation/pay-kit/go` |
| Kotlin | `com.solanafoundation:pay-kit` (Maven coordinates) |
| Swift | `SolanaPayKit` (SwiftPM target) |
| Lua | `lua-resty-pay-kit` (LuaRocks) |
