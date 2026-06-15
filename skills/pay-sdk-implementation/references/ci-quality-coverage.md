# CI, quality, coverage

The reference CI is `mpp-sdk/.github/workflows/ci.yml`. Copy the
shape of `test-rust` (or `test-python`/`test-go` for the closest
language fit), add formatter + linter steps, gate coverage at ≥ 90 %.

## Required jobs per SDK

A new-language SDK needs **all** of the following jobs in `ci.yml`:

1. **`test-<lang>`** — unit tests + coverage upload + format/lint check.
2. **`integration`** (existing) — already runs against Surfnet; once the
   harness adapter is registered, the harness picks it up.
3. **`harness`** (existing) — add `<lang>` to the focused matrix lines
   the way `Run Rust client harness smoke` is set up (one line for
   `<lang> client × ts server`, one for `ts client × <lang> server`,
   one self-pair).

## Template — `test-<lang>` job

```yaml
test-<lang>:
  name: <Language> tests
  needs: build-html
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v5
    - uses: <lang-setup-action>     # actions/setup-go, actions/setup-node…
      with:
        <pin language version, enable caching>
    - uses: actions/cache@v5         # only if the language toolchain doesn't cache itself
      with:
        path: <lang-cache-dirs>
        key: ${{ runner.os }}-<lang>-${{ hashFiles('<lockfile>') }}
        restore-keys: ${{ runner.os }}-<lang>-
    - name: Download HTML assets
      uses: actions/download-artifact@v7
      with:
        name: html-assets
    - name: Format check
      working-directory: <lang>
      run: <fmt-check-cmd>
    - name: Lint
      working-directory: <lang>
      run: <lint-cmd>
    - name: Type-check
      working-directory: <lang>
      run: <typecheck-cmd>   # skip for dynamically-typed languages with no type tool
    - name: Run tests with coverage
      working-directory: <lang>
      env:
        SURFPOOL_REPORT: "1"
      run: <coverage-cmd-with-90-pct-gate>
    - name: Upload coverage
      if: always()
      uses: actions/upload-artifact@v7
      with:
        name: <lang>-coverage
        path: <lang>/coverage.<ext>
    - name: Upload Surfpool report data
      if: always()
      uses: actions/upload-artifact@v7
      with:
        name: surfpool-reports-<lang>
        path: <lang>/target/surfpool-reports/
        if-no-files-found: ignore
```

The `Download HTML assets` step is mandatory if the server side ships
a payment-link renderer — the assets are generated upstream by
`build-html` and need to be in place before the tests start. Skip the
download only when the SDK is **client-only**.

## Coverage gate

Coverage threshold is **≥ 90 %** for new SDKs. Existing SDKs target:

- Rust: line + branch via `cargo llvm-cov`, expressed as a test count
  in the badge (the JSON is uploaded for trending).
- Go: `go test -coverprofile`, checked by
  `go/scripts/check_coverage.sh coverage.out 70`. The 70 % gate is a
  legacy floor — new SDKs ship 90 %+.
- Python: `pytest --cov --cov-fail-under=85` configured in
  `pyproject.toml`. Treat 85 % as a legacy floor for the same reason.
- Lua: line count via LuaCov, gated at 70 %.

For a new SDK, **bake the 90 % gate into the test command itself** so
local `just <l>-test-cover` and CI agree. Examples:

- Rust — `cargo llvm-cov --fail-under-lines 90`
- Python — `pytest --cov --cov-fail-under=90`
- Go — `./scripts/check_coverage.sh coverage.out 90`
- PHP — `phpunit --coverage-clover ... --coverage-min=90`
  (or `infection --min-msi=90` for mutation; pick the metric that
  exists for the language)

If the language's coverage tool cannot enforce a gate, write a small
script in `<lang>/scripts/check_coverage.<sh|py>` modeled on
`go/scripts/check_coverage.sh`.

## Linting and formatting

Every public SDK has **format check + lint** running in CI. Failures
must fail the job:

- Rust — `cargo fmt --check`, `cargo clippy -- -D warnings`
- Python — `ruff check`, `ruff format --check`, `pyright`
- Go — `gofmt -l .` (must produce no output) + `go vet ./...`
- TypeScript — `pnpm lint`, `pnpm format:check`, `pnpm typecheck`
- Lua — `luacheck` (or equivalent)
- PHP — `phpstan analyse --level=max`, `php-cs-fixer --dry-run --diff`
- Ruby — `standardrb` (or `rubocop`), `sorbet tc` if typed

## Doc comments (LSP discoverability)

Every public type/function carries a **one-line summary** so the
language's hover/LSP shows it. Reference: every `pub` item in
`rust/crates/mpp/src/lib.rs` has a `///` line. Examples to mirror:

```rust
/// Payment method identifier (newtype over String).
///
/// Per spec, method identifiers MUST be lowercase ASCII strings.
pub struct MethodName(String);
```

Per-language enforcement:

- Rust — `cargo doc -- -D missing_docs` (gated in CI).
- Python — `pyright`/`ruff` flag missing docstrings (`D` rules) if
  configured; minimum policy: every `def` and `class` in `__init__.py`
  re-exports has a one-line docstring.
- Go — `go vet -all` flags missing comments on exported identifiers;
  enable `revive` or `golint` with `exported` rule.
- TS — TSDoc on every `export`.

## Auditing

The TS workflow runs `pnpm audit --production`. Add an equivalent for
the new language:

- Rust — `cargo audit` (separate job; failures are warnings if the
  upstream is unmaintained but it must run).
- Python — `pip-audit` or `safety check`.
- Go — `govulncheck ./...`.
- PHP — `composer audit`.
- Ruby — `bundle audit`.

## Things to pay attention to

- **Coverage is computed after deleting `target/` and the language's
  build cache** if your tool has stale-coverage issues (Rust
  `cargo llvm-cov` does). Add a `clean` step before the coverage step
  in CI if you see drift between local and CI numbers.
- **`html-assets` is an artifact, not a checked-in directory.** The
  `build-html` job uploads it; downstream jobs `actions/download-artifact`
  it. Generated HTML files (e.g. `rust/crates/mpp/src/server/html/*.gen.*`) are
  committed for offline builds but CI verifies the committed copy is
  up-to-date — see the `Verify committed gen files are up to date`
  step in `ci.yml`. New language servers go in that diff list.
- **`SURFPOOL_REPORT=1`** flips the per-language test harness into a
  mode that writes JSON reports to `<lang>/target/surfpool-reports/`.
  Honor this env var so the surfpool reports artifact upload picks
  them up.
- **Caching keys** include the lockfile hash and the OS. Don't share
  caches between languages or between toolchain versions — the
  reference jobs key off the language's lockfile only.
- **Job names matter** — `report.yml` aggregates per-job coverage by
  artifact name. Use `<lang>-coverage` and
  `surfpool-reports-<lang>` exactly.
