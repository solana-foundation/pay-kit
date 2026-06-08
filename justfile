set shell := ["bash", "-uc"]

# Pinned upstream commits. Bump each `_ref` alongside an IDL refresh so
# reproducibility doesn't depend on whatever `main` happens to be when
# the `*-pull-idl` recipes were last run.
subscriptions_repo     := "solana-foundation/subscriptions"
subscriptions_ref      := "30a6f7cbd1c53862cc598d93cb771c2c86a10cbf"
payment_channels_repo  := "Moonsong-Labs/solana-payment-channels"
payment_channels_ref   := "f1b5e91482553fd1dce33aab4ff2a71cb6e734f8"

default:
    @just --list

# ── Codama codegen ──
#
# Single source of truth for Solana program clients consumed by the SDKs.
# Today: pulls the subscriptions IDL from a pinned upstream commit and
# renders a Rust client into `rust/crates/programs/subscriptions/`.
# Extending to TS/Go/Python is a matter of dropping the matching
# `@codama/renderers-*` into `skills/pay-sdk-implementation/codegen/`
# and adding a recipe below.

codegen_dir := "skills/pay-sdk-implementation/codegen"

# Install codegen Node deps (run once after clone; idempotent).
codegen-install:
    cd {{codegen_dir}} && pnpm install

# Fetch the subscriptions IDL from the pinned upstream commit into
# `idl/subscriptions.json`. Vendor the file alongside the generated
# client so codegen is reproducible from a clean checkout without a
# round-trip to GitHub.
subscriptions-pull-idl:
    @mkdir -p idl
    @echo "Fetching idl/subscriptions.json @ {{subscriptions_ref}}"
    curl -fsSL \
        "https://raw.githubusercontent.com/{{subscriptions_repo}}/{{subscriptions_ref}}/idl/subscriptions.json" \
        -o idl/subscriptions.json
    @echo "Wrote idl/subscriptions.json"

# Render the Rust client from the vendored IDL. Wipes
# `rust/crates/programs/subscriptions/src/generated/` and rewrites it
# in place — see {{codegen_dir}}/generate-subscriptions-client.ts.
subscriptions-generate-rs: codegen-install
    cd {{codegen_dir}} && pnpm run subscriptions:rust
    cd rust && cargo fmt -p subscriptions-client

# Full refresh: pull IDL + regenerate Rust client.
subscriptions-sync: subscriptions-pull-idl subscriptions-generate-rs

# Fetch the payment-channels IDL from the pinned upstream commit into
# `idl/payment-channels.json`.
payment-channels-pull-idl:
    @mkdir -p idl
    @echo "Fetching idl/payment-channels.json @ {{payment_channels_ref}}"
    curl -fsSL \
        "https://raw.githubusercontent.com/{{payment_channels_repo}}/{{payment_channels_ref}}/program/payment_channels/idl/payment_channels.json" \
        -o idl/payment-channels.json
    @echo "Wrote idl/payment-channels.json"

# Render the Rust client from the vendored IDL. Wipes
# `rust/crates/programs/payment-channels/src/generated/` and rewrites
# it in place — see {{codegen_dir}}/generate-payment-channels-client.ts.
payment-channels-generate-rs: codegen-install
    cd {{codegen_dir}} && pnpm run payment-channels:rust
    cd rust && cargo fmt -p payment-channels-client

# Full refresh: pull IDL + regenerate Rust client.
payment-channels-sync: payment-channels-pull-idl payment-channels-generate-rs

# ── TypeScript ──

# Install TypeScript dependencies
ts-install:
    cd typescript && pnpm install

# Build TypeScript packages
ts-build:
    cd typescript && pnpm build

# Typecheck TypeScript
ts-typecheck:
    cd typescript && pnpm typecheck

# Unit tests (TypeScript)
ts-test:
    cd typescript && pnpm test

# Integration tests (TypeScript, requires Surfpool)
ts-test-integration:
    cd typescript && pnpm test:integration

# Format and lint TypeScript
ts-fmt:
    cd typescript && pnpm lint:fix && pnpm format

# Audit TypeScript dependencies
ts-audit:
    cd typescript && pnpm audit --production

# ── Rust ──

# Build Rust crate
rs-build:
    cd rust && cargo build

# Test Rust crate
rs-test:
    cd rust && cargo test

# Format Rust
rs-fmt:
    cd rust && cargo fmt

# Lint Rust
rs-lint:
    cd rust && cargo clippy -- -D warnings

# ── Go ──
# Recipes live in go/Justfile. The wrappers below delegate so the
# orchestration targets ("build", "test", "test-all", "fmt", "pre-commit")
# keep working without root-level knowledge of Go commands.

# Build Go SDK (delegates to go/Justfile)
go-build:
    cd go && just build

# Test Go SDK (delegates to go/Justfile)
go-test:
    cd go && just test

# Format Go SDK (delegates to go/Justfile)
go-fmt:
    cd go && just fmt

# Lint Go SDK (delegates to go/Justfile)
go-lint:
    cd go && just lint

# Run Go coverage with the 90% gate (delegates to go/Justfile)
go-test-cover:
    cd go && just test-cover

# ── Lua ──

# Install Lua SDK dependencies into a project-local rocks tree
lua-install:
    cd lua && just install

# Run Lua SDK tests under LuaJIT
lua-test:
    cd lua && just test

# Lint the Lua SDK
lua-lint:
    cd lua && just lint

# Audit the Lua rockspec
lua-audit:
    cd lua && just audit

# Run Lua SDK coverage with a minimum threshold of 90%
lua-test-cover:
    cd lua && just test-cover

# ── Python ──
# Recipes live in python/Justfile. The wrappers below delegate so the
# orchestration targets keep working without root-level knowledge of the
# Python commands, and the 90% gate stays defined in one place.

# Install Python SDK dependencies (delegates to python/Justfile)
py-install:
    cd python && just install

# Run Python SDK tests (delegates to python/Justfile)
py-test:
    cd python && just test

# Run Python coverage with the 90% gate (delegates to python/Justfile)
py-test-cover:
    cd python && just test-cover

# Lint Python (delegates to python/Justfile)
py-lint:
    cd python && just lint

# Format Python (delegates to python/Justfile)
py-fmt:
    cd python && just fmt

# Typecheck Python (delegates to python/Justfile)
py-typecheck:
    cd python && just typecheck

# ── PHP ──
# Recipes live in php/Justfile. The wrappers below delegate so the
# orchestration targets ("build", "test", "test-all", "fmt", "pre-commit")
# keep working without root-level knowledge of PHP commands.

# Install PHP SDK dependencies (delegates to php/Justfile)
php-install:
    cd php && just install

# Validate PHP composer.json (delegates to php/Justfile)
php-build:
    cd php && just build

# Run PHP unit tests (delegates to php/Justfile)
php-test:
    cd php && just test

# Format PHP SDK (delegates to php/Justfile)
php-fmt:
    cd php && just fmt

# Lint PHP SDK (delegates to php/Justfile)
php-lint:
    cd php && just lint

# Run PHP coverage with the 90% gate (delegates to php/Justfile)
php-test-cover:
    cd php && just test-cover

# ── Ruby ──
# Recipes live in ruby/Justfile. The wrappers below keep root orchestration
# aligned with the language-local gate.

# Install Ruby SDK dependencies
rb-install:
    cd ruby && just install

# Validate Ruby gemspec
rb-build:
    cd ruby && just build

# Run Ruby unit tests
rb-test:
    cd ruby && just test

# Format Ruby SDK
rb-fmt:
    cd ruby && just fmt

# Lint Ruby SDK
rb-lint:
    cd ruby && just lint

# Audit Ruby SDK dependencies
rb-audit:
    cd ruby && just audit

# Run Ruby line and branch coverage gates
rb-test-cover:
    cd ruby && just test-cover

# ── Kotlin ──
# Recipes live in kotlin/Justfile. The wrappers below keep root orchestration
# aligned with the language-local gate.

# Install Kotlin SDK dependencies
kt-install:
    cd kotlin && just install

# Build the Kotlin SDK
kt-build:
    cd kotlin && just build

# Run Kotlin unit tests
kt-test:
    cd kotlin && just test

# Format Kotlin sources
kt-fmt:
    cd kotlin && just fmt

# Lint Kotlin SDK
kt-lint:
    cd kotlin && just lint

# Run Kotlin coverage with the >=90% line gate
kt-test-cover:
    cd kotlin && just test-cover

# ── HTML Payment Links ──

# Install HTML payment link dependencies
html-install:
    cd html && npm install

# Build HTML payment link assets (bundles JS for all server implementations)
html-build:
    cd html && npm run build

# Build HTML assets in test mode (with sourcemaps)
html-build-test:
    cd html && npm run build:test

# Run payment link E2E tests (requires Surfpool on :8899 and demo server on :3000)
html-test-e2e:
    cd html && npm run test:e2e

# ── Orchestration ──

# Build compiled SDKs
build: html-build ts-build rs-build go-build php-build rb-build

# Run all unit tests
test: ts-test rs-test go-test lua-test py-test php-test rb-test kt-test

# Run all tests including integration + coverage gates
test-all: ts-test ts-test-integration rs-test go-test-cover lua-test-cover py-test-cover php-test-cover rb-test-cover kt-test-cover

# Format everything
fmt: ts-fmt rs-fmt go-fmt py-fmt php-fmt rb-fmt kt-fmt

# Pre-commit checks
pre-commit: ts-audit ts-fmt ts-typecheck ts-test rs-fmt rs-lint rs-test go-fmt go-lint go-test-cover lua-lint lua-test-cover lua-audit py-lint py-test-cover php-lint php-test-cover rb-lint rb-audit rb-test-cover kt-fmt kt-lint kt-test-cover
