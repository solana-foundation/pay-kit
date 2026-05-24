set shell := ["bash", "-uc"]

default:
    @just --list

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

# Run Go coverage with the 70% gate (delegates to go/Justfile)
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

# Install Python SDK dependencies
py-install:
    cd python && pip install -e '.[dev]'

# Run Python SDK tests
py-test:
    cd python && pytest

# Run Python coverage with a minimum threshold of 85%
py-test-cover:
    cd python && pytest --cov --cov-report=term --cov-fail-under=85

# Lint Python
py-lint:
    cd python && ruff check src/ tests/

# Format Python
py-fmt:
    cd python && ruff format src/ tests/

# Typecheck Python
py-typecheck:
    cd python && pyright

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

# Install Kotlin deps (resolved on first Gradle invocation; no-op recipe).
kt-install:
    cd kotlin && gradle --version

# Build the Kotlin SDK
kt-build:
    cd kotlin && gradle build -x test

# Run Kotlin unit tests
kt-test:
    cd kotlin && gradle test

# Format Kotlin sources (Kotlin Coding Conventions; ktlint when present)
kt-fmt:
    cd kotlin && (command -v ktlint >/dev/null && ktlint -F src/**/*.kt) || echo "ktlint not installed; relying on Kotlin Coding Conventions"

# Lint Kotlin (detekt when present)
kt-lint:
    cd kotlin && (command -v detekt >/dev/null && detekt) || gradle compileKotlin

# Coverage with ≥90% line gate (enforced by jacocoTestCoverageVerification)
kt-test-cover:
    cd kotlin && gradle test jacocoTestCoverageVerification

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
