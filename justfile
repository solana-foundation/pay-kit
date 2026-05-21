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

# Build Go SDK
go-build:
    mkdir -p /tmp/go-build-cache
    cd go && GOCACHE=/tmp/go-build-cache go build ./...

# Test Go SDK
go-test:
    mkdir -p /tmp/go-build-cache
    cd go && GOCACHE=/tmp/go-build-cache go test ./...

# Format Go SDK
go-fmt:
    cd go && gofmt -w $$(find . -name '*.go' -type f | sort)

# Run Go coverage with a minimum threshold of 70%
go-test-cover:
    mkdir -p /tmp/go-build-cache
    cd go && GOCACHE=/tmp/go-build-cache go test ./... -coverprofile=coverage.out -covermode=atomic
    cd go && GOCACHE=/tmp/go-build-cache ./scripts/check_coverage.sh coverage.out 70

# ── Lua ──

# Run Lua SDK tests
lua-test:
    cd lua && lua tests/run.lua

# Run Lua SDK coverage with a minimum threshold of 70%
lua-test-cover:
    cd lua && rm -f ../luacov.stats.out ../luacov.report.out
    cd lua && eval "$(luarocks path)" && lua -lluacov tests/run.lua
    cd lua && eval "$(luarocks path)" && luacov
    cd lua && ./scripts/check_coverage.sh ../luacov.report.out 70

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

# Install PHP SDK dependencies
php-install:
    cd php && composer install

# Build PHP package metadata
php-build:
    cd php && composer validate

# Test PHP SDK
php-test:
    cd php && composer test

# Format PHP SDK
php-fmt:
    cd php && vendor/bin/php-cs-fixer fix --using-cache=no

# Lint PHP SDK
php-lint:
    cd php && composer run lint

# Run PHP coverage with a minimum threshold of 90%
php-test-cover:
    cd php && mkdir -p build/coverage
    cd php && composer run test:coverage

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
build: html-build ts-build rs-build go-build php-build

# Run all unit tests
test: ts-test rs-test go-test lua-test py-test php-test

# Run all tests including integration + coverage gates
test-all: ts-test ts-test-integration rs-test go-test-cover lua-test-cover py-test-cover php-test-cover

# Format everything
fmt: ts-fmt rs-fmt go-fmt py-fmt php-fmt

# Pre-commit checks
pre-commit: ts-audit ts-fmt ts-typecheck ts-test rs-fmt rs-lint rs-test go-fmt go-test-cover lua-test-cover py-lint py-test-cover php-lint php-test-cover
