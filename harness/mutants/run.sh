#!/usr/bin/env bash
# Local driver for the x402 exact-verifier "guard coverage meter" (radar L4).
#
# Mutation testing = the objective check that the test suite actually KILLS
# injected bugs. A surviving ("MISSED") mutant is a real defect the tests would
# let through — a CI blind spot, not a style nit.
#
# Scope, features, and timeouts are defined in rust/.cargo/mutants.toml.
#
# Usage:
#   harness/mutants/run.sh                 # full sweep of the configured scope
#   harness/mutants/run.sh --list          # just list the mutants, run nothing
#   harness/mutants/run.sh --file <path>   # override scope to a single file
#
# Requires cargo-mutants:  cargo install cargo-mutants
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root/rust"

if ! command -v cargo-mutants >/dev/null 2>&1; then
  echo "cargo-mutants not found. Install with: cargo install cargo-mutants" >&2
  exit 127
fi

exec cargo mutants -j 4 --timeout 120 "$@"
