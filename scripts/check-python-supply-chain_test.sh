#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
guard="$script_dir/check-python-supply-chain.sh"
work="$(mktemp -d 2>/dev/null || mktemp -d -t check_python_supply_chain)"

cleanup() {
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "check-python-supply-chain_test FAILED: $*" >&2
  exit 1
}

reset_fixture() {
  rm -rf "$work/.github"
  mkdir -p "$work/.github/workflows"
  cp "$repo_root/.github/workflows/python.yml" "$work/.github/workflows/python.yml"
  cp "$repo_root/.github/workflows/harness.yml" "$work/.github/workflows/harness.yml"
  cp "$repo_root/.github/workflows/pypi-publish.yml" "$work/.github/workflows/pypi-publish.yml"
}

if ! "$guard"; then
  fail "guard rejected the shipped workflows"
fi

reset_fixture
awk 'removed == 0 && /UV_MALWARE_CHECK:/ { removed = 1; next } { print }' \
  "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a frozen-sync job without malware checking"
fi

reset_fixture
sed 's/run: uv audit --frozen/run: echo audit-disabled/' \
  "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a Python workflow without the blocking audit"
fi

reset_fixture
sed 's/run: uv audit --frozen/run: echo audit-disabled/' \
  "$work/.github/workflows/harness.yml" > "$work/harness.yml"
mv "$work/harness.yml" "$work/.github/workflows/harness.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted the standalone Python harness without the blocking audit"
fi

reset_fixture
sed 's/run: uv audit --frozen/run: echo audit-disabled/' \
  "$work/.github/workflows/pypi-publish.yml" > "$work/pypi-publish.yml"
mv "$work/pypi-publish.yml" "$work/.github/workflows/pypi-publish.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted the PyPI publish workflow without the blocking audit"
fi

reset_fixture
awk '
  $0 == "  harness-python:" { in_job = 1 }
  in_job && $0 ~ /^  [A-Za-z0-9_-]+:/ && $0 != "  harness-python:" { in_job = 0 }
  in_job && $0 == "      - name: Audit locked Python dependencies" { skip = 1; next }
  skip && $0 ~ /^      - / { skip = 0 }
  skip { next }
  { print }
' "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted the Python harness matrix without the blocking audit"
fi

reset_fixture
sed 's/run: uv sync --frozen --extra dev/run: uv sync --extra dev/' \
  "$work/.github/workflows/harness.yml" > "$work/harness.yml"
mv "$work/harness.yml" "$work/.github/workflows/harness.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a non-frozen Python harness sync"
fi

reset_fixture
awk '/run: uv sync --frozen --extra dev/ && replaced == 0 {
  print "        run: |"
  print "          uv sync --extra dev"
  replaced = 1
  next
} { print }' "$work/.github/workflows/harness.yml" > "$work/harness.yml"
mv "$work/harness.yml" "$work/.github/workflows/harness.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a non-frozen Python harness sync in a block scalar"
fi

reset_fixture
awk 'replaced == 0 && /run: uv run --frozen pydoc-markdown/ {
  sub(/uv run --frozen/, "uv run")
  replaced = 1
}
{ print }' "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a non-frozen Python tool invocation"
fi

reset_fixture
awk '/- name: Install Python SDK \(frozen\)/ && added == 0 {
  print
  print "        env:"
  print "          UV_MALWARE_CHECK: \"0\""
  added = 1
  next
} { print }' "$work/.github/workflows/harness.yml" > "$work/harness.yml"
mv "$work/harness.yml" "$work/.github/workflows/harness.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a step-level malware opt-out"
fi

reset_fixture
awk '/- name: Install Python SDK \(frozen\)/ && added == 0 {
  print "      - name: Attempted runtime supply-chain override"
  print "        run: echo UV_MALWARE_CHECK=0 UV_PREVIEW_FEATURES=none >> \"$GITHUB_ENV\""
  added = 1
} { print }' "$work/.github/workflows/harness.yml" > "$work/harness.yml"
mv "$work/harness.yml" "$work/.github/workflows/harness.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a runtime supply-chain environment override"
fi

reset_fixture
awk '$0 == "  test-python:" {
  print
  print "    if: ${{ false }}"
  next
} { print }' "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a disabled Python test job"
fi

reset_fixture
awk 'replaced == 0 && /version: "0.11.26"/ {
  print "          # version: \"0.11.26\""
  replaced = 1
  next
} { print }' "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a commented-out uv runtime pin"
fi

reset_fixture
awk 'replaced == 0 && /version: "0.11.26"/ {
  print "          version: \"0.11.26\" # mutable"
  replaced = 1
  next
} { print }' "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a uv runtime pin with a trailing comment"
fi

reset_fixture
awk '/version: "0.11.26"/ && added == 0 {
  print
  print "          version: \"0.11.26\""
  added = 1
  next
} { print }' "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted duplicate uv runtime pins"
fi

reset_fixture
awk '/- name: Audit locked Python dependencies/ && added == 0 {
  print
  print "        if: ${{ false }}"
  added = 1
  next
} { print }' "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted a conditionally skipped audit"
fi

reset_fixture
awk 'replaced == 0 && /version: "0.11.26"/ { sub(/version: "0.11.26"/, "version: \"latest\""); replaced = 1 } { print }' \
  "$work/.github/workflows/python.yml" > "$work/python.yml"
mv "$work/python.yml" "$work/.github/workflows/python.yml"
if ! grep -Fq 'version: "latest"' "$work/.github/workflows/python.yml"; then
  fail "test fixture did not remove the uv runtime pin"
fi
if ROOT="$work" "$guard" >/dev/null 2>&1; then
  fail "guard accepted an unpinned uv runtime"
fi

echo "check-python-supply-chain_test: PASS"
