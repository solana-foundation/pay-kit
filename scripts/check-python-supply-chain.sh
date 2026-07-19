#!/usr/bin/env bash

set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
UV_VERSION="0.11.26"
fail=0

fail_check() {
  echo "FAIL [python-supply-chain]: $*" >&2
  fail=1
}

job_policy() {
  local file="$1"
  local job="$2"
  awk -v target="  ${job}:" '
    function scan_uv_sync(line) {
      sub(/^[[:space:]]+/, "", line)
      if (line ~ /^#/ || line ~ /^[[:space:]]*$/) return
      if (line ~ /(^|[[:space:]])uv[[:space:]]+sync([[:space:]]|$)/ &&
          line !~ /(^|[[:space:]])--frozen([[:space:]]|$)/) {
        unfrozen = 1
      }
    }
    function emit() {
      print "malware=" malware
      print "preview=" preview
      print "misplaced=" misplaced
      print "unfrozen=" unfrozen
    }
    $0 == target { in_job = 1; next }
    in_job && $0 ~ /^  [A-Za-z0-9_-]+:/ { emit(); exit }
    in_job && $0 ~ /^    env:[[:space:]]*$/ { in_env = 1; next }
    in_job && in_env && $0 ~ /^    [A-Za-z0-9_-]+:/ { in_env = 0 }
    in_job && /UV_MALWARE_CHECK:/ {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (in_env && line == "UV_MALWARE_CHECK: \"1\"") malware = 1
      else misplaced = 1
    }
    in_job && /UV_PREVIEW_FEATURES:/ {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (in_env && line == "UV_PREVIEW_FEATURES: \"audit-command,malware-check\"") preview = 1
      else misplaced = 1
    }
    in_job { scan_uv_sync($0) }
    END { if (in_job) emit() }
  ' "$file"
}

check_job_policy() {
  local file="$1"
  local job="$2"
  local policy
  policy="$(job_policy "$file" "$job")"

  if [ -z "$policy" ]; then
    fail_check "missing job ${job} in ${file#$ROOT/}"
    return
  fi
  if ! grep -Fq 'malware=1' <<<"$policy"; then
    fail_check "${file#$ROOT/}:${job} does not enable UV_MALWARE_CHECK"
  fi
  if ! grep -Fq 'preview=1' <<<"$policy"; then
    fail_check "${file#$ROOT/}:${job} does not opt into the pinned preview features"
  fi
  if grep -Fq 'misplaced=1' <<<"$policy"; then
    fail_check "${file#$ROOT/}:${job} overrides supply-chain env outside its job-level env"
  fi
  if grep -Fq 'unfrozen=1' <<<"$policy"; then
    fail_check "${file#$ROOT/}:${job} contains a non-frozen uv sync"
  fi
}

audit_step_block() {
  local file="$1"
  local job="$2"
  awk -v target="  ${job}:" '
    $0 == target { in_job = 1; next }
    in_job && $0 ~ /^  [A-Za-z0-9_-]+:/ { exit }
    in_job && $0 ~ /^    steps:[[:space:]]*$/ { in_steps = 1; next }
    in_steps && $0 ~ /^      - / {
      if (in_audit) exit
      in_audit = ($0 == "      - name: Audit locked Python dependencies")
      next
    }
    in_audit { print }
  ' "$file"
}

check_blocking_audit() {
  local file="$1"
  local job="$2"
  local block
  block="$(audit_step_block "$file" "$job")"

  if [ -z "$block" ]; then
    fail_check "${file#$ROOT/}:${job} is missing the named audit step"
    return
  fi
  if ! grep -Eq '^        run:[[:space:]]+uv audit --frozen[[:space:]]*$' <<<"$block"; then
    fail_check "${file#$ROOT/}:${job} audit step is not exactly uv audit --frozen"
  fi
  if grep -Eq '^        (if|continue-on-error):' <<<"$block"; then
    fail_check "${file#$ROOT/}:${job} audit step is conditional or non-blocking"
  fi
}

while IFS= read -r workflow; do
  if ! awk -v expected="$UV_VERSION" '
    function finish() {
      if (in_setup) {
        if (version_count != 1 || invalid_version) {
          printf "setup-uv step at line %d must contain exactly one version: \"%s\"\n", start, expected > "/dev/stderr"
          failed = 1
        }
      }
      in_setup = 0
      version_count = 0
      invalid_version = 0
    }
    {
      if (in_setup && $0 ~ /^[[:space:]]*-[[:space:]]+[A-Za-z_][A-Za-z0-9_-]*:/) finish()
      if ($0 ~ /^[[:space:]]*-[[:space:]]+uses:[[:space:]]*astral-sh\/setup-uv@/) {
        in_setup = 1
        start = NR
      }
      if (in_setup && $0 ~ /^[[:space:]]+version:[[:space:]]*/) {
        line = $0
        sub(/^[[:space:]]+/, "", line)
        version_count++
        if (line != "version: \"" expected "\"") invalid_version = 1
      }
    }
    END {
      finish()
      exit failed
    }
  ' "$workflow"; then
    fail_check "${workflow#$ROOT/} has an unpinned setup-uv runtime"
  fi
done < <(find "$ROOT/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) -print)

python_workflow="$ROOT/.github/workflows/python.yml"
harness_workflow="$ROOT/.github/workflows/harness.yml"
pypi_workflow="$ROOT/.github/workflows/pypi-publish.yml"

check_job_policy "$python_workflow" test-python
check_job_policy "$python_workflow" harness-python
check_job_policy "$harness_workflow" python
check_job_policy "$pypi_workflow" publish

check_blocking_audit "$python_workflow" test-python
check_blocking_audit "$harness_workflow" python
check_blocking_audit "$pypi_workflow" publish

if [ "$fail" -ne 0 ]; then
  exit 1
fi

echo "python-supply-chain: OK"
