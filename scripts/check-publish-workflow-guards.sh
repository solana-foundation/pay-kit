#!/usr/bin/env bash
set -euo pipefail

# Assert two release-integrity guards on a publish workflow's OWN YAML, so a
# future edit that reopens either hole turns CI red instead of shipping it.
#
# The publish workflows (npm-publish.yml, pypi-publish.yml) are the only place
# the release token and OIDC identity are exercised, so the guards they carry
# are load-bearing:
#
#   (a) Least privilege. The workflow-level `permissions:` block must be
#       read-only (no `*: write`). Every write grant belongs on the individual
#       publish/release job, not at the top level where the whole release-gate
#       fan-out (every SDK's test/build job, run via a reusable workflow)
#       silently inherits it.
#
#   (b) Release gated on publish. Any step that creates a git tag or a GitHub
#       Release must be conditioned on the publish step actually succeeding
#       (an `if:` referencing `steps.<publish>.outcome == 'success'`), not on
#       the create-release input alone. Otherwise a dry run (publish input
#       false) still tags and releases a version that was never published.
#
# Usage: check-publish-workflow-guards.sh <workflow.yml> [<workflow.yml> ...]
#
# Parsing is done from the raw YAML text with awk keyed on indentation, so the
# check needs no yq/PyYAML in the runner. It intentionally understands only the
# narrow shape these two workflows use (top-level `permissions:` mapping; steps
# as `- name:`/`if:` list items) and fails loudly on anything it cannot classify.

if [ "$#" -lt 1 ]; then
  echo "usage: $0 <workflow.yml> [<workflow.yml> ...]" >&2
  exit 2
fi

# Step names that create durable release state and therefore must be gated on
# publish success. Matched case-insensitively against the step's `name:` value.
tag_release_names='create and push tag|create github release'

check_one() {
  local file="$1"

  if [ ! -f "$file" ]; then
    echo "FAIL: workflow not found: $file" >&2
    return 1
  fi

  awk -v file="$file" -v release_names="$tag_release_names" '
  function indent(line,   n) {
    n = 0
    while (substr(line, n + 1, 1) == " ") n++
    return n
  }
  function trim(s) {
    sub(/^[ \t]+/, "", s)
    sub(/[ \t]+$/, "", s)
    return s
  }
  # Lower-case without relying on gawk-only tolower edge cases.
  function lower(s) { return tolower(s) }

  BEGIN {
    fail = 0
    in_top_perms = 0
    # Step-block accumulator state.
    in_step = 0
    step_indent = -1
    step_name = ""
    step_if = ""
  }

  # Strip inline comments only when the # is clearly not inside a value we
  # care about. The lines under test (permissions grants, if: expressions,
  # name:) never legitimately contain a #, so a blanket strip is safe here.
  {
    raw = $0
    # Drop full-line comments and blank lines from structural consideration,
    # but keep them flowing through the step-block boundary logic below.
  }

  # ---- Guard (a): top-level permissions must be exactly contents: read ----
  # The top-level block is the only `permissions:` at column 0.
  /^permissions:[[:space:]]*$/ {
    in_top_perms = 1
    saw_contents_read = 0
    next
  }
  /^permissions:[[:space:]]*\{/ {
    # Require the reviewable block form. Accepting an arbitrary flow mapping
    # makes it too easy to hide extra read scopes next to contents: read.
    printf("FAIL[%s]: top-level permissions must use an explicit block containing only contents: read: %s\n", file, trim($0)) > "/dev/stderr"
    fail = 1
    next
  }
  /^permissions:[[:space:]]*[^[:space:]{]/ {
    # Scalar shorthand on one line, e.g. permissions: write-all / read-all.
    # (The block form and flow-mapping form above already consumed their lines,
    # so this only fires on a scalar value.) Least privilege at the workflow
    # `read-all` is still broader than least privilege: it exposes every
    # readable token scope, not only repository contents.
    printf("FAIL[%s]: scalar top-level permissions are forbidden; use only contents: read: %s\n", file, trim($0)) > "/dev/stderr"
    fail = 1
    next
  }
  in_top_perms == 1 {
    # A new column-0 key (non-space at position 1) ends the block.
    if ($0 ~ /^[^[:space:]]/) {
      if (!saw_contents_read) {
        printf("FAIL[%s]: top-level permissions must contain contents: read\n", file) > "/dev/stderr"
        fail = 1
      }
      in_top_perms = 0
      # fall through so this same line is still processed by later rules
    } else if ($0 ~ /^[[:space:]]*$/) {
      # blank line inside the block: still part of it
      next
    } else {
      # A grant line inside the top-level permissions mapping.
      grant = trim($0)
      sub(/[[:space:]]*#.*$/, "", grant)
      if (grant == "contents: read") {
        saw_contents_read = 1
      } else if (grant != "") {
        printf("FAIL[%s]: unexpected top-level permission; only contents: read is allowed: %s\n", file, grant) > "/dev/stderr"
        fail = 1
      }
      next
    }
  }

  # ---- Guard (b): tag/release steps must be gated on publish success ----
  # A step starts at a `- name:` list item. Track its indent so we know where
  # the step ends (next list item at the same indent, or a dedent).
  {
    line = $0
    ind = indent(line)
    body = trim(line)
  }

  # Detect the start of a new list item (step).
  body ~ /^- / {
    # Close any open step before starting the next one.
    if (in_step) { flush_step() }
    in_step = 1
    step_indent = ind
    step_name = ""
    step_if = ""
    # A `- name: X` opens the step with its name on the same line.
    rest = body
    sub(/^- /, "", rest)
    if (rest ~ /^name:/) {
      v = rest
      sub(/^name:[[:space:]]*/, "", v)
      step_name = strip_quotes(v)
    } else if (rest ~ /^if:/) {
      v = rest
      sub(/^if:[[:space:]]*/, "", v)
      step_if = v
    }
    next
  }

  # Within an open step, capture its name: / if: keys (indented deeper than the
  # list marker). A dedent to <= step_indent that is not a new list item ends
  # the steps region entirely.
  in_step == 1 {
    if (body == "") next
    if (ind <= step_indent && body !~ /^- /) {
      flush_step()
      in_step = 0
      step_indent = -1
      # fall through: this line may itself be structural (handled elsewhere)
    } else {
      if (body ~ /^name:/ && step_name == "") {
        v = body
        sub(/^name:[[:space:]]*/, "", v)
        step_name = strip_quotes(v)
      } else if (body ~ /^if:/ && step_if == "") {
        v = body
        sub(/^if:[[:space:]]*/, "", v)
        step_if = v
      }
      next
    }
  }

  END {
    if (in_top_perms && !saw_contents_read) {
      printf("FAIL[%s]: top-level permissions must contain contents: read\n", file) > "/dev/stderr"
      fail = 1
    }
    if (in_step) flush_step()
    if (fail) exit 1
  }

  # ---- helpers ----
  function strip_quotes(s) {
    s = trim(s)
    if (s ~ /^".*"$/) { s = substr(s, 2, length(s) - 2) }
    else if (s ~ /^'"'"'.*'"'"'$/) { s = substr(s, 2, length(s) - 2) }
    return s
  }

  function flush_step(   lname) {
    if (step_name == "") return
    lname = lower(step_name)
    if (lname ~ ("^(" release_names ")$")) {
      # This is a tag/release step: its if: must gate on publish success.
      if (step_if == "") {
        printf("FAIL[%s]: release/tag step \"%s\" has no if: gating it on publish success\n", file, step_name) > "/dev/stderr"
        fail = 1
      } else if (index(step_if, ".outcome") == 0 || index(step_if, "success") == 0) {
        printf("FAIL[%s]: release/tag step \"%s\" if: does not gate on publish step success (missing steps.<publish>.outcome == '"'"'success'"'"'): %s\n", file, step_name, step_if) > "/dev/stderr"
        fail = 1
      }
    }
  }
  ' "$file"
}

overall=0
for f in "$@"; do
  if check_one "$f"; then
    echo "OK: $f — top-level permissions read-only; tag/release steps gated on publish success"
  else
    overall=1
  fi
done

exit "$overall"
