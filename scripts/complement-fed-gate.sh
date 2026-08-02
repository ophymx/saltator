#!/usr/bin/env bash
# Summarize Complement federation results and fail if any "must-pass" test
# regressed.
#
# Federation coverage is still growing, so unlike csapi this gate is a
# positive list (a test that MUST pass), not an allowed-to-fail list: it
# locks in the top-level tests we've gotten green so a regression fails CI,
# while the long tail of unimplemented features is free to keep failing.
# Top-level pass/fail is read from the go-test `--- PASS:/FAIL:` output
# markers — the JSON Action lines over-count subtests for this suite.
#
# Behaves identically for the per-push (-skip deferred buckets) and weekly
# unfiltered runs: no must-pass test lives in a skipped/deferred bucket.
#
# Usage: complement-fed-gate.sh <results.json> <must-pass-file> [step-summary-file]
set -euo pipefail

json="${1:?results.json path required}"
mustpass="${2:?must-pass file required}"
summary="${3:-/dev/null}"

pass=$(jq -r 'select(.Action=="pass" and .Test != null) | .Test' "$json" | wc -l)
fail=$(jq -r 'select(.Action=="fail" and .Test != null) | .Test' "$json" | wc -l)
skip=$(jq -r 'select(.Action=="skip" and .Test != null) | .Test' "$json" | wc -l)
total=$((pass + fail))

{
  echo "## Complement federation: ${pass}/${total} passed (${skip} skipped)"
  echo ""
  echo "<details><summary>Passed tests</summary>"
  echo ""
  jq -r 'select(.Action=="pass" and .Test != null) | "- `" + .Test + "`"' "$json"
  echo "</details>"
  echo "<details><summary>Failed tests</summary>"
  echo ""
  jq -r 'select(.Action=="fail" and .Test != null) | "- `" + .Test + "`"' "$json"
  echo "</details>"
} >> "$summary"

# Top-level results from the output markers (|| true: grep exits 1 when a
# run legitimately has zero passes or zero fails).
passed_top=$(grep -oE '\-\-\- PASS: Test[A-Za-z0-9_]+ \(' "$json" |
  sed -E 's/--- PASS: (Test[A-Za-z0-9_]+) \(/\1/' | sort -u || true)
failed_top=$(grep -oE '\-\-\- FAIL: Test[A-Za-z0-9_]+ \(' "$json" |
  sed -E 's/--- FAIL: (Test[A-Za-z0-9_]+) \(/\1/' | sort -u || true)

mapfile -t must < <(grep -vE '^[[:space:]]*(#|$)' "$mustpass" | sed 's/[[:space:]]*$//')

regressed=()
for t in "${must[@]}"; do
  if grep -qxF "$t" <<<"$failed_top" || ! grep -qxF "$t" <<<"$passed_top"; then
    regressed+=("$t")
  fi
done

echo "Complement federation: ${pass}/${total} passed (${skip} skipped); must-pass ${#must[@]}, regressed ${#regressed[@]}"
if [ "${#regressed[@]}" -gt 0 ]; then
  echo "::error::must-pass federation tests regressed (were green, now failing or missing):" >&2
  printf '  %s\n' "${regressed[@]}" >&2
  exit 1
fi
echo "All ${#must[@]} must-pass federation tests passed."
