#!/usr/bin/env bash
# Summarize Complement csapi results and fail the build on any regression.
#
# The gate fails on any LEAF failure not in the allowlist (a parent test
# that fails only because of an allowed child is ignored). It also warns
# about allowlist entries that no longer fail (stale), and fails outright
# if zero tests passed (a broken image/deployer, not a protocol gap).
#
# Usage: complement-csapi-gate.sh <results.json> <allowlist-file> [step-summary-file]
set -euo pipefail

json="${1:?results.json path required}"
allowlist="${2:?allowlist file required}"
summary="${3:-/dev/null}"

pass=$(jq -r 'select(.Action=="pass" and .Test != null) | .Test' "$json" | wc -l)
fail=$(jq -r 'select(.Action=="fail" and .Test != null) | .Test' "$json" | wc -l)
skip=$(jq -r 'select(.Action=="skip" and .Test != null) | .Test' "$json" | wc -l)
total=$((pass + fail))

# stdout (the step summary is not reachable through the API, and the JSON
# stream no longer hits the step log).
echo "Complement csapi: ${pass}/${total} passed (${skip} skipped)"
jq -r 'select(.Action=="fail" and .Test != null) | "FAILED: " + .Test' "$json"
{
  echo "## Complement csapi: ${pass}/${total} passed (${skip} skipped)"
  echo ""
  echo "<details><summary>Failed tests</summary>"
  echo ""
  jq -r 'select(.Action=="fail" and .Test != null) | "- `" + .Test + "`"' "$json"
  echo "</details>"
} >> "$summary"

# Zero passes means the image or deployer is broken — fail loudly.
if [ "$pass" -eq 0 ]; then
  echo "no Complement tests passed; deployment is broken" >&2
  exit 1
fi

mapfile -t fails < <(jq -r 'select(.Action=="fail" and .Test != null) | .Test' "$json" | sort -u)
mapfile -t allow < <(grep -vE '^[[:space:]]*(#|$)' "$allowlist" | sed 's/[[:space:]]*$//')

in_list() { local x="$1" a; for a in "${allow[@]}"; do [ "$a" = "$x" ] && return 0; done; return 1; }
# Leaf = a failing test with no failing descendant.
is_leaf() { local t="$1" s; for s in "${fails[@]}"; do case "$s" in "$t"/*) return 1 ;; esac; done; return 0; }

unexpected=()
for t in "${fails[@]}"; do
  is_leaf "$t" || continue
  in_list "$t" || unexpected+=("$t")
done

# Surface stale allowlist entries (listed but no longer failing).
for a in "${allow[@]}"; do
  printf '%s\n' "${fails[@]}" | grep -qxF "$a" ||
    echo "::warning::allowlisted csapi test no longer failing; remove from ${allowlist}: ${a}"
done

if [ "${#unexpected[@]}" -gt 0 ]; then
  echo "::error::unexpected Complement csapi failures (not in ${allowlist}):"
  printf '  %s\n' "${unexpected[@]}" >&2
  exit 1
fi
echo "No unexpected csapi failures (${#allow[@]} allowlisted)."
