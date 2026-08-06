#!/usr/bin/env bash
# Summarize Complement federation results and fail the build on any
# regression.
#
# Flipped 2026-08-06 from a positive must-pass list to an allowed-to-fail
# list (like csapi): federation coverage reached ~90/96 top-level, so the
# natural encoding is the short list of known failures — and a brand-new
# upstream test that fails is caught by default instead of being invisible
# to a positive list.
#
# The gate fails on any LEAF failure not in the allowlist (a parent test
# that fails only because of an allowed child is ignored). An allowlist
# entry that PASSES is flagged stale; a merely-absent entry is not, since
# the per-push run `-skip`s the v7-only knock bucket (filtered tests emit
# no JSON events) that the weekly unfiltered run lets fail. It also fails
# outright if zero tests passed (a broken image/deployer, not a protocol
# gap).
#
# Usage: complement-fed-gate.sh <results.json> <allowlist-file> [step-summary-file]
set -euo pipefail

json="${1:?results.json path required}"
allowlist="${2:?allowlist file required}"
summary="${3:-/dev/null}"

pass=$(jq -r 'select(.Action=="pass" and .Test != null) | .Test' "$json" | wc -l)
fail=$(jq -r 'select(.Action=="fail" and .Test != null) | .Test' "$json" | wc -l)
skip=$(jq -r 'select(.Action=="skip" and .Test != null) | .Test' "$json" | wc -l)
total=$((pass + fail))

echo "Complement federation: ${pass}/${total} passed (${skip} skipped)"
jq -r 'select(.Action=="fail" and .Test != null) | "FAILED: " + .Test' "$json"
{
  echo "## Complement federation: ${pass}/${total} passed (${skip} skipped)"
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
mapfile -t passes < <(jq -r 'select(.Action=="pass" and .Test != null) | .Test' "$json" | sort -u)
mapfile -t allow < <(grep -vE '^[[:space:]]*(#|$)' "$allowlist" | sed 's/[[:space:]]*$//')

in_list() { local x="$1" a; for a in "${allow[@]}"; do [ "$a" = "$x" ] && return 0; done; return 1; }
# Leaf = a failing test with no failing descendant.
is_leaf() { local t="$1" s; for s in "${fails[@]}"; do case "$s" in "$t"/*) return 1 ;; esac; done; return 0; }

unexpected=()
for t in "${fails[@]}"; do
  is_leaf "$t" || continue
  in_list "$t" || unexpected+=("$t")
done

# Surface stale allowlist entries: listed yet PASSING. (Merely-absent is
# not stale — `-skip`-filtered tests emit no JSON events at all, and the
# per-push run skips the v7-only knock bucket that the weekly unfiltered
# run lets fail.)
for a in "${allow[@]}"; do
  if printf '%s\n' "${passes[@]}" | grep -qxF "$a"; then
    echo "::warning::allowlisted federation test now passing; remove from ${allowlist}: ${a}"
  fi
done

if [ "${#unexpected[@]}" -gt 0 ]; then
  echo "::error::unexpected Complement federation failures (not in ${allowlist}):"
  printf '  %s\n' "${unexpected[@]}" >&2
  exit 1
fi
echo "No unexpected federation failures (${#allow[@]} allowlisted)."
