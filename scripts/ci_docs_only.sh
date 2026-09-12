#!/usr/bin/env sh
# CI diff classifier: is this push/PR docs-only (every changed file under
# docs/ or ending in .md)? Emits `docs_only=true|false` to $GITHUB_OUTPUT
# (and stdout). The ci.yml `changes` job runs this; the three root jobs
# gate on its output, and everything expensive skips through the `needs`
# chain.
#
# Inputs (env): EVENT (github.event_name), PR_BASE (the PR base sha),
# PUSH_BEFORE (the pre-push head). Fails open: schedule runs, branch
# creations, and anything unclassifiable report docs_only=false so the
# full pipeline runs.
#
# Pure POSIX sh and case-matching on purpose — no grep: local grep may be
# ugrep, whose -q -v exit codes differ from GNU's, and this script is
# also run locally by its own tests.
set -eu

case "${EVENT:-}" in
  pull_request) base="${PR_BASE:-}" ;;
  push)         base="${PUSH_BEFORE:-}" ;;
  *)            base="" ;;
esac

docs_only=false
if [ -n "$base" ] && git cat-file -e "$base" 2>/dev/null; then
  # Three-dot: diff against the merge base, so a stale PR base or a
  # fast-forward push both classify only OUR changes.
  files=$(git diff --name-only "$base...HEAD")
  if [ -n "$files" ]; then
    docs_only=true
    while IFS= read -r f; do
      case "$f" in
        docs/*|*.md) ;;
        *) docs_only=false; break ;;
      esac
    done <<EOF
$files
EOF
  fi
  printf 'changed files:\n%s\n' "$files"
fi

echo "docs_only=$docs_only" >> "${GITHUB_OUTPUT:-/dev/null}"
echo "docs_only=$docs_only"
