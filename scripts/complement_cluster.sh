#!/usr/bin/env bash
# Run Complement suites against a 3-node in-container saltator cluster,
# optionally with node churn (kill -9 + restart on a cadence).
#
# Local-only by design — deliberately NOT wired into CI: multi-node
# election/failover timing under Complement load is expected to be noisy,
# and the goal is shaking out real bugs locally, not a green badge.
#
# Usage:
#   scripts/complement_cluster.sh [-c churn_secs] [go test args...]
#   scripts/complement_cluster.sh -run '^TestRoomCreate$' ./tests/csapi
#   scripts/complement_cluster.sh -c 20 -run '^TestSync$' ./tests/csapi
#
# COMPLEMENT_DIR overrides the Complement checkout (default ~/src/complement).
set -euo pipefail
cd "$(dirname "$0")/.."

CHURN=0
if [ "${1:-}" = "-c" ]; then
  CHURN="$2"
  shift 2
fi

cargo build --release -p saltator
cp target/release/saltator docker/complement/saltator
docker build -q \
  --build-arg CLUSTER_NODES=3 \
  --build-arg CHURN_INTERVAL="$CHURN" \
  -t complement-saltator:cluster docker/complement

cd "${COMPLEMENT_DIR:-$HOME/src/complement}"
COMPLEMENT_BASE_IMAGE=complement-saltator:cluster go test -count=1 "$@"
