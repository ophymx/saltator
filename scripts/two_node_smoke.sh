#!/usr/bin/env bash
# Two-node cluster smoke test (M4): start two real saltator binaries and
# verify node 2 joins node 1's cluster and ends up hosting both shard groups.
#
# Node 2 only reaches "room shards ready" + "user shard ready" if node 1's
# reconciler admitted it as a voter of the Room/0 and User/0 groups — so a
# clean startup of node 2 proves join + placement + reconciliation end to end.
#
# Usage: scripts/two_node_smoke.sh [path-to-saltator-binary]
set -uo pipefail

BIN="${1:-target/release/saltator}"
if [ ! -x "$BIN" ]; then
  echo "saltator binary not found at '$BIN' (pass its path as arg 1)" >&2
  exit 2
fi

WORK="$(mktemp -d)"
cleanup() {
  kill "${N1:-}" "${N2:-}" 2>/dev/null
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

write_config() {
  local dir="$1" id="$2" internal="$3" client="$4" fed="$5" seeds="$6"
  cat > "$dir.toml" <<EOF
server_name = "cluster.test"
data_dir = "$dir"
[client]
rate_limits_enabled = false
[node]
id = $id
advertise = "$internal"
[cluster]
seeds = [$seeds]
[listeners]
internal = "$internal"
client = "$client"
federation = "$fed"
EOF
}

mkdir -p "$WORK/n1" "$WORK/n2"
write_config "$WORK/n1" 1 "127.0.0.1:17400" "127.0.0.1:18008" "127.0.0.1:18448" ""
write_config "$WORK/n2" 2 "127.0.0.1:17401" "127.0.0.1:18009" "127.0.0.1:18449" '"127.0.0.1:17400"'

wait_up() {
  local url="$1"
  for _ in $(seq 1 120); do
    curl -fsS "$url/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

echo "=== node 1 (founder) ==="
"$BIN" start --config "$WORK/n1.toml" > "$WORK/n1.log" 2>&1 &
N1=$!
wait_up http://127.0.0.1:18008 || { echo "node 1 never came up"; tail -20 "$WORK/n1.log"; exit 1; }

# OQ-6: the cluster KEK is an operator-provisioned secret, copied to each
# node like a TLS key.
cp "$WORK/n1/master.key" "$WORK/n2/master.key"

echo "=== node 2 (joiner) ==="
"$BIN" start --config "$WORK/n2.toml" > "$WORK/n2.log" 2>&1 &
N2=$!
wait_up http://127.0.0.1:18009 || { echo "node 2 never came up"; tail -30 "$WORK/n2.log"; exit 1; }

echo "=== waiting for node 2 to host both shard groups ==="
for _ in $(seq 1 60); do
  grep -q "user shard ready" "$WORK/n2.log" && break
  sleep 0.5
done

pass=1
for marker in "metadata group ready" "room shards ready" "user shard ready"; do
  if ! grep -q "$marker" "$WORK/n2.log"; then
    echo "MISSING on node 2: '$marker'"; pass=0
  fi
done

# Leader forwarding + read-your-writes: node 1 founded every group so it
# leads them — node 2 is a follower for everything. Every write below goes
# ONLY to node 2 (no cross-node retries) and each write's effect must be
# readable from node 2 immediately after its ack.
if [ "$pass" = 1 ]; then
  echo "=== leader forwarding via node 2 (follower) ==="
  C2=http://127.0.0.1:18009
  TOKEN=$(curl -fsS -X POST "$C2/_matrix/client/v3/register" \
    -H 'Content-Type: application/json' \
    -d '{"auth":{"type":"m.login.dummy"},"username":"fwd","password":"p"}' | jq -r .access_token 2>/dev/null)
  if [ -z "$TOKEN" ] || [ "$TOKEN" = null ]; then
    echo "FORWARDING FAIL: register via follower did not succeed"; pass=0
  else
    ROOM=$(curl -fsS -X POST "$C2/_matrix/client/v3/createRoom" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d '{"preset":"public_chat"}' | jq -r .room_id 2>/dev/null)
    if [ -z "$ROOM" ] || [ "$ROOM" = null ]; then
      echo "FORWARDING FAIL: createRoom via follower did not succeed"; pass=0
    else
      ROOM_ENC=$(printf %s "$ROOM" | jq -sRr @uri)
      CODE=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
        "$C2/_matrix/client/v3/rooms/$ROOM_ENC/send/m.room.message/fwd-1" \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
        -d '{"msgtype":"m.text","body":"forwarded-write"}')
      if [ "$CODE" != 200 ]; then
        echo "FORWARDING FAIL: send via follower returned $CODE"; pass=0
      else
        # Read-your-writes: no retry loop — the ack must imply local
        # visibility on the node that served the write.
        BODY=$(curl -fsS "$C2/_matrix/client/v3/rooms/$ROOM_ENC/messages?dir=b&limit=10" \
          -H "Authorization: Bearer $TOKEN" | jq -r '.chunk[]?.content.body // empty')
        if ! printf '%s\n' "$BODY" | grep -qxF "forwarded-write"; then
          echo "READ-YOUR-WRITES FAIL: acked write not readable from the serving follower"; pass=0
        fi
      fi
    fi
  fi
fi

if [ "$pass" = 1 ]; then
  echo "reconcile on node 1:"; grep "reconciled group membership" "$WORK/n1.log" || true
  echo "RESULT: PASS — node 2 joined, hosts both shard groups, and serves forwarded writes with read-your-writes"
  exit 0
fi
echo "RESULT: FAIL"
echo "--- node 1 log ---"; tail -30 "$WORK/n1.log"
echo "--- node 2 log ---"; tail -30 "$WORK/n2.log"
exit 1
