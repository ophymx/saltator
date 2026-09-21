#!/usr/bin/env bash
# Transaction-ID idempotence across a cluster: a client that retries the
# same transaction must never send twice.
#
# The spec's guarantee ("Transaction identifiers", CS API) is per device and
# per endpoint path, not per server process — a retry is a retry whichever
# node answers it, and whether or not that node has been restarted since.
# Both used to duplicate, back when the record was an in-memory map owned
# by one cs-api process:
#
#   A. retry against a DIFFERENT node of the cluster
#   B. retry against the SAME node after it restarted
#
# Neither is a corner case. (A) is what a load balancer does the moment a
# node drains or fails a health check — the event HA exists to survive. (B)
# is what a rolling upgrade does to every in-flight client.
#
# Gates the cluster job. It is the only place either property is visible:
# cs-api's suite is single-node by construction, and cluster_churn_soak.sh
# deliberately never retries across nodes.
#
# Usage: scripts/txn_dedupe_smoke.sh [path-to-saltator-binary]
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

C1=http://127.0.0.1:18018
C2=http://127.0.0.1:18019

write_config() {
  local dir="$1" id="$2" internal="$3" client="$4" fed="$5" seeds="$6"
  cat > "$dir.toml" <<EOF
server_name = "txn.test"
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
write_config "$WORK/n1" 1 "127.0.0.1:17410" "127.0.0.1:18018" "127.0.0.1:18458" ""
write_config "$WORK/n2" 2 "127.0.0.1:17411" "127.0.0.1:18019" "127.0.0.1:18459" '"127.0.0.1:17410"'

wait_up() {
  local url="$1"
  for _ in $(seq 1 120); do
    curl -fsS --max-time 30 "$url/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

start_n1() { "$BIN" start --config "$WORK/n1.toml" >> "$WORK/n1.log" 2>&1 & N1=$!; }

echo "=== node 1 (founder) ==="
start_n1
wait_up "$C1" || { echo "node 1 never came up"; tail -20 "$WORK/n1.log"; exit 1; }

# The cluster KEK is an operator-provisioned secret, copied to each node.
cp "$WORK/n1/master.key" "$WORK/n2/master.key"

echo "=== node 2 (joiner) ==="
"$BIN" start --config "$WORK/n2.toml" > "$WORK/n2.log" 2>&1 &
N2=$!
wait_up "$C2" || { echo "node 2 never came up"; tail -30 "$WORK/n2.log"; exit 1; }

for _ in $(seq 1 60); do
  grep -q "user shard ready" "$WORK/n2.log" && break
  sleep 0.5
done

TOKEN=$(curl -fsS --max-time 30 -X POST "$C1/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"txn","password":"p"}' | jq -r .access_token 2>/dev/null)
if [ -z "$TOKEN" ] || [ "$TOKEN" = null ]; then
  echo "SETUP FAIL: register did not return a token"; tail -20 "$WORK/n1.log"; exit 1
fi
ROOM=$(curl -fsS --max-time 30 -X POST "$C1/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"preset":"public_chat"}' | jq -r .room_id 2>/dev/null)
if [ -z "$ROOM" ] || [ "$ROOM" = null ]; then
  echo "SETUP FAIL: createRoom did not return a room"; tail -20 "$WORK/n1.log"; exit 1
fi
ROOM_ENC=$(printf %s "$ROOM" | jq -sRr @uri)

# Send `body` under `txn` to `node`, echoing the event ID it returns.
send() {
  local node="$1" txn="$2" body="$3"
  curl -fsS --max-time 30 -X PUT \
    "$node/_matrix/client/v3/rooms/$ROOM_ENC/send/m.room.message/$txn" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg b "$body" '{msgtype:"m.text",body:$b}')" \
    | jq -r '.event_id // empty' 2>/dev/null
}

# How many events in the room carry `body`.
count_body() {
  curl -fsS --max-time 30 \
    "$C1/_matrix/client/v3/rooms/$ROOM_ENC/messages?dir=b&limit=100" \
    -H "Authorization: Bearer $TOKEN" \
    | jq --arg b "$1" '[.chunk[]? | select(.content.body == $b)] | length' 2>/dev/null
}

# A retry is idempotent when it returns the ORIGINAL event ID and leaves
# one event behind. Both halves matter: a second event ID means the room
# has two messages, and one event ID with two events would mean the room
# disagrees with what the client was told.
check() {
  local what="$1" first="$2" retry="$3" body="$4" n
  n=$(count_body "$body")
  if [ -z "$retry" ]; then
    echo "SETUP FAIL ($what): the retry got no event ID back — an HTTP error, not a dedupe verdict"
    return 1
  fi
  if [ "$retry" != "$first" ]; then
    echo "FAIL ($what): retry minted a new event"
    echo "  first=$first retry=$retry events-with-that-body=${n:-?}"
    return 1
  fi
  if [ "${n:-0}" != 1 ]; then
    echo "FAIL ($what): retry returned the original event ID but the room holds ${n:-?} copies"
    return 1
  fi
  echo "ok ($what): retry replayed $first, one event in the room"
  return 0
}

pass=1

echo "=== A. retry against a different node ==="
A_FIRST=$(send "$C1" txn-cross-node "cross-node")
if [ -z "$A_FIRST" ]; then
  echo "SETUP FAIL: first send to node 1 returned no event ID"; exit 1
fi
A_RETRY=$(send "$C2" txn-cross-node "cross-node")
check "cross-node" "$A_FIRST" "$A_RETRY" "cross-node" || pass=0

echo "=== B. retry against the same node, across its restart ==="
B_FIRST=$(send "$C1" txn-restart "restart")
if [ -z "$B_FIRST" ]; then
  echo "SETUP FAIL: first send to node 1 returned no event ID"; exit 1
fi
kill -9 "$N1" 2>/dev/null
wait "$N1" 2>/dev/null
echo "--- node 1 killed, restarting on the same data dir ---"
start_n1
wait_up "$C1" || { echo "node 1 never came back"; tail -20 "$WORK/n1.log"; exit 1; }
B_RETRY=$(send "$C1" txn-restart "restart")
check "across-restart" "$B_FIRST" "$B_RETRY" "restart" || pass=0

if [ "$pass" = 1 ]; then
  echo "RESULT: PASS — transaction IDs are deduplicated across nodes and restarts"
  exit 0
fi
echo "RESULT: FAIL — a retried transaction was sent twice"
echo "--- node 1 log ---"; tail -20 "$WORK/n1.log"
echo "--- node 2 log ---"; tail -20 "$WORK/n2.log"
exit 1
