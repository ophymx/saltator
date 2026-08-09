#!/usr/bin/env bash
# Cluster churn soak (local hardening, not CI): a 3-node cluster under
# continuous client traffic while nodes are repeatedly kill -9'd and
# restarted — including whichever node leads — then a convergence audit.
#
# Verifies, per churn cycle and at the end:
#   1. No acknowledged message is ever lost.
#   2. The cluster keeps accepting writes through every failover.
#   3. A restarted node catches back up (its own client port serves the
#      full message set).
#   4. A NEVER-SEEN 4th node added at the end converges to the same set —
#      the "add a node" half of drop/add churn.
#
# Usage: scripts/cluster_churn_soak.sh [binary] [cycles]
set -uo pipefail

BIN="${1:-target/release/saltator}"
CYCLES="${2:-5}"
if [ ! -x "$BIN" ]; then
  echo "saltator binary not found at '$BIN' (pass its path as arg 1)" >&2
  exit 2
fi
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

WORK="$(mktemp -d)"
declare -A PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$WORK"; }
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

start_node() {
  local i="$1"
  "$BIN" start --config "$WORK/n$i.toml" >> "$WORK/n$i.log" 2>&1 &
  PIDS[$i]=$!
}

wait_up() {
  for _ in $(seq 1 240); do
    curl -fsS "$1/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

CLIENT=(unused http://127.0.0.1:18008 http://127.0.0.1:18009 http://127.0.0.1:18010 http://127.0.0.1:18011)

mkdir -p "$WORK"/n{1,2,3,4}
write_config "$WORK/n1" 1 "127.0.0.1:17400" "127.0.0.1:18008" "127.0.0.1:18448" ""
write_config "$WORK/n2" 2 "127.0.0.1:17401" "127.0.0.1:18009" "127.0.0.1:18449" '"127.0.0.1:17400"'
write_config "$WORK/n3" 3 "127.0.0.1:17402" "127.0.0.1:18010" "127.0.0.1:18450" '"127.0.0.1:17400"'
# n4 seeds through n2: by add time node 1 may be down; any live member works.
write_config "$WORK/n4" 4 "127.0.0.1:17403" "127.0.0.1:18011" "127.0.0.1:18451" '"127.0.0.1:17401"'

echo "=== forming 3-node cluster ==="
start_node 1
wait_up "${CLIENT[1]}" || { echo "node 1 down"; tail -20 "$WORK/n1.log"; exit 1; }
cp "$WORK/n1/master.key" "$WORK/n2/master.key"
cp "$WORK/n1/master.key" "$WORK/n3/master.key"
cp "$WORK/n1/master.key" "$WORK/n4/master.key"
start_node 2
start_node 3
wait_up "${CLIENT[2]}" && wait_up "${CLIENT[3]}" || { echo "joiners down"; exit 1; }
for _ in $(seq 1 60); do
  grep -q "user shard ready" "$WORK/n2.log" && grep -q "user shard ready" "$WORK/n3.log" && break
  sleep 0.5
done

echo "=== register + create room ==="
TOKEN=$(curl -fsS -X POST "${CLIENT[1]}/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"soak","password":"p"}' | jq -r .access_token)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "register failed"; exit 1; }
ROOM=$(curl -fsS -X POST "${CLIENT[1]}/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"preset":"public_chat"}' | jq -r .room_id)
[ -n "$ROOM" ] && [ "$ROOM" != null ] || { echo "createRoom failed"; exit 1; }
ROOM_ENC=$(printf %s "$ROOM" | jq -sRr @uri)

SENT="$WORK/sent.txt"; : > "$SENT"
# One message to ONE alive node — no cross-node retries: with leader
# forwarding, any single live node must accept the write (riding out an
# election is the server's job, not the client's).
send_one() {
  local body="$1" txn="$2" node="$3" code
  for _ in $(seq 1 40); do
    code=$(curl -s -m 15 -o /dev/null -w '%{http_code}' -X PUT \
      "${CLIENT[$node]}/_matrix/client/v3/rooms/$ROOM_ENC/send/m.room.message/$txn" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "$(jq -n --arg b "$body" '{msgtype:"m.text",body:$b}')" 2>/dev/null)
    if [ "$code" = 200 ]; then echo "$body" >> "$SENT"; return 0; fi
    sleep 0.5
  done
  echo "send '$body' via node $node never acked (last code $code)"
  return 1
}

# All acked messages must be readable from `node`.
verify_node() {
  local node="$1" tries="${2:-60}" bodies missing
  for _ in $(seq 1 "$tries"); do
    bodies=$(curl -fsS -m 10 "${CLIENT[$node]}/_matrix/client/v3/rooms/$ROOM_ENC/messages?dir=b&limit=1000" \
      -H "Authorization: Bearer $TOKEN" 2>/dev/null \
      | jq -r '.chunk[]?.content.body // empty' 2>/dev/null)
    missing=0
    while IFS= read -r want; do
      printf '%s\n' "$bodies" | grep -qxF "$want" || { missing=1; break; }
    done < "$SENT"
    [ "$missing" = 0 ] && return 0
    sleep 0.5
  done
  echo "node $node is missing acked messages (wanted $(wc -l < "$SENT"))"
  return 1
}

alive=(1 2 3)
seq_no=0
for cycle in $(seq 1 "$CYCLES"); do
  echo "=== cycle $cycle/$CYCLES ==="
  # Traffic before the kill, spread across live nodes.
  for i in 1 2 3; do
    seq_no=$((seq_no+1))
    node=${alive[$((seq_no % ${#alive[@]}))]}
    send_one "msg-$cycle-pre-$i" "t$seq_no" "$node" || exit 1
  done

  victim=${alive[$((RANDOM % ${#alive[@]}))]}
  echo "--- kill -9 node $victim ---"
  kill -9 "${PIDS[$victim]}" 2>/dev/null
  survivors=(); for n in 1 2 3; do [ "$n" != "$victim" ] && survivors+=("$n"); done
  alive=("${survivors[@]}")

  # Traffic through the failover, each write pinned to a single survivor.
  for i in 1 2 3 4; do
    seq_no=$((seq_no+1))
    node=${alive[$((seq_no % ${#alive[@]}))]}
    send_one "msg-$cycle-during-$i" "t$seq_no" "$node" || { echo "write refused after killing node $victim"; exit 1; }
  done

  echo "--- restart node $victim ---"
  start_node "$victim"
  wait_up "${CLIENT[$victim]}" || { echo "node $victim never came back"; tail -20 "$WORK/n$victim.log"; exit 1; }
  alive=(1 2 3)

  # The restarted node must catch up and serve the full set itself.
  verify_node "$victim" || { echo "restarted node $victim did not converge"; tail -20 "$WORK/n$victim.log"; exit 1; }
  echo "cycle $cycle: node $victim recovered and converged ($(wc -l < "$SENT") msgs)"
done

echo "=== final: every node serves every acked message ==="
for n in 1 2 3; do
  verify_node "$n" || exit 1
done

echo "=== add node 4 (never seen any traffic) ==="
start_node 4
wait_up "${CLIENT[4]}" || { echo "node 4 down"; tail -30 "$WORK/n4.log"; exit 1; }
for _ in $(seq 1 120); do
  grep -q "user shard ready" "$WORK/n4.log" && break
  sleep 0.5
done
# It must converge to the full set AND serve a fresh write.
verify_node 4 120 || { echo "late joiner did not converge"; tail -30 "$WORK/n4.log"; exit 1; }
seq_no=$((seq_no+1))
send_one "msg-via-late-joiner" "t$seq_no" 4 || exit 1
verify_node 4 || exit 1

total=$(wc -l < "$SENT")
echo "RESULT: PASS — $total acked messages survived $CYCLES kill/restart cycles; late joiner converged and serves writes"
