#!/usr/bin/env bash
# M4 exit criterion (spec.md §12): a 3-node cluster survives kill -9 of any
# node mid-traffic with no message loss.
#
# Forms a 3-node cluster, streams client messages into a room, kill -9's the
# node that leads the room shard (the interesting case), keeps streaming
# through the election, then verifies every acknowledged message is still
# readable from a survivor and that the cluster accepted new writes after the
# failure. Writes are routed to whichever node currently accepts them (the
# leader) — the role a load balancer plays in front of a real cluster; reads
# hit any survivor (followers serve local applied state).
#
# Usage: scripts/three_node_chaos.sh [path-to-saltator-binary]
set -uo pipefail

BIN="${1:-target/release/saltator}"
if [ ! -x "$BIN" ]; then
  echo "saltator binary not found at '$BIN' (pass its path as arg 1)" >&2
  exit 2
fi
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

WORK="$(mktemp -d)"
declare -a PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

write_config() {
  local dir="$1" id="$2" internal="$3" client="$4" fed="$5" seeds="$6"
  cat > "$dir.toml" <<EOF
server_name = "cluster.test"
data_dir = "$dir"
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

wait_up() {
  for _ in $(seq 1 120); do
    curl -fsS "$1/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

# Client URLs, indexed to match node ids; entries blanked when a node is killed.
C1=http://127.0.0.1:18008
C2=http://127.0.0.1:18009
C3=http://127.0.0.1:18010
declare -a ALIVE

mkdir -p "$WORK/n1" "$WORK/n2" "$WORK/n3"
write_config "$WORK/n1" 1 "127.0.0.1:17400" "127.0.0.1:18008" "127.0.0.1:18448" ""
write_config "$WORK/n2" 2 "127.0.0.1:17401" "127.0.0.1:18009" "127.0.0.1:18449" '"127.0.0.1:17400"'
write_config "$WORK/n3" 3 "127.0.0.1:17402" "127.0.0.1:18010" "127.0.0.1:18450" '"127.0.0.1:17400"'

echo "=== node 1 (founder) ==="
"$BIN" start --config "$WORK/n1.toml" > "$WORK/n1.log" 2>&1 &
PID1=$!; PIDS+=("$PID1")
wait_up "$C1" || { echo "node 1 down"; tail -20 "$WORK/n1.log"; exit 1; }
cp "$WORK/n1/master.key" "$WORK/n2/master.key"
cp "$WORK/n1/master.key" "$WORK/n3/master.key"

echo "=== nodes 2, 3 (joiners) ==="
"$BIN" start --config "$WORK/n2.toml" > "$WORK/n2.log" 2>&1 &
PID2=$!; PIDS+=("$PID2")
"$BIN" start --config "$WORK/n3.toml" > "$WORK/n3.log" 2>&1 &
PID3=$!; PIDS+=("$PID3")
wait_up "$C2" && wait_up "$C3" || { echo "joiners down"; exit 1; }
# Wait until both joiners host the shard groups (voters), so RF=3 holds
# before we start killing.
for _ in $(seq 1 60); do
  grep -q "user shard ready" "$WORK/n2.log" && grep -q "user shard ready" "$WORK/n3.log" && break
  sleep 0.5
done
ALIVE=("$C1" "$C2" "$C3")

echo "=== register + create room (via node 1) ==="
TOKEN=$(curl -fsS -X POST "$C1/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"alice","password":"p"}' | jq -r .access_token)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "register failed"; exit 1; }
ROOM=$(curl -fsS -X POST "$C1/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"preset":"public_chat"}' | jq -r .room_id)
[ -n "$ROOM" ] && [ "$ROOM" != null ] || { echo "createRoom failed"; exit 1; }
ROOM_ENC=$(printf %s "$ROOM" | jq -sRr @uri)

SENT="$WORK/sent.txt"; : > "$SENT"
# Send one message, routed to whichever alive node accepts it (the leader).
# Retries across nodes and over time to ride out an election.
send_routed() {
  local body="$1" txn="$2" url code
  for _ in $(seq 1 80); do
    for url in "${ALIVE[@]}"; do
      [ -n "$url" ] || continue
      code=$(curl -s -o /dev/null -w '%{http_code}' -X PUT \
        "$url/_matrix/client/v3/rooms/$ROOM_ENC/send/m.room.message/$txn" \
        -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
        -d "$(jq -n --arg b "$body" '{msgtype:"m.text",body:$b}')" 2>/dev/null)
      if [ "$code" = 200 ]; then echo "$body" >> "$SENT"; return 0; fi
    done
    sleep 0.5
  done
  return 1
}

echo "=== phase 1: messages before the kill ==="
for i in $(seq 1 10); do send_routed "msg-pre-$i" "pre-$i" || { echo "pre-send $i failed"; exit 1; }; done

echo "=== kill -9 the room-shard leader ==="
# node 1 founded every group, so it leads the room shard; killing it forces a
# failover among the survivors.
kill -9 "$PID1"; ALIVE[0]=""
echo "killed node 1"

echo "=== phase 2: messages during/after the failover ==="
post=0
for i in $(seq 1 10); do
  if send_routed "msg-post-$i" "post-$i"; then post=$((post+1)); else echo "post-send $i failed"; exit 1; fi
done
echo "accepted $post messages after the kill"

echo "=== verify: every acknowledged message is readable from a survivor ==="
# Read from node 2 (a survivor). Retry briefly so its applied state settles.
missing=1
for _ in $(seq 1 40); do
  BODIES=$(curl -fsS "$C2/_matrix/client/v3/rooms/$ROOM_ENC/messages?dir=b&limit=1000" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null \
    | jq -r '.chunk[]?.content.body // empty' 2>/dev/null)
  missing=0
  while IFS= read -r want; do
    printf '%s\n' "$BODIES" | grep -qxF "$want" || { missing=1; break; }
  done < "$SENT"
  [ "$missing" = 0 ] && break
  sleep 0.5
done

total=$(wc -l < "$SENT")
if [ "$missing" = 0 ] && [ "$post" -gt 0 ]; then
  echo "RESULT: PASS — all $total acknowledged messages survived; $post accepted after kill -9"
  exit 0
fi
echo "RESULT: FAIL (missing=$missing, post-kill accepted=$post of 10)"
echo "--- readable bodies ---"; printf '%s\n' "$BODIES"
echo "--- node 2 log ---"; tail -30 "$WORK/n2.log"
echo "--- node 3 log ---"; tail -30 "$WORK/n3.log"
exit 1
