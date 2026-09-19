#!/usr/bin/env bash
# Shard-movement smoke:
# node 1 founds a 4-shard cluster under rf_cap_unsafe = 1 and fills every
# shard with rooms. Node 2 then joins — the placement re-assigns each
# group to exactly ONE node, so a subset MOVES: node 1's reconciler
# catches node 2 up (Raft snapshot), promotes it, demotes itself, and
# node 1's lifecycle driver swaps the router slot to remote, stands the
# local group down, and deletes its data.
#
# Asserts: every pre-move room (and its pre-move message) stays readable
# through BOTH nodes; new writes into moved rooms work through node 1
# (the remote intent path); node 1's log records the stand-down.
# Local-only, never CI (rf_cap is a debug override, not policy).
#
# Usage: scripts/shard_move_smoke.sh [path-to-saltator-binary]
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

strip_ansi() { sed 's/\x1b\[[0-9;]*m//g' "$1"; }

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
room_shards = 4
rf_cap_unsafe = 1
[listeners]
internal = "$internal"
client = "$client"
federation = "$fed"
EOF
}

mkdir -p "$WORK/n1" "$WORK/n2"
write_config "$WORK/n1" 1 "127.0.0.1:17430" "127.0.0.1:18038" "127.0.0.1:18478" ""
write_config "$WORK/n2" 2 "127.0.0.1:17431" "127.0.0.1:18039" "127.0.0.1:18479" '"127.0.0.1:17430"'

wait_up() {
  local url="$1"
  for _ in $(seq 1 240); do
    curl -fsS --max-time 30 "$url/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

C1=http://127.0.0.1:18038
C2=http://127.0.0.1:18039

echo "=== node 1 (founder, hosts all 4 shards) ==="
"$BIN" start --config "$WORK/n1.toml" > "$WORK/n1.log" 2>&1 &
N1=$!
wait_up $C1 || { echo "node 1 never came up"; tail -20 "$WORK/n1.log"; exit 1; }

TOKEN=$(curl -fsS --max-time 30 -X POST "$C1/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"mover","password":"p"}' | jq -r .access_token)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "FAIL: register"; exit 1; }

# Rooms + a message on every shard, all before node 2 exists.
ROOMS=()
EVENTS=()
for i in $(seq 1 12); do
  ROOM=$(curl -fsS --max-time 30 -X POST "$C1/_matrix/client/v3/createRoom" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"preset":"public_chat"}' | jq -r .room_id)
  [ -n "$ROOM" ] && [ "$ROOM" != null ] || { echo "FAIL: pre-move createRoom #$i"; exit 1; }
  ENC=$(printf %s "$ROOM" | jq -sRr @uri)
  EV=$(curl -fsS --max-time 30 -X PUT "$C1/_matrix/client/v3/rooms/$ENC/send/m.room.message/pre$i" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "{\"msgtype\":\"m.text\",\"body\":\"pre-move $i\"}" | jq -r .event_id)
  [ -n "$EV" ] && [ "$EV" != null ] || { echo "FAIL: pre-move send #$i"; exit 1; }
  ROOMS+=("$ROOM"); EVENTS+=("$EV")
done
echo "seeded ${#ROOMS[@]} rooms across the shards"

cp "$WORK/n1/master.key" "$WORK/n2/master.key"

echo "=== node 2 joins: placement re-assigns each group to one node ==="
"$BIN" start --config "$WORK/n2.toml" > "$WORK/n2.log" 2>&1 &
N2=$!
wait_up $C2 || { echo "node 2 never came up"; tail -40 "$WORK/n2.log"; exit 1; }

echo "=== waiting for node 1 to stand down its moved groups ==="
moved=""
for _ in $(seq 1 60); do
  moved=$(strip_ansi "$WORK/n1.log" | grep -c "lifecycle: local replica removed" || true)
  [ "${moved:-0}" -ge 1 ] && break
  sleep 2
done
if [ "${moved:-0}" -lt 1 ]; then
  echo "FAIL: node 1 never stood down any group"
  echo "--- node 1 lifecycle lines ---"
  strip_ansi "$WORK/n1.log" | grep -i lifecycle | tail -10
  exit 1
fi
echo "node 1 stood down $moved group(s)"

# 2b part 2: the moved state must have arrived via the bulk checkpoint
# pre-seed, not a leader-shipped raft snapshot.
if ! strip_ansi "$WORK/n2.log" | grep -q "pre-seeded room shard from checkpoint"; then
  echo "FAIL: node 2 never pre-seeded from a checkpoint"
  strip_ansi "$WORK/n2.log" | grep -iE "pre-seed|snapshot" | tail -6
  exit 1
fi
echo "node 2 pre-seeded its gained shard(s) from a checkpoint"

pass=1
# Every pre-move room + message must survive, read through BOTH nodes.
for idx in "${!ROOMS[@]}"; do
  ROOM=${ROOMS[$idx]}; EV=${EVENTS[$idx]}
  ENC=$(printf %s "$ROOM" | jq -sRr @uri)
  EVE=$(printf %s "$EV" | jq -sRr @uri)
  for C in "$C1" "$C2"; do
    BODY=$(curl -fsS --max-time 30 "$C/_matrix/client/v3/rooms/$ENC/event/$EVE" \
      -H "Authorization: Bearer $TOKEN" | jq -r .content.body 2>/dev/null)
    if [ "$BODY" != "pre-move $((idx + 1))" ]; then
      echo "FAIL: $ROOM via $C: got '$BODY'"; pass=0
    fi
  done
done

# New writes through node 1 into every room — moved rooms take the
# remote intent path.
if [ "$pass" = 1 ]; then
  for idx in "${!ROOMS[@]}"; do
    ROOM=${ROOMS[$idx]}
    ENC=$(printf %s "$ROOM" | jq -sRr @uri)
    EV=$(curl -fsS --max-time 30 -X PUT "$C1/_matrix/client/v3/rooms/$ENC/send/m.room.message/post$idx" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "{\"msgtype\":\"m.text\",\"body\":\"post-move $idx\"}" | jq -r .event_id 2>/dev/null)
    if [ -z "$EV" ] || [ "$EV" = null ]; then
      echo "FAIL: post-move send in $ROOM via node 1"; pass=0; break
    fi
  done
fi

if [ "$pass" = 1 ]; then
  echo "RESULT: PASS — $moved group(s) moved node 1 → node 2 with zero data loss; both nodes serve every room; post-move writes flow through the remote path"
else
  echo "RESULT: FAIL"
  echo "--- node 1 log ---"; strip_ansi "$WORK/n1.log" | tail -30
  echo "--- node 2 log ---"; strip_ansi "$WORK/n2.log" | tail -30
  exit 1
fi
