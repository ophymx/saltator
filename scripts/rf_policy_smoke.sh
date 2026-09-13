#!/usr/bin/env bash
# RF-policy smoke (phase 3, docs/design-room-sharding-phase2.md): the
# replication factor is REAL policy now — no rf_cap_unsafe debug knob.
# Node 1 founds an 8-shard cluster with replication_factor = 2 and fills
# every shard with rooms. Node 2 joins (2 nodes <= RF: both host
# everything). Node 3 joins — the placement re-ranks each room group to
# its rendezvous top-2 of 3, so a subset MOVES: the excluded incumbent
# stands its replica down, node 3 gains its placed groups (pre-seeded
# over the bulk checkpoint channel), and every node serves every room —
# hosted or remote. The user/fed-out groups keep the every-node floor.
#
# Asserts, after convergence:
#   - stand-downs on nodes 1/2 balance node 3's gains (each room group
#     ends at exactly RF=2 replicas),
#   - node 3 pre-seeded at least one gained group from a checkpoint,
#   - every pre-move room + message reads back through ALL THREE nodes,
#   - new writes land in every room via every node (remote intent path),
#   - /sync via every node shows every room.
# Local-only, never CI (like the other cluster smokes).
#
# Usage: scripts/rf_policy_smoke.sh [path-to-saltator-binary]
set -uo pipefail

BIN="${1:-target/release/saltator}"
if [ ! -x "$BIN" ]; then
  echo "saltator binary not found at '$BIN' (pass its path as arg 1)" >&2
  exit 2
fi

WORK="$(mktemp -d)"
cleanup() {
  kill "${N1:-}" "${N2:-}" "${N3:-}" 2>/dev/null
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
room_shards = 8
replication_factor = 2
[listeners]
internal = "$internal"
client = "$client"
federation = "$fed"
EOF
}

mkdir -p "$WORK/n1" "$WORK/n2" "$WORK/n3"
write_config "$WORK/n1" 1 "127.0.0.1:17440" "127.0.0.1:18048" "127.0.0.1:18488" ""
write_config "$WORK/n2" 2 "127.0.0.1:17441" "127.0.0.1:18049" "127.0.0.1:18489" '"127.0.0.1:17440"'
write_config "$WORK/n3" 3 "127.0.0.1:17442" "127.0.0.1:18050" "127.0.0.1:18490" '"127.0.0.1:17440"'

wait_up() {
  local url="$1"
  for _ in $(seq 1 240); do
    curl -fsS --max-time 30 "$url/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

C1=http://127.0.0.1:18048
C2=http://127.0.0.1:18049
C3=http://127.0.0.1:18050

echo "=== node 1 (founder, RF 2, hosts all 8 shards) ==="
"$BIN" start --config "$WORK/n1.toml" > "$WORK/n1.log" 2>&1 &
N1=$!
wait_up $C1 || { echo "node 1 never came up"; tail -20 "$WORK/n1.log"; exit 1; }

TOKEN=$(curl -fsS --max-time 30 -X POST "$C1/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"policy","password":"p"}' | jq -r .access_token)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "FAIL: register"; exit 1; }

# Rooms + a message on every shard, before the cluster grows.
ROOMS=()
EVENTS=()
for i in $(seq 1 16); do
  ROOM=$(curl -fsS --max-time 30 -X POST "$C1/_matrix/client/v3/createRoom" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"preset":"public_chat"}' | jq -r .room_id)
  [ -n "$ROOM" ] && [ "$ROOM" != null ] || { echo "FAIL: seed createRoom #$i"; exit 1; }
  ENC=$(printf %s "$ROOM" | jq -sRr @uri)
  EV=$(curl -fsS --max-time 30 -X PUT "$C1/_matrix/client/v3/rooms/$ENC/send/m.room.message/pre$i" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "{\"msgtype\":\"m.text\",\"body\":\"seed $i\"}" | jq -r .event_id)
  [ -n "$EV" ] && [ "$EV" != null ] || { echo "FAIL: seed send #$i"; exit 1; }
  ROOMS+=("$ROOM"); EVENTS+=("$EV")
done
echo "seeded ${#ROOMS[@]} rooms across the shards"

cp "$WORK/n1/master.key" "$WORK/n2/master.key"
cp "$WORK/n1/master.key" "$WORK/n3/master.key"

echo "=== node 2 joins (2 nodes <= RF 2: both host everything) ==="
"$BIN" start --config "$WORK/n2.toml" > "$WORK/n2.log" 2>&1 &
N2=$!
wait_up $C2 || { echo "node 2 never came up"; tail -40 "$WORK/n2.log"; exit 1; }

echo "=== node 3 joins: each group re-ranks to its top-2 of 3 ==="
"$BIN" start --config "$WORK/n3.toml" > "$WORK/n3.log" 2>&1 &
N3=$!
wait_up $C3 || { echo "node 3 never came up"; tail -40 "$WORK/n3.log"; exit 1; }

# Node 3's boot-time hosted count (it may also gain more at runtime if
# its boot raced the placement write).
H3=$(strip_ansi "$WORK/n3.log" | grep -o "room shards ready.*" | grep -oE "hosted=[0-9]+" | grep -oE "[0-9]+" | head -1)
echo "node 3 booted hosting ${H3:-?} of 8 room shards"

echo "=== waiting for movement to converge (stand-downs == node 3 gains) ==="
converged=0
for _ in $(seq 1 90); do
  R1=$(strip_ansi "$WORK/n1.log" | grep -c "lifecycle: local replica removed")
  R2=$(strip_ansi "$WORK/n2.log" | grep -c "lifecycle: local replica removed")
  G3=$(strip_ansi "$WORK/n3.log" | grep -c "lifecycle: group hosted")
  if [ $((R1 + R2)) -gt 0 ] && [ $((R1 + R2)) -eq $((${H3:-0} + G3)) ]; then
    converged=1; break
  fi
  sleep 2
done
R1=${R1:-0}; R2=${R2:-0}; G3=${G3:-0}
echo "node 1 stood down $R1, node 2 stood down $R2, node 3 hosts ${H3:-0}+$G3"
if [ "$converged" != 1 ]; then
  echo "FAIL: movement never converged (stand-downs $((R1 + R2)) vs node-3 hostings $((${H3:-0} + G3)))"
  for n in 1 2 3; do
    echo "--- node $n lifecycle/reconcile lines ---"
    strip_ansi "$WORK/n$n.log" | grep -iE "lifecycle|reconciled" | tail -8
  done
  exit 1
fi

# Gained state must arrive via the bulk checkpoint pre-seed (2b part 2).
if ! strip_ansi "$WORK/n3.log" | grep -q "pre-seeded room shard from checkpoint"; then
  echo "FAIL: node 3 never pre-seeded from a checkpoint"
  strip_ansi "$WORK/n3.log" | grep -iE "pre-seed|snapshot" | tail -6
  exit 1
fi
echo "node 3 pre-seeded its gained shard(s) from a checkpoint"

pass=1
# Every seeded room + message must survive, read through ALL THREE nodes
# (each node now hosts only ~2/3 of the room groups).
for idx in "${!ROOMS[@]}"; do
  ROOM=${ROOMS[$idx]}; EV=${EVENTS[$idx]}
  ENC=$(printf %s "$ROOM" | jq -sRr @uri)
  EVE=$(printf %s "$EV" | jq -sRr @uri)
  for C in "$C1" "$C2" "$C3"; do
    BODY=$(curl -fsS --max-time 30 "$C/_matrix/client/v3/rooms/$ENC/event/$EVE" \
      -H "Authorization: Bearer $TOKEN" | jq -r .content.body 2>/dev/null)
    if [ "$BODY" != "seed $((idx + 1))" ]; then
      echo "FAIL: $ROOM via $C: got '$BODY'"; pass=0
    fi
  done
done

# New writes through every node into every room — unhosted shards take
# the remote intent path, and read-your-writes must hold at the writer.
if [ "$pass" = 1 ]; then
  NODES=("$C1" "$C2" "$C3")
  for idx in "${!ROOMS[@]}"; do
    ROOM=${ROOMS[$idx]}
    C=${NODES[$((idx % 3))]}
    ENC=$(printf %s "$ROOM" | jq -sRr @uri)
    EV=$(curl -fsS --max-time 30 -X PUT "$C/_matrix/client/v3/rooms/$ENC/send/m.room.message/post$idx" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "{\"msgtype\":\"m.text\",\"body\":\"post $idx\"}" | jq -r .event_id 2>/dev/null)
    if [ -z "$EV" ] || [ "$EV" = null ]; then
      echo "FAIL: post-move send in $ROOM via $C"; pass=0; break
    fi
    BODY=$(curl -fsS --max-time 30 "$C/_matrix/client/v3/rooms/$ENC/event/$(printf %s "$EV" | jq -sRr @uri)" \
      -H "Authorization: Bearer $TOKEN" | jq -r .content.body 2>/dev/null)
    if [ "$BODY" != "post $idx" ]; then
      echo "FAIL: post-move RYW in $ROOM via $C got '$BODY'"; pass=0; break
    fi
  done
fi

# /sync via every node sees every room (remote Subscribe streams for
# the shards a node does not host).
if [ "$pass" = 1 ]; then
  for C in "$C1" "$C2" "$C3"; do
    JOINED=$(curl -fsS --max-time 30 "$C/_matrix/client/v3/sync?timeout=0" \
      -H "Authorization: Bearer $TOKEN" | jq '.rooms.join | length' 2>/dev/null)
    if [ "${JOINED:-0}" -lt "${#ROOMS[@]}" ]; then
      echo "FAIL: sync via $C shows $JOINED rooms, expected ${#ROOMS[@]}"; pass=0
    fi
  done
fi

if [ "$pass" = 1 ]; then
  echo "RESULT: PASS — RF 2 as real policy: $((R1 + R2)) group(s) moved to node 3 with zero data loss; all three nodes create, write, read, and sync every room"
else
  echo "RESULT: FAIL"
  for n in 1 2 3; do
    echo "--- node $n log ---"; strip_ansi "$WORK/n$n.log" | tail -30
  done
  exit 1
fi
