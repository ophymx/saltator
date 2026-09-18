#!/usr/bin/env bash
# Dead-node re-placement smoke (phase 3, docs/design-room-sharding-phase2.md):
# a crashed node's room-group replicas re-place automatically. Four nodes,
# 8 room shards, replication_factor = 3, dead_node_grace_secs = 5. After
# the cluster converges (each group on its rendezvous top-3 of 4) and every
# shard holds seeded rooms, node 4 is killed -9. The metadata leader's
# failure detector marks it unreachable after the grace period, placement
# re-ranks every group it hosted onto the three survivors (add-learner →
# checkpoint/raft catch-up → promote), and the cluster runs at full RF
# again. Node 4 then restarts: the detector restores it to Active and
# rendezvous hands its original groups back.
#
# RF 3 is the point, not a convenience: at RF 2 a dead replica IS lost
# quorum (2-of-2), and no placement change can reconfigure a group that
# cannot commit — re-placement heals redundancy only where a quorum
# survives.
#
# Asserts:
#   - the detector marks node 4 unreachable (leader log), never sooner
#     than the grace period,
#   - every group node 4 hosted is re-gained by exactly the survivor the
#     old placement excluded (gain count == node 4's hosted count),
#   - during the outage: every seeded room reads, writes, and syncs
#     through all three survivors,
#   - after restart: the detector restores node 4, it re-hosts its
#     original group count, and all four nodes serve every room.
# Local-only, never CI (like the other cluster smokes).
#
# Usage: scripts/dead_node_smoke.sh [path-to-saltator-binary]
set -uo pipefail

BIN="${1:-target/release/saltator}"
if [ ! -x "$BIN" ]; then
  echo "saltator binary not found at '$BIN' (pass its path as arg 1)" >&2
  exit 2
fi

WORK="$(mktemp -d)"
cleanup() {
  kill "${N1:-}" "${N2:-}" "${N3:-}" "${N4:-}" 2>/dev/null
  wait 2>/dev/null
  if [ "${KEEP:-0}" = 1 ]; then
    echo "KEEP=1: logs left in $WORK"
  else
    rm -rf "$WORK"
  fi
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
replication_factor = 3
dead_node_grace_secs = 5
[listeners]
internal = "$internal"
client = "$client"
federation = "$fed"
EOF
}

mkdir -p "$WORK/n1" "$WORK/n2" "$WORK/n3" "$WORK/n4"
write_config "$WORK/n1" 1 "127.0.0.1:17450" "127.0.0.1:18058" "127.0.0.1:18498" ""
write_config "$WORK/n2" 2 "127.0.0.1:17451" "127.0.0.1:18059" "127.0.0.1:18499" '"127.0.0.1:17450"'
write_config "$WORK/n3" 3 "127.0.0.1:17452" "127.0.0.1:18060" "127.0.0.1:18500" '"127.0.0.1:17450"'
write_config "$WORK/n4" 4 "127.0.0.1:17453" "127.0.0.1:18061" "127.0.0.1:18501" '"127.0.0.1:17450"'

wait_up() {
  local url="$1"
  for _ in $(seq 1 240); do
    curl -fsS --max-time 30 "$url/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

C1=http://127.0.0.1:18058
C2=http://127.0.0.1:18059
C3=http://127.0.0.1:18060
C4=http://127.0.0.1:18061

hosted_boot() { # $1 = log file: the boot-time hosted count
  strip_ansi "$1" | grep -o "room shards ready.*" | grep -oE "hosted=[0-9]+" | grep -oE "[0-9]+" | head -1
}
gains() { # $1 = log file: runtime group gains
  strip_ansi "$1" | grep -c "lifecycle: group hosted"
}
standdowns() { # $1 = log file
  strip_ansi "$1" | grep -c "lifecycle: local replica removed"
}

echo "=== nodes 1-3 (founder + joiners; 3 nodes == RF 3: all host all) ==="
"$BIN" start --config "$WORK/n1.toml" > "$WORK/n1.log" 2>&1 &
N1=$!
wait_up $C1 || { echo "node 1 never came up"; tail -20 "$WORK/n1.log"; exit 1; }
cp "$WORK/n1/master.key" "$WORK/n2/master.key"
cp "$WORK/n1/master.key" "$WORK/n3/master.key"
cp "$WORK/n1/master.key" "$WORK/n4/master.key"
"$BIN" start --config "$WORK/n2.toml" > "$WORK/n2.log" 2>&1 &
N2=$!
wait_up $C2 || { echo "node 2 never came up"; tail -40 "$WORK/n2.log"; exit 1; }
"$BIN" start --config "$WORK/n3.toml" > "$WORK/n3.log" 2>&1 &
N3=$!
wait_up $C3 || { echo "node 3 never came up"; tail -40 "$WORK/n3.log"; exit 1; }

echo "=== node 4 joins: each group re-ranks to its top-3 of 4 ==="
"$BIN" start --config "$WORK/n4.toml" > "$WORK/n4.log" 2>&1 &
N4=$!
wait_up $C4 || { echo "node 4 never came up"; tail -40 "$WORK/n4.log"; exit 1; }

H4=$(hosted_boot "$WORK/n4.log")
echo "node 4 booted hosting ${H4:-?} of 8 room shards"

echo "=== waiting for join movement to converge ==="
converged=0
for _ in $(seq 1 90); do
  R=$(( $(standdowns "$WORK/n1.log") + $(standdowns "$WORK/n2.log") + $(standdowns "$WORK/n3.log") ))
  G4=$(gains "$WORK/n4.log")
  N4HOSTS=$(( ${H4:-0} + G4 ))
  # Every group excludes exactly one of 4 nodes: survivors' stand-downs
  # must equal the groups node 4 ended up hosting.
  if [ "$N4HOSTS" -gt 0 ] && [ "$R" -eq "$N4HOSTS" ]; then
    converged=1; break
  fi
  sleep 2
done
if [ "$converged" != 1 ]; then
  echo "FAIL: join movement never converged (stand-downs ${R:-?} vs node-4 hostings ${N4HOSTS:-?})"
  for n in 1 2 3 4; do
    echo "--- node $n lifecycle lines ---"
    strip_ansi "$WORK/n$n.log" | grep -iE "lifecycle|reconciled" | tail -6
  done
  exit 1
fi
echo "converged: node 4 hosts $N4HOSTS group(s); survivors stood down $R"

TOKEN=$(curl -fsS --max-time 30 -X POST "$C1/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"deadnode","password":"p"}' | jq -r .access_token)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "FAIL: register"; exit 1; }

# Rooms + a message on every shard.
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

# Baselines before the kill: gains are cumulative log greps.
B1=$(gains "$WORK/n1.log"); B2=$(gains "$WORK/n2.log"); B3=$(gains "$WORK/n3.log")

echo "=== kill -9 node 4 (hosts $N4HOSTS groups) at $(date -u +%H:%M:%S) ==="
kill -9 "$N4" 2>/dev/null
wait "$N4" 2>/dev/null
N4=

echo "=== waiting for the failure detector (grace 5s) ==="
marked=0
for _ in $(seq 1 120); do
  for log in "$WORK/n1.log" "$WORK/n2.log" "$WORK/n3.log"; do
    # grep -c, not -q: -q's early exit SIGPIPEs strip_ansi, and under
    # pipefail that reads as "no match" however present the line is.
    if [ "$(strip_ansi "$log" | grep -c "liveness: node unreachable")" -gt 0 ]; then marked=1; fi
  done
  [ "$marked" = 1 ] && break
  sleep 1
done
if [ "$marked" != 1 ]; then
  echo "FAIL: node 4 was never marked unreachable"
  for n in 1 2 3; do
    echo "--- node $n liveness lines ---"
    strip_ansi "$WORK/n$n.log" | grep -i "liveness" | tail -4
  done
  exit 1
fi
echo "node 4 marked unreachable at $(date -u +%H:%M:%S)"

echo "=== waiting for re-placement (survivors regain node 4's groups) ==="
healed=0
for _ in $(seq 1 90); do
  REGAINED=$(( $(gains "$WORK/n1.log") + $(gains "$WORK/n2.log") + $(gains "$WORK/n3.log") - B1 - B2 - B3 ))
  if [ "$REGAINED" -eq "$N4HOSTS" ]; then healed=1; break; fi
  sleep 2
done
if [ "$healed" != 1 ]; then
  echo "FAIL: re-placement never converged (regained ${REGAINED:-?} of $N4HOSTS)"
  for n in 1 2 3; do
    echo "--- node $n lifecycle lines ---"
    strip_ansi "$WORK/n$n.log" | grep -iE "lifecycle|liveness|reconciled" | tail -8
  done
  exit 1
fi
echo "survivors re-gained all $N4HOSTS group(s); full RF restored"

# A send with a short retry window: right at the re-placement boundary a
# freshly promoted group may still be electing/retargeting its leader,
# and a one-shot 500 there is churn, not breakage. Steady-state failure
# (all attempts) is still a FAIL.
send_with_retry() { # $1=base url $2=room-enc $3=txn $4=body; echoes event id
  local url="$1" enc="$2" txn="$3" body="$4" resp= ev=
  for _ in 1 2 3 4 5; do
    resp=$(curl -sS --max-time 30 -X PUT "$url/_matrix/client/v3/rooms/$enc/send/m.room.message/$txn" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "{\"msgtype\":\"m.text\",\"body\":\"$body\"}" 2>/dev/null)
    ev=$(printf %s "$resp" | jq -r .event_id 2>/dev/null)
    if [ -n "$ev" ] && [ "$ev" != null ]; then echo "$ev"; return 0; fi
    sleep 2
  done
  echo "last response: $resp" >&2
  return 1
}

dump_errors() {
  for n in 1 2 3; do
    echo "--- node $n recent warn/error lines ---"
    strip_ansi "$WORK/n$n.log" | grep -iE "warn|error" | tail -10
  done
}

pass=1
# During the outage: every seeded room reads, writes, and syncs via all
# three survivors.
SURVIVORS=("$C1" "$C2" "$C3")
for idx in "${!ROOMS[@]}"; do
  ROOM=${ROOMS[$idx]}; EV=${EVENTS[$idx]}
  ENC=$(printf %s "$ROOM" | jq -sRr @uri)
  EVE=$(printf %s "$EV" | jq -sRr @uri)
  for C in "${SURVIVORS[@]}"; do
    BODY=$(curl -fsS --max-time 30 "$C/_matrix/client/v3/rooms/$ENC/event/$EVE" \
      -H "Authorization: Bearer $TOKEN" | jq -r .content.body 2>/dev/null)
    if [ "$BODY" != "seed $((idx + 1))" ]; then
      echo "FAIL: outage read $ROOM via $C: got '$BODY'"; pass=0
    fi
  done
  C=${SURVIVORS[$((idx % 3))]}
  if ! send_with_retry "$C" "$ENC" "out$idx" "outage $idx" >/dev/null; then
    echo "FAIL: outage send in $ROOM via $C"; pass=0
  fi
done
if [ "$pass" = 1 ]; then
  for C in "${SURVIVORS[@]}"; do
    JOINED=$(curl -fsS --max-time 30 "$C/_matrix/client/v3/sync?timeout=0" \
      -H "Authorization: Bearer $TOKEN" | jq '.rooms.join | length' 2>/dev/null)
    if [ "${JOINED:-0}" -lt "${#ROOMS[@]}" ]; then
      echo "FAIL: outage sync via $C shows $JOINED rooms, expected ${#ROOMS[@]}"; pass=0
    fi
  done
fi
[ "$pass" = 1 ] || { echo "RESULT: FAIL (outage serving)"; dump_errors; exit 1; }
echo "outage serving: all rooms read, write, and sync via every survivor"

echo "=== node 4 restarts ==="
"$BIN" start --config "$WORK/n4.toml" > "$WORK/n4-restart.log" 2>&1 &
N4=$!
wait_up $C4 || { echo "node 4 never came back"; tail -40 "$WORK/n4-restart.log"; exit 1; }

recovered=0
for _ in $(seq 1 60); do
  for log in "$WORK/n1.log" "$WORK/n2.log" "$WORK/n3.log"; do
    if [ "$(strip_ansi "$log" | grep -c "liveness: node recovered")" -gt 0 ]; then recovered=1; fi
  done
  [ "$recovered" = 1 ] && break
  sleep 1
done
if [ "$recovered" != 1 ]; then
  echo "FAIL: node 4 was never restored to Active"
  for n in 1 2 3; do
    strip_ansi "$WORK/n$n.log" | grep -i "liveness" | tail -4
  done
  exit 1
fi
echo "node 4 restored to Active"

echo "=== waiting for node 4 to re-host its groups ==="
back=0
for _ in $(seq 1 90); do
  H4B=$(hosted_boot "$WORK/n4-restart.log"); H4B=${H4B:-0}
  G4B=$(gains "$WORK/n4-restart.log")
  if [ $((H4B + G4B)) -ge "$N4HOSTS" ]; then back=1; break; fi
  sleep 2
done
if [ "$back" != 1 ]; then
  echo "FAIL: node 4 re-hosts $((${H4B:-0} + ${G4B:-0})) of $N4HOSTS group(s)"
  strip_ansi "$WORK/n4-restart.log" | grep -iE "lifecycle|reconciled" | tail -8
  exit 1
fi
echo "node 4 re-hosts $((H4B + G4B)) group(s)"

# Final: all four nodes serve every room, including the outage writes.
NODES=("$C1" "$C2" "$C3" "$C4")
for idx in "${!ROOMS[@]}"; do
  ROOM=${ROOMS[$idx]}
  ENC=$(printf %s "$ROOM" | jq -sRr @uri)
  C=${NODES[$((idx % 4))]}
  EV=$(send_with_retry "$C" "$ENC" "post$idx" "post $idx")
  if [ -z "$EV" ] || [ "$EV" = null ]; then
    echo "FAIL: post-recovery send in $ROOM via $C"; pass=0; break
  fi
  BODY=$(curl -fsS --max-time 30 "$C/_matrix/client/v3/rooms/$ENC/event/$(printf %s "$EV" | jq -sRr @uri)" \
    -H "Authorization: Bearer $TOKEN" | jq -r .content.body 2>/dev/null)
  if [ "$BODY" != "post $idx" ]; then
    echo "FAIL: post-recovery RYW in $ROOM via $C got '$BODY'"; pass=0; break
  fi
done
if [ "$pass" = 1 ]; then
  for C in "${NODES[@]}"; do
    JOINED=$(curl -fsS --max-time 30 "$C/_matrix/client/v3/sync?timeout=0" \
      -H "Authorization: Bearer $TOKEN" | jq '.rooms.join | length' 2>/dev/null)
    if [ "${JOINED:-0}" -lt "${#ROOMS[@]}" ]; then
      echo "FAIL: final sync via $C shows $JOINED rooms, expected ${#ROOMS[@]}"; pass=0
    fi
  done
fi

if [ "$pass" = 1 ]; then
  echo "RESULT: PASS — node 4's $N4HOSTS group(s) re-placed onto survivors after kill -9, full serving throughout, and node 4 recovered its placement on return"
else
  echo "RESULT: FAIL"
  for n in 1 2 3; do
    echo "--- node $n log ---"; strip_ansi "$WORK/n$n.log" | tail -20
  done
  echo "--- node 4 restart log ---"; strip_ansi "$WORK/n4-restart.log" | tail -20
  exit 1
fi
