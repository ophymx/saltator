#!/usr/bin/env bash
# Rolling upgrade across a schema step: N/N+1 binaries must interoperate
# (spec.md §4.4), and no migration may be proposed until every voter's
# binary supports it.
#
# Nothing else exercises this. Every other harness founds its cluster
# fresh, so the founder migrates while it is the only voter and the gate
# passes trivially with one voter to poll. The gate's actual job — holding
# a migration back until the slowest binary in the fleet catches up — only
# happens when an EXISTING cluster is upgraded, which is the one thing no
# test does.
#
# Three properties, each with a visible failure:
#
#   1. The gate HOLDS while the fleet is mixed. A migration proposed early
#      raises the stored version above what the remaining old nodes
#      support, and opening a shard refuses that outright — the old node
#      wedges. So "every node still serves" is the assertion.
#   2. The gate OPENS once every node is new: the held migrations land.
#   3. An upgraded node keeps serving BEFORE the migration lands. This is
#      the subtle one. The gate protects the log; it does not protect
#      reads. Between the moment a node starts on the new binary and the
#      moment the fleet-wide migration runs, new code is reading records
#      written in the old shape — and postcard is positional, so a record
#      that gained a field does not decode at all.
#
# Usage: scripts/rolling_upgrade_smoke.sh <old-binary> <new-binary>
set -uo pipefail

OLD_BIN="${1:?path to the OLD saltator binary required}"
NEW_BIN="${2:?path to the NEW saltator binary required}"
for b in "$OLD_BIN" "$NEW_BIN"; do
  [ -x "$b" ] || { echo "not executable: $b" >&2; exit 2; }
done

WORK="$(mktemp -d)"
declare -A PID
cleanup() {
  for n in 1 2 3; do kill "${PID[$n]:-}" 2>/dev/null; done
  wait 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

client() { echo "http://127.0.0.1:1803$1"; }

write_config() {
  local n="$1" seeds="$2"
  cat > "$WORK/n$n.toml" <<EOF
server_name = "upgrade.test"
data_dir = "$WORK/n$n"
[client]
rate_limits_enabled = false
[node]
id = $n
advertise = "127.0.0.1:1742$n"
[cluster]
seeds = [$seeds]
[listeners]
internal = "127.0.0.1:1742$n"
client = "127.0.0.1:1803$n"
federation = "127.0.0.1:1847$n"
EOF
}

wait_up() {
  local url="$1"
  for _ in $(seq 1 120); do
    curl -fsS --max-time 30 "$url/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

start_node() {
  local n="$1" bin="$2"
  "$bin" start --config "$WORK/n$n.toml" >> "$WORK/n$n.log" 2>&1 &
  PID[$n]=$!
}

# Migration lines across the whole fleet. The count is the probe: the old
# nodes finish their own startup migrations before any rolling begins, so
# any increase during the mixed window is the gate leaking.
migrations() { cat "$WORK"/n*.log 2>/dev/null | grep -c "schema migrated"; }

mkdir -p "$WORK/n1" "$WORK/n2" "$WORK/n3"
write_config 1 ""
write_config 2 '"127.0.0.1:17421"'
write_config 3 '"127.0.0.1:17421"'

echo "=== founding a 3-node cluster on the OLD binary ==="
start_node 1 "$OLD_BIN"
wait_up "$(client 1)" || { echo "node 1 never came up"; tail -20 "$WORK/n1.log"; exit 1; }
cp "$WORK/n1/master.key" "$WORK/n2/master.key"
cp "$WORK/n1/master.key" "$WORK/n3/master.key"
for n in 2 3; do
  start_node "$n" "$OLD_BIN"
  wait_up "$(client $n)" || { echo "node $n never came up"; tail -30 "$WORK/n$n.log"; exit 1; }
done

TOKEN=$(curl -fsS --max-time 30 -X POST "$(client 1)/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"roller","password":"pw-12345678"}' \
  | jq -r .access_token 2>/dev/null)
if [ -z "$TOKEN" ] || [ "$TOKEN" = null ]; then
  echo "SETUP FAIL: register on the old cluster returned no token"; tail -20 "$WORK/n1.log"; exit 1
fi
ROOM=$(curl -fsS --max-time 30 -X POST "$(client 1)/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"preset":"public_chat"}' | jq -r .room_id 2>/dev/null)
if [ -z "$ROOM" ] || [ "$ROOM" = null ]; then
  echo "SETUP FAIL: createRoom on the old cluster failed"; tail -20 "$WORK/n1.log"; exit 1
fi
ROOM_ENC=$(printf %s "$ROOM" | jq -sRr @uri)
SENT="$WORK/sent.txt"; : > "$SENT"

# An authenticated write and an authenticated read through one node. Both
# halves matter: the write proves the node can still propose, the read
# proves it can still decode what it stored. A node that cannot decode a
# record written by the older binary fails here and nowhere else.
serves() {
  local n="$1" body="$2" code
  code=$(curl -s -m 20 -o /dev/null -w '%{http_code}' -X PUT \
    "$(client "$n")/_matrix/client/v3/rooms/$ROOM_ENC/send/m.room.message/$body" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg b "$body" '{msgtype:"m.text",body:$b}')" 2>/dev/null)
  if [ "$code" != 200 ]; then
    echo "  node $n refused an authenticated write: HTTP $code"
    return 1
  fi
  echo "$body" >> "$SENT"
  local bodies
  bodies=$(curl -fsS -m 20 "$(client "$n")/_matrix/client/v3/rooms/$ROOM_ENC/messages?dir=b&limit=100" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null | jq -r '.chunk[]?.content.body // empty')
  if ! printf '%s\n' "$bodies" | grep -qxF "$body"; then
    echo "  node $n could not read back its own acked write"
    return 1
  fi
  return 0
}

# A read whose answer depends on a migration having run. The namespace
# backfill is gated with everything else, so between upgrade and migration
# an upgraded node is asking a table that has not been filled in yet — and
# reporting a taken name as free is worse than refusing to answer.
namespace_holds() {
  local n="$1" body
  body=$(curl -s -m 20 "$(client "$n")/_matrix/client/v3/register/available?username=roller" 2>/dev/null)
  if [ "$(printf '%s' "$body" | jq -r '.errcode // empty' 2>/dev/null)" != "M_USER_IN_USE" ]; then
    echo "  node $n says an already-registered name is available: $body"
    return 1
  fi
  return 0
}

all_serve() {
  # `n` must be local: the caller is iterating over it, and a for-loop here
  # would otherwise leave it at 3 and skip the caller's own gate check.
  local tag="$1" ok=0 n
  for n in 1 2 3; do
    serves "$n" "$tag-n$n" || ok=1
    namespace_holds "$n" || ok=1
  done
  return $ok
}

pass=1
echo "=== baseline: every node serves on the old binary ==="
all_serve "before" || { echo "FAIL: the old cluster was not healthy to begin with"; pass=0; }
BASE_MIGRATIONS=$(migrations)
echo "migration lines after founding: $BASE_MIGRATIONS"

for n in 1 2 3; do
  echo "=== rolling node $n onto the NEW binary ==="
  kill "${PID[$n]}" 2>/dev/null
  wait "${PID[$n]}" 2>/dev/null
  start_node "$n" "$NEW_BIN"
  wait_up "$(client $n)" || { echo "node $n never came back on the new binary"; tail -30 "$WORK/n$n.log"; exit 1; }

  if ! all_serve "roll$n"; then
    echo "FAIL: the cluster stopped serving with $n node(s) upgraded"
    pass=0
  fi

  if [ "$n" -lt 3 ]; then
    now=$(migrations)
    if [ "$now" -ne "$BASE_MIGRATIONS" ]; then
      echo "FAIL: a migration was proposed with old binaries still in the fleet ($BASE_MIGRATIONS -> $now)"
      pass=0
    else
      echo "  gate holds: no migration with $((3 - n)) old node(s) left"
    fi
  fi
done

echo "=== the fleet is uniform: the held migrations must land ==="
for _ in $(seq 1 60); do
  [ "$(migrations)" -gt "$BASE_MIGRATIONS" ] && break
  sleep 1
done
AFTER=$(migrations)
if [ "$AFTER" -le "$BASE_MIGRATIONS" ]; then
  echo "FAIL: the fleet is fully upgraded but no migration ran ($BASE_MIGRATIONS -> $AFTER)"
  pass=0
else
  echo "  gate opens: $((AFTER - BASE_MIGRATIONS)) migration step(s) applied"
  cat "$WORK"/n*.log | grep -oE "schema migrated .*shard[^ ]* [^ ]*shard=[A-Za-z]+/[0-9]+ [^ ]*to[^ ]*=[0-9]+" | tail -8
fi

echo "=== everything written across the upgrade is still readable ==="
bodies=$(curl -fsS -m 20 "$(client 1)/_matrix/client/v3/rooms/$ROOM_ENC/messages?dir=b&limit=200" \
  -H "Authorization: Bearer $TOKEN" 2>/dev/null | jq -r '.chunk[]?.content.body // empty')
while IFS= read -r want; do
  printf '%s\n' "$bodies" | grep -qxF "$want" || { echo "FAIL: lost '$want'"; pass=0; }
done < "$SENT"

if [ "$pass" = 1 ]; then
  echo "RESULT: PASS — the gate held while mixed, opened when uniform, and no node stopped serving"
  exit 0
fi
echo "RESULT: FAIL"
for n in 1 2 3; do echo "--- node $n ---"; tail -15 "$WORK/n$n.log"; done
exit 1
