#!/usr/bin/env bash
# Remote-serving smoke:
# two nodes, rf_cap_unsafe = 1, room_shards = 4 — so node 2 does NOT
# host every room group, and rooms on its unhosted shards are served
# through the remote data plane (reads over the Read RPC, writes as
# Execute intents, sync via the Subscribe stream).
#
# Node 2's boot log names its hosted count; the test then registers a
# user and creates rooms VIA NODE 2 until one lands on a shard node 2
# does not host, and asserts write + read-your-writes + /sync all work
# through the remote path. Local-only (like the cluster harness — this
# never runs in CI; the rf_cap knob is a debug override, not policy).
#
# Usage: scripts/remote_serving_smoke.sh [path-to-saltator-binary]
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
room_shards = 4
rf_cap_unsafe = 1
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
  for _ in $(seq 1 240); do
    curl -fsS --max-time 30 "$url/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

echo "=== node 1 (founder, hosts everything) ==="
"$BIN" start --config "$WORK/n1.toml" > "$WORK/n1.log" 2>&1 &
N1=$!
wait_up http://127.0.0.1:18018 || { echo "node 1 never came up"; tail -20 "$WORK/n1.log"; exit 1; }

cp "$WORK/n1/master.key" "$WORK/n2/master.key"

echo "=== node 2 (joiner under rf_cap 1: hosts a strict subset) ==="
"$BIN" start --config "$WORK/n2.toml" > "$WORK/n2.log" 2>&1 &
N2=$!
wait_up http://127.0.0.1:18019 || { echo "node 2 never came up"; tail -40 "$WORK/n2.log"; exit 1; }

# tracing's ANSI codes split field=value pairs; strip them first.
hosted=$(sed 's/\x1b\[[0-9;]*m//g' "$WORK/n2.log" | grep -o "room shards ready.*" | grep -oE "hosted=[0-9]+" | grep -oE "[0-9]+" | head -1)
echo "node 2 hosts $hosted of 4 room shards"
if [ -z "$hosted" ] || [ "$hosted" -ge 4 ]; then
  echo "FAIL: node 2 hosts every shard — rf_cap did not bite"; exit 1
fi

pass=1
C2=http://127.0.0.1:18019
TOKEN=$(curl -fsS --max-time 30 -X POST "$C2/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"remote","password":"p"}' | jq -r .access_token 2>/dev/null)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "FAIL: register via node 2"; exit 1; }

# Create rooms via node 2 until every shard has one; every room must
# round-trip regardless of which node hosts its shard.
rounds=0
for i in $(seq 1 16); do
  ROOM=$(curl -fsS --max-time 30 -X POST "$C2/_matrix/client/v3/createRoom" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"preset":"public_chat"}' | jq -r .room_id 2>/dev/null)
  if [ -z "$ROOM" ] || [ "$ROOM" = null ]; then
    echo "FAIL: createRoom #$i via node 2"; pass=0; break
  fi
  ROOM_ENC=$(printf %s "$ROOM" | jq -sRr @uri)
  EV=$(curl -fsS --max-time 30 -X PUT "$C2/_matrix/client/v3/rooms/$ROOM_ENC/send/m.room.message/t$i" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "{\"msgtype\":\"m.text\",\"body\":\"remote $i\"}" | jq -r .event_id 2>/dev/null)
  if [ -z "$EV" ] || [ "$EV" = null ]; then
    echo "FAIL: send in $ROOM via node 2"; pass=0; break
  fi
  # Read-your-writes through node 2.
  BODY=$(curl -fsS --max-time 30 "$C2/_matrix/client/v3/rooms/$ROOM_ENC/event/$(printf %s "$EV" | jq -sRr @uri)" \
    -H "Authorization: Bearer $TOKEN" | jq -r .content.body 2>/dev/null)
  if [ "$BODY" != "remote $i" ]; then
    echo "FAIL: RYW read of $EV in $ROOM got '$BODY'"; pass=0; break
  fi
  rounds=$i
done

# /sync via node 2 sees all the rooms (the long-poll holds remote
# Subscribe streams for the unhosted shards).
if [ "$pass" = 1 ]; then
  JOINED=$(curl -fsS --max-time 30 "$C2/_matrix/client/v3/sync?timeout=0" \
    -H "Authorization: Bearer $TOKEN" | jq '.rooms.join | length' 2>/dev/null)
  if [ "${JOINED:-0}" -lt "$rounds" ]; then
    echo "FAIL: sync shows $JOINED rooms, expected >= $rounds"; pass=0
  fi
fi

if [ "$pass" = 1 ]; then
  echo "RESULT: PASS — node 2 (hosting $hosted/4 room shards) created, wrote, read, and synced rooms across every shard"
else
  echo "RESULT: FAIL"
  echo "--- node 1 log ---"; tail -30 "$WORK/n1.log"
  echo "--- node 2 log ---"; tail -30 "$WORK/n2.log"
  exit 1
fi
