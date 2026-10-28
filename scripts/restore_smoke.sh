#!/usr/bin/env bash
# Whole-cluster restore from ONE node's backup (docs/deployment.md §10).
#
# A 3-node cluster takes traffic; one node is stopped, its data dir copied,
# and it is restarted — the stopped-node backup the guide describes. More
# traffic lands after the copy. Then every node is stopped and wiped, the
# backup goes back onto its own node id, and the other two come up EMPTY
# under their original ids with seeds pointing at the restored node.
#
# Asserts, for the restored node both leading its groups (node 1, the
# founder, which resumes leadership from its persisted vote) and following
# (node 3):
#   - the rebuilt cluster has three active nodes, each hosting every group,
#   - every node reads exactly the pre-backup message set — post-backup
#     writes are gone, and nothing else is,
#   - a write through a rebuilt node is readable from all three.
#
# Why one backup and not three: restoring each node from its own copy,
# taken at different times, was tried and does not reconcile — a node
# holding a committed vote for itself resumes leading without an election,
# so nothing ever picks the longest log (deferred.md). This script proves
# the procedure the guide gives, not that one.
#
# Usage: scripts/restore_smoke.sh [path-to-saltator-binary]
set -uo pipefail

BIN="${1:-target/release/saltator}"
if [ ! -x "$BIN" ]; then
  echo "saltator binary not found at '$BIN' (pass its path as arg 1)" >&2
  exit 2
fi
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

WORK="$(mktemp -d)"
declare -A PID=()
cleanup() { for p in "${PID[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# Loopback aliases 127.0.0.{1,2,3}; ports chosen away from the other smokes.
addr() { echo "127.0.0.$1"; }
client() { echo "http://$(addr "$1"):19508"; }

write_config() { # node seeds
  cat > "$WORK/n$1.toml" <<EOT
server_name = "restore.test"
data_dir = "$WORK/n$1"
[client]
rate_limits_enabled = false
admin_users = ["@root:restore.test"]
[node]
id = $1
advertise = "$(addr "$1"):19500"
[cluster]
seeds = [$2]
[listeners]
internal = "$(addr "$1"):19500"
client = "$(addr "$1"):19508"
federation = "$(addr "$1"):19548"
EOT
}

start_node() {
  RUST_LOG=info "$BIN" start --config "$WORK/n$1.toml" >> "$WORK/n$1.log" 2>&1 &
  PID[$1]=$!
}
stop_node() { kill "${PID[$1]}" 2>/dev/null; wait "${PID[$1]}" 2>/dev/null; unset "PID[$1]"; }
wait_ready() {
  for _ in $(seq 1 240); do
    curl -fs "$(client "$1")/_saltator/health/ready" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "node $1 never became ready"; tail -20 "$WORK/n$1.log"; return 1
}
nodes() { curl -fsS "$(client "$1")/_saltator/admin/v1/cluster/nodes" -H "Authorization: Bearer $TOKEN"; }
wait_full() { # every node hosts every group, as seen from node $1
  for _ in $(seq 1 240); do
    [ "$(nodes "$1" 2>/dev/null | jq '[.nodes[] | select((.groups | length) == 18)] | length' 2>/dev/null)" = 3 ] && return 0
    sleep 0.5
  done
  echo "cluster never converged (view from node $1):"; nodes "$1" | jq -c .; return 1
}
send() { # node body
  curl -fsS -X PUT "$(client "$1")/_matrix/client/v3/rooms/$ROOM/send/m.room.message/$2" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d "{\"msgtype\":\"m.text\",\"body\":\"$2\"}" >/dev/null
}
read_set() { # node -> sorted space-joined bodies
  curl -fsS "$(client "$1")/_matrix/client/v3/rooms/$ROOM/messages?dir=b&limit=500" \
    -H "Authorization: Bearer $TOKEN" \
    | jq -r '.chunk[] | select(.type == "m.room.message") | .content.body' | sort | tr '\n' ' '
}

run_case() { # keep = the node whose backup is restored
  local keep="$1"
  echo "=== case: restore from node $keep's backup ==="
  rm -rf "$WORK"/n[123] "$WORK"/n[123].log "$WORK"/backup.tar
  write_config 1 ""
  write_config 2 "\"$(addr 1):19500\""
  write_config 3 "\"$(addr 1):19500\""
  start_node 1; wait_ready 1 || return 1
  for n in 2 3; do
    mkdir -p "$WORK/n$n"; cp "$WORK/n1/master.key" "$WORK/n$n/"
    start_node $n; wait_ready $n || return 1
  done
  TOKEN=$(curl -fsS -X POST "$(client 1)/_matrix/client/v3/register" -H 'Content-Type: application/json' \
    -d '{"auth":{"type":"m.login.dummy"},"username":"root","password":"p"}' | jq -r .access_token)
  ROOM=$(curl -fsS -X POST "$(client 1)/_matrix/client/v3/createRoom" -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' -d '{"name":"restore"}' | jq -r .room_id)
  for i in 1 2 3 4 5; do send 1 "before$i"; done
  wait_full 1 || return 1
  local expected; expected=$(read_set 1)

  echo "--- stopped-node backup of node $keep"
  stop_node "$keep"
  tar -C "$WORK/n$keep" -cf "$WORK/backup.tar" db raft media master.key
  start_node "$keep"; wait_ready "$keep" || return 1; wait_full "$keep" || return 1
  for i in 1 2 3; do send 2 "after$i"; done
  echo "live set: $(read_set 3)"

  echo "--- disaster: stop all, wipe all"
  for n in 1 2 3; do stop_node $n; done
  rm -rf "$WORK"/n[123]
  mkdir -p "$WORK/n$keep"; tar -C "$WORK/n$keep" -xf "$WORK/backup.tar"
  # Every node seeds from the survivor — the founder too, or its empty
  # data dir would found a second cluster.
  for n in 1 2 3; do write_config $n "\"$(addr "$keep"):19500\""; done

  echo "--- restore: node $keep from backup, the others empty under their old ids"
  start_node "$keep"
  for n in 1 2 3; do
    [ "$n" = "$keep" ] && continue
    mkdir -p "$WORK/n$n"; cp "$WORK/n$keep/master.key" "$WORK/n$n/"
    start_node $n
  done
  for n in 1 2 3; do wait_ready $n || return 1; done
  wait_full "$keep" || return 1

  local pass=1
  for n in 1 2 3; do
    local got; got=$(read_set $n)
    if [ "$got" != "$expected" ]; then
      echo "FAIL: node $n reads '$got', expected '$expected'"; pass=0
    fi
  done
  local writer=1; [ "$keep" = 1 ] && writer=2
  send $writer "rebuilt"
  sleep 1
  for n in 1 2 3; do
    case "$(read_set $n)" in *rebuilt*) ;; *) echo "FAIL: post-restore write not visible on node $n"; pass=0 ;; esac
  done
  local roster; roster=$(nodes "$keep" | jq -c '[.nodes[] | {node_id, status, groups: (.groups | length)}]')
  echo "roster: $roster"
  [ "$(echo "$roster" | jq '[.[] | select(.status == "active" and .groups == 18)] | length')" = 3 ] || { echo "FAIL: roster not fully active"; pass=0; }
  for n in 1 2 3; do stop_node $n; done
  [ "$pass" = 1 ] && echo "case node $keep: PASS — restored set '$expected' on all three, post-restore write replicated"
  [ "$pass" = 1 ]
}

run_case 1 || { echo "RESULT: FAIL (leader's backup)"; exit 1; }
run_case 3 || { echo "RESULT: FAIL (follower's backup)"; exit 1; }
echo "RESULT: PASS — a whole-cluster restore from one node's backup converges, from a leader's copy and from a follower's"
