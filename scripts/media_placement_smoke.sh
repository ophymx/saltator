#!/usr/bin/env bash
# Media blob placement smoke (phase 3, docs/design-room-sharding-phase2.md
# "Media blob placement"): media bytes place by rendezvous over the blob
# id, replicate to a majority before an upload acks, fall through to the
# replica set on a local miss, and re-place when the topology moves.
#
# Blobs are the last data in the system that was not placed: before this,
# an upload landed on whichever node answered it and a download from any
# other node was a 404. The shape of the test follows the three
# mechanisms:
#
#   A. THREE NODES, RF 3 — every node holds every blob. Upload on node 1;
#      all three nodes must have the bytes on disk (replication), and all
#      three must serve them (correctness).
#   B. NODE 4 JOINS — each blob re-ranks to a top-3 of 4. Node 4 pulls
#      the blobs that rank onto it, the displaced node evicts its copy,
#      and every blob converges to exactly 3 copies while all four nodes
#      keep serving it (read-through covers the node that no longer has
#      it). Eviction is the dangerous half: it must happen, and it must
#      never leave a blob below its replica count.
#   C. KILL -9 — a holder dies. Survivors keep serving every blob, and
#      the reconciler heals back to 3 copies among the three survivors.
#   D. RESTART — the node returns, re-ranks, and pulls its share back.
#
# Also asserted throughout: bytes are byte-identical (sha256), uploads to
# a NON-founding node work the same way, and thumbnails generate on a node
# that does not hold the blob (proving the read-through reaches the
# thumbnailer, not just the download route).
#
# Local-only, never CI (like the other cluster smokes).
#
# Usage: scripts/media_placement_smoke.sh [path-to-saltator-binary]
set -uo pipefail

BIN="${1:-target/release/saltator}"
if [ ! -x "$BIN" ]; then
  echo "saltator binary not found at '$BIN' (pass its path as arg 1)" >&2
  exit 2
fi
for tool in jq curl openssl basenc; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

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
write_config "$WORK/n1" 1 "127.0.0.1:17470" "127.0.0.1:18070" "127.0.0.1:18510" ""
write_config "$WORK/n2" 2 "127.0.0.1:17471" "127.0.0.1:18071" "127.0.0.1:18511" '"127.0.0.1:17470"'
write_config "$WORK/n3" 3 "127.0.0.1:17472" "127.0.0.1:18072" "127.0.0.1:18512" '"127.0.0.1:17470"'
write_config "$WORK/n4" 4 "127.0.0.1:17473" "127.0.0.1:18073" "127.0.0.1:18513" '"127.0.0.1:17470"'

C1=http://127.0.0.1:18070
C2=http://127.0.0.1:18071
C3=http://127.0.0.1:18072
C4=http://127.0.0.1:18073
ALL=("$C1" "$C2" "$C3" "$C4")

wait_up() {
  local url="$1"
  for _ in $(seq 1 240); do
    curl -fsS --max-time 30 "$url/_matrix/client/versions" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  return 1
}

# The content-addressed blob id the server will mint for a file: URL-safe
# unpadded base64 of its SHA-256 (saltator_media::MediaStore::store). The
# mxc media id is a random UPLOAD id and is deliberately not this — the
# script needs the blob id to look at what is on each node's disk.
blob_id_of() {
  openssl dgst -sha256 -binary "$1" | basenc --base64url | tr -d '=' | tr -d '\n'
}

# How many of the given node dirs hold this blob.
copies_of() { # $1 = blob id, rest = node dirs
  local blob="$1"; shift
  local n=0
  for dir in "$@"; do
    [ -f "$dir/media/blobs/${blob:0:2}/$blob" ] && n=$((n + 1))
  done
  echo "$n"
}
holders_of() { # $1 = blob id, rest = node dirs -> prints the dirs that have it
  local blob="$1"; shift
  for dir in "$@"; do
    [ -f "$dir/media/blobs/${blob:0:2}/$blob" ] && echo "$dir"
  done
}

# Wait until every blob has exactly $want copies among the given dirs.
wait_for_copies() { # $1 = want, $2 = tries, rest = node dirs
  local want="$1" tries="$2"; shift 2
  local dirs=("$@")
  for _ in $(seq 1 "$tries"); do
    local ok=1
    for i in "${!BLOBS[@]}"; do
      local c
      c=$(copies_of "${BLOBS[$i]}" "${dirs[@]}")
      [ "$c" -eq "$want" ] || ok=0
    done
    [ "$ok" = 1 ] && return 0
    sleep 2
  done
  return 1
}

report_copies() { # rest = node dirs
  for i in "${!BLOBS[@]}"; do
    printf '  blob %d (%s…): %s copies\n' "$i" "${BLOBS[$i]:0:8}" \
      "$(copies_of "${BLOBS[$i]}" "$@")"
  done
}

# Download a blob through a node and check the bytes match the original.
check_download() { # $1 = client url, $2 = media id, $3 = source file
  local out="$WORK/dl.bin"
  curl -fsS --max-time 60 -o "$out" \
    "$1/_matrix/client/v1/media/download/cluster.test/$2" \
    -H "Authorization: Bearer $TOKEN" 2>/dev/null || return 1
  cmp -s "$out" "$3"
}

pass=1
fail() { echo "FAIL: $*"; pass=0; }

# ---------------------------------------------------------------- phase A
echo "=== nodes 1-3 (3 nodes == RF 3: every node holds every blob) ==="
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

TOKEN=$(curl -fsS --max-time 30 -X POST "$C1/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' \
  -d '{"auth":{"type":"m.login.dummy"},"username":"mediaplacement","password":"p"}' \
  | jq -r .access_token)
[ -n "$TOKEN" ] && [ "$TOKEN" != null ] || { echo "FAIL: register"; exit 1; }

# Eight blobs: enough that a 3-of-4 rendezvous split is visible rather
# than luck. Each is a couple of MiB so the transfer really chunks.
BLOBS=()
MEDIA=()
FILES=()
UPLOAD_NODE=()
echo "=== uploading 8 blobs (7 via node 1, 1 via node 2) ==="
for i in $(seq 0 7); do
  f="$WORK/blob$i.bin"
  # Distinct, incompressible-ish content per blob.
  head -c $((2 * 1024 * 1024)) /dev/urandom > "$f"
  printf 'saltator-media-placement-blob-%d' "$i" >> "$f"
  FILES+=("$f")

  # One upload goes to a non-founding node: replication must work in
  # both directions, not just outward from the founder.
  if [ "$i" = 7 ]; then C="$C2"; else C="$C1"; fi
  UPLOAD_NODE+=("$C")
  MID=$(curl -fsS --max-time 120 -X POST "$C/_matrix/media/v3/upload?filename=blob$i.bin" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/octet-stream' \
    --data-binary "@$f" | jq -r .content_uri | sed 's|mxc://cluster.test/||')
  [ -n "$MID" ] && [ "$MID" != null ] || { echo "FAIL: upload #$i via $C"; exit 1; }
  MEDIA+=("$MID")
  BLOBS+=("$(blob_id_of "$f")")
done
# A real PNG too: the blobs above are random bytes and will not
# thumbnail, and the thumbnail path is the one that proves the
# read-through lives inside MediaStore::read rather than in the download
# route. It is uploaded HERE, with everything else, on purpose — see the
# thumbnail step at the end.
PNG="$WORK/pic.png"
openssl base64 -d -out "$PNG" <<'B64'
iVBORw0KGgoAAAANSUhEUgAAAAgAAAAIAQMAAAD+wSzIAAAABlBMVEX///+/v7+jQ3Y5AAAADklE
QVQI12P4AIX8EAgALgAD/aNpbtEAAAAASUVORK5CYII=
B64
PIC_MID=$(curl -fsS --max-time 60 -X POST "$C1/_matrix/media/v3/upload?filename=pic.png" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: image/png' \
  --data-binary "@$PNG" | jq -r .content_uri | sed 's|mxc://cluster.test/||')
[ -n "$PIC_MID" ] && [ "$PIC_MID" != null ] || { echo "FAIL: png upload"; exit 1; }
PIC_BLOB=$(blob_id_of "$PNG")
# It takes part in every placement assertion below like any other blob.
BLOBS+=("$PIC_BLOB"); MEDIA+=("$PIC_MID"); FILES+=("$PNG"); UPLOAD_NODE+=("$C1")

echo "uploaded ${#BLOBS[@]} blobs (including one PNG)"

DIRS3=("$WORK/n1" "$WORK/n2" "$WORK/n3")
# At 3 nodes and RF 3 the replica set IS every node, and the upload acks
# only at a majority — so a copy on all three must already be true, or
# become true the moment the third push lands.
if ! wait_for_copies 3 30 "${DIRS3[@]}"; then
  fail "3-node replication never reached 3 copies of every blob"
  report_copies "${DIRS3[@]}"
fi
echo "every blob is on all 3 nodes"

echo "=== all 3 nodes serve every blob, byte-identical ==="
for i in "${!BLOBS[@]}"; do
  for C in "$C1" "$C2" "$C3"; do
    check_download "$C" "${MEDIA[$i]}" "${FILES[$i]}" \
      || { fail "blob $i download via $C (3-node phase)"; break 2; }
  done
done
[ "$pass" = 1 ] && echo "all ${#BLOBS[@]} blobs verified on all 3 nodes"

# ---------------------------------------------------------------- phase B
if [ "$pass" = 1 ]; then
  echo "=== node 4 joins: blobs re-rank to a top-3 of 4 ==="
  "$BIN" start --config "$WORK/n4.toml" > "$WORK/n4.log" 2>&1 &
  N4=$!
  wait_up $C4 || { echo "node 4 never came up"; tail -40 "$WORK/n4.log"; exit 1; }

  DIRS4=("$WORK/n1" "$WORK/n2" "$WORK/n3" "$WORK/n4")
  # The convergence that proves BOTH halves of the reconciler: node 4
  # pulled what ranks onto it, and the displaced node deleted its copy.
  # Exactly 3, not "at least 3" — "at least" would pass with eviction
  # completely broken.
  if ! wait_for_copies 3 60 "${DIRS4[@]}"; then
    fail "blobs never converged to exactly 3 copies across 4 nodes"
    report_copies "${DIRS4[@]}"
  else
    echo "every blob converged to exactly 3 of 4 copies (pulled + evicted)"
  fi

  # Node 4 must have actually taken on work, and something must have been
  # evicted — otherwise "3 copies" could be an accident of nothing moving.
  N4HELD=0
  for b in "${BLOBS[@]}"; do
    [ -f "$WORK/n4/media/blobs/${b:0:2}/$b" ] && N4HELD=$((N4HELD + 1))
  done
  [ "$N4HELD" -gt 0 ] || fail "node 4 pulled no blobs at all"
  EVICTED=$(( $(strip_ansi "$WORK/n1.log" | grep -c "blob reconciler: evicted") \
            + $(strip_ansi "$WORK/n2.log" | grep -c "blob reconciler: evicted") \
            + $(strip_ansi "$WORK/n3.log" | grep -c "blob reconciler: evicted") ))
  [ "$EVICTED" -gt 0 ] || fail "no node ever evicted a re-placed blob"
  echo "node 4 holds $N4HELD of ${#BLOBS[@]} blobs; survivors logged $EVICTED eviction pass(es)"
fi

if [ "$pass" = 1 ]; then
  echo "=== all 4 nodes serve every blob (the one that no longer holds it reads through) ==="
  for i in "${!BLOBS[@]}"; do
    for C in "${ALL[@]}"; do
      check_download "$C" "${MEDIA[$i]}" "${FILES[$i]}" \
        || { fail "blob $i download via $C (4-node phase)"; break 2; }
    done
  done
  [ "$pass" = 1 ] && echo "all ${#BLOBS[@]} blobs verified on all 4 nodes"
fi

# ---------------------------------------------------------------- phase C
if [ "$pass" = 1 ]; then
  # Kill a node that actually holds a replica of blob 0 and is not the
  # node we will download through first.
  VICTIM_DIR=$(holders_of "${BLOBS[0]}" "${DIRS4[@]}" | head -1)
  case "$VICTIM_DIR" in
    "$WORK/n1") VICTIM_PID=$N1; VICTIM=1 ;;
    "$WORK/n2") VICTIM_PID=$N2; VICTIM=2 ;;
    "$WORK/n3") VICTIM_PID=$N3; VICTIM=3 ;;
    *)          VICTIM_PID=$N4; VICTIM=4 ;;
  esac
  SURVIVOR_URLS=()
  SURVIVOR_DIRS=()
  for n in 1 2 3 4; do
    [ "$n" = "$VICTIM" ] && continue
    SURVIVOR_URLS+=("${ALL[$((n - 1))]}")
    SURVIVOR_DIRS+=("$WORK/n$n")
  done

  echo "=== kill -9 node $VICTIM (holds a replica of blob 0) ==="
  kill -9 "$VICTIM_PID" 2>/dev/null
  wait "$VICTIM_PID" 2>/dev/null
  eval "N$VICTIM="

  echo "=== survivors keep serving every blob during the outage ==="
  for i in "${!BLOBS[@]}"; do
    for C in "${SURVIVOR_URLS[@]}"; do
      check_download "$C" "${MEDIA[$i]}" "${FILES[$i]}" \
        || { fail "blob $i download via $C during outage"; break 2; }
    done
  done
  [ "$pass" = 1 ] && echo "all ${#BLOBS[@]} blobs served throughout the outage"
fi

if [ "$pass" = 1 ]; then
  # Three survivors at RF 3: the replica set is all of them, so healing
  # means every blob ends up on every survivor.
  echo "=== reconciler heals back to full replication on the survivors ==="
  if ! wait_for_copies 3 60 "${SURVIVOR_DIRS[@]}"; then
    fail "blobs never healed to 3 copies among the 3 survivors"
    report_copies "${SURVIVOR_DIRS[@]}"
  else
    echo "every blob is on all 3 survivors again"
  fi
fi

# ---------------------------------------------------------------- phase D
if [ "$pass" = 1 ]; then
  # What the restarted node brings back with it. A node marked
  # unreachable is excluded from placement, and reading that exclusion as
  # "none of these blobs are mine" made it delete its entire blob store
  # within half a second of booting — see placement::may_evict.
  BEFORE_RESTART=$(find "$WORK/n$VICTIM/media/blobs" -type f 2>/dev/null | wc -l)
  echo "=== node $VICTIM restarts (carrying $BEFORE_RESTART blob(s)) ==="
  "$BIN" start --config "$WORK/n$VICTIM.toml" > "$WORK/n$VICTIM-restart.log" 2>&1 &
  RESTARTED=$!
  eval "N$VICTIM=$RESTARTED"
  wait_up "${ALL[$((VICTIM - 1))]}" \
    || { echo "node $VICTIM never came back"; tail -40 "$WORK/n$VICTIM-restart.log"; exit 1; }

  # It must not have thrown its media away on the way in. Sampled inside
  # the window where the node is up but the detector has not yet restored
  # it to Active (grace 5s => 1s probes x a 3-probe recovery streak): the
  # regression wiped the store ~0.5s after boot, well before that. The
  # test is "lost EVERYTHING", which no legitimate eviction can do — an
  # active node keeps the ~3/4 of blobs that rank onto it — so a fast
  # recovery cannot turn this into a false failure.
  sleep 2
  AFTER_RESTART=$(find "$WORK/n$VICTIM/media/blobs" -type f 2>/dev/null | wc -l)
  if [ "$BEFORE_RESTART" -gt 0 ] && [ "$AFTER_RESTART" -eq 0 ]; then
    fail "node $VICTIM discarded all $BEFORE_RESTART of its blobs while marked unreachable"
  else
    echo "node $VICTIM kept $AFTER_RESTART of $BEFORE_RESTART blob(s) across the restart"
  fi

  # Back to 4 nodes: blobs re-rank again and must settle at 3 copies.
  if ! wait_for_copies 3 60 "${DIRS4[@]}"; then
    fail "blobs never re-converged to 3 copies after the node returned"
    report_copies "${DIRS4[@]}"
  else
    echo "every blob is back to exactly 3 of 4 copies"
  fi
fi

if [ "$pass" = 1 ]; then
  echo "=== final: all 4 nodes serve every blob ==="
  for i in "${!BLOBS[@]}"; do
    for C in "${ALL[@]}"; do
      check_download "$C" "${MEDIA[$i]}" "${FILES[$i]}" \
        || { fail "blob $i final download via $C"; break 2; }
    done
  done
fi

# Thumbnail through a node that does not hold the blob: the read-through
# lives inside MediaStore::read, so the thumbnailer inherits it.
#
# The PNG was uploaded back in phase A rather than here. Uploading it now
# and immediately reading it on another node would race the MEDIA ROW's
# replication through the user group — a node that has just rejoined is
# still catching up — and this step is an assertion about blob placement,
# not about metadata propagation timing. Racing an unrelated subsystem
# and calling the result a media-placement failure is how a test starts
# crying wolf.
if [ "$pass" = 1 ]; then
  echo "=== thumbnail via a node that does not hold the blob ==="
  NON_HOLDER=
  for n in 1 2 3 4; do
    if [ ! -f "$WORK/n$n/media/blobs/${PIC_BLOB:0:2}/$PIC_BLOB" ]; then
      NON_HOLDER="${ALL[$((n - 1))]}"; break
    fi
  done
  if [ -z "$NON_HOLDER" ]; then
    fail "every node holds the PNG; the read-through path was never exercised"
  else
    CT=$(curl -fsS --max-time 60 -o "$WORK/thumb.png" -w '%{content_type}' \
      "$NON_HOLDER/_matrix/client/v1/media/thumbnail/cluster.test/$PIC_MID?width=4&height=4&method=scale" \
      -H "Authorization: Bearer $TOKEN")
    case "$CT" in
      image/*) [ -s "$WORK/thumb.png" ] || fail "thumbnail via a non-holder was empty" ;;
      *) fail "thumbnail via a non-holder returned content-type '$CT'" ;;
    esac
    [ "$pass" = 1 ] && echo "thumbnail generated through the read-through path"
  fi
fi

if [ "$pass" = 1 ]; then
  echo "RESULT: PASS — blobs replicate to RF on upload, re-place on join (pull + evict), survive a kill -9 with full serving, heal to RF, and re-place again on recovery"
else
  echo "RESULT: FAIL"
  for n in 1 2 3 4; do
    [ -f "$WORK/n$n.log" ] || continue
    echo "--- node $n blob lines ---"
    strip_ansi "$WORK/n$n.log" | grep -iE "blob|media" | tail -12
  done
  exit 1
fi
