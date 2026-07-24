#!/usr/bin/env bash
# Synapse interop test — the M3 exit criterion, made executable.
#
# Stands up a real Synapse and saltator on a shared docker network with a
# shared private CA, then proves the loop that matters: a saltator user
# joins a Synapse-hosted room over federation, and a message flows in each
# direction (saltator's outbound sender -> Synapse, Synapse's sender ->
# saltator's inbound /send). Exits non-zero if any step fails; dumps both
# containers' logs on failure.
set -euo pipefail
cd "$(dirname "$0")"

SYN=http://localhost:8008   # Synapse client API (published)
SAL=http://localhost:8009   # saltator client API (published)
ALICE_MSG="hello bob, this is alice on synapse"
BOB_MSG="hello alice, this is bob on saltator"

export HOST_UID="$(id -u)" HOST_GID="$(id -g)"

log() { echo "=== $* ==="; }

cleanup() {
  local code=$?
  if [ "$code" -ne 0 ]; then
    log "FAILURE (exit $code) — container logs follow"
    docker compose logs --no-color --tail=200 || true
  fi
  docker compose down -v --remove-orphans >/dev/null 2>&1 || true
  exit "$code"
}
trap cleanup EXIT

# --- shared CA + per-server full-chain certs ------------------------------
log "generating CA and certificates"
rm -rf certs synapse-data
mkdir -p certs synapse-data
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/ca.key -out certs/ca.crt -subj "/CN=saltator-interop-ca" 2>/dev/null

gen_cert() {
  local name="$1"
  openssl ecparam -name prime256v1 -genkey -noout -out "certs/$name.key" 2>/dev/null
  openssl req -new -key "certs/$name.key" -subj "/CN=$name" -out "certs/$name.csr" 2>/dev/null
  openssl x509 -req -in "certs/$name.csr" -CA certs/ca.crt -CAkey certs/ca.key \
    -CAcreateserial -days 3650 -sha256 \
    -extfile <(printf 'subjectAltName=DNS:%s\n' "$name") \
    -out "certs/$name.leaf.crt" 2>/dev/null
  # Serve the full chain (leaf + CA); Synapse expects a chain file, and it
  # is harmless for saltator's rustls listener.
  cat "certs/$name.leaf.crt" certs/ca.crt > "certs/$name.crt"
}
gen_cert synapse
gen_cert saltator

# --- Synapse signing key + log config (via `generate`) --------------------
log "generating Synapse signing key + log config"
docker compose run --rm synapse generate
log "installing our homeserver.yaml"
cp homeserver.yaml synapse-data/homeserver.yaml

# --- bring both servers up ------------------------------------------------
log "starting Synapse + saltator"
docker compose up -d

wait_up() {
  local url="$1" name="$2" i
  for i in $(seq 1 120); do
    if curl -fsS "$url/_matrix/client/versions" >/dev/null 2>&1; then
      log "$name is up"; return 0
    fi
    sleep 1
  done
  echo "timed out waiting for $name at $url" >&2; return 1
}
wait_up "$SYN" synapse
wait_up "$SAL" saltator

# --- users ----------------------------------------------------------------
log "registering @alice:synapse"
docker compose exec -T synapse \
  register_new_matrix_user -u alice -p alicepass -a \
  -c /data/homeserver.yaml http://localhost:8008

log "logging in @alice:synapse"
alice_token=$(curl -fsS -X POST "$SYN/_matrix/client/v3/login" \
  -H 'Content-Type: application/json' -d '{
    "type":"m.login.password",
    "identifier":{"type":"m.id.user","user":"alice"},
    "password":"alicepass"
  }' | jq -r .access_token)
[ -n "$alice_token" ] && [ "$alice_token" != null ] || { echo "alice login failed" >&2; exit 1; }

log "registering @bob:saltator"
bob_token=$(curl -fsS -X POST "$SAL/_matrix/client/v3/register" \
  -H 'Content-Type: application/json' -d '{
    "auth":{"type":"m.login.dummy"},
    "username":"bob","password":"bobpass"
  }' | jq -r .access_token)
[ -n "$bob_token" ] && [ "$bob_token" != null ] || { echo "bob register failed" >&2; exit 1; }

# --- alice creates a public room on synapse -------------------------------
log "alice creates a public room on synapse"
room_id=$(curl -fsS -X POST "$SYN/_matrix/client/v3/createRoom" \
  -H "Authorization: Bearer $alice_token" -H 'Content-Type: application/json' \
  -d '{"preset":"public_chat","name":"interop"}' | jq -r .room_id)
[ -n "$room_id" ] && [ "$room_id" != null ] || { echo "createRoom failed" >&2; exit 1; }
log "room is $room_id"
room_enc=$(printf %s "$room_id" | jq -sRr @uri)

# --- bob joins the remote room via federation -----------------------------
# The room ID carries synapse as its resident, so saltator drives
# make_join/send_join against Synapse. Retry: key fetch + handshake can
# lag a beat behind startup.
log "bob joins $room_id from saltator (federated make_join/send_join)"
join_ok=""
for i in $(seq 1 30); do
  if curl -fsS -X POST "$SAL/_matrix/client/v3/rooms/$room_enc/join" \
      -H "Authorization: Bearer $bob_token" -H 'Content-Type: application/json' \
      -d '{}' >/dev/null 2>&1; then
    join_ok=1; break
  fi
  sleep 2
done
[ -n "$join_ok" ] || { echo "bob failed to join the remote room" >&2; exit 1; }
log "bob joined"

# --- a message each direction ---------------------------------------------
log "bob sends a message (saltator -> synapse)"
curl -fsS -X PUT "$SAL/_matrix/client/v3/rooms/$room_enc/send/m.room.message/txn-bob-1" \
  -H "Authorization: Bearer $bob_token" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg b "$BOB_MSG" '{msgtype:"m.text",body:$b}')" >/dev/null

log "alice sends a message (synapse -> saltator)"
curl -fsS -X PUT "$SYN/_matrix/client/v3/rooms/$room_enc/send/m.room.message/txn-alice-1" \
  -H "Authorization: Bearer $alice_token" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg b "$ALICE_MSG" '{msgtype:"m.text",body:$b}')" >/dev/null

# --- assert delivery both ways --------------------------------------------
sees() {
  local base="$1" token="$2" needle="$3" i body
  for i in $(seq 1 45); do
    body=$(curl -fsS "$base/_matrix/client/v3/sync?timeout=1000" \
      -H "Authorization: Bearer $token" 2>/dev/null || true)
    if printf %s "$body" | grep -qF "$needle"; then return 0; fi
    sleep 2
  done
  return 1
}

log "asserting synapse (alice) received bob's message"
sees "$SYN" "$alice_token" "$BOB_MSG" || { echo "synapse never saw bob's message" >&2; exit 1; }
log "asserting saltator (bob) received alice's message"
sees "$SAL" "$bob_token" "$ALICE_MSG" || { echo "saltator never saw alice's message" >&2; exit 1; }

log "SUCCESS: saltator <-> Synapse federation round-trip verified"
