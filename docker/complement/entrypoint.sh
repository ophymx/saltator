#!/bin/sh
# Complement entrypoint: build node config(s) from SERVER_NAME and start.
# Complement may restart the container, so this must tolerate running
# multiple times: configs and certs are regenerated, /data is reused.
#
# CLUSTER_NODES=1 (default): one node serving 8008/8448 directly — the CI
# shape. CLUSTER_NODES=3: a real 3-node cluster inside the container
# behind haproxy (all traffic to the first healthy node, failing over
# when it dies; leader forwarding lets any node serve any request) — the
# local hardening harness. CHURN_INTERVAL=<secs> additionally kill -9s a
# random node on that cadence and restarts it a few seconds later
# (cluster mode only).
set -eu

: "${SERVER_NAME:=localhost}"
: "${CLUSTER_NODES:=1}"
: "${CHURN_INTERVAL:=0}"
mkdir -p /data

# Complement mounts a CA (ca.crt + ca.key) that all test homeservers trust.
# For federation tests we serve HTTPS on 8448 with a cert signed by it, and
# trust it for outbound. When the CA is absent (csapi-only runs), the
# federation port stays plain HTTP.
HAVE_TLS=""
CA_CRT="/complement/ca/ca.crt"
CA_KEY="/complement/ca/ca.key"
if [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ]; then
    HAVE_TLS=1
    openssl ecparam -name prime256v1 -genkey -noout -out /data/fed.key
    openssl req -new -key /data/fed.key -subj "/CN=$SERVER_NAME" -out /data/fed.csr
    cat > /data/fed.ext <<EXT
subjectAltName = DNS:$SERVER_NAME
EXT
    openssl x509 -req -in /data/fed.csr \
        -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
        -out /data/fed.crt -days 3650 -sha256 -extfile /data/fed.ext
fi

# Complement copies appservice registration files here for blueprints
# that declare one (e.g. the jump-to-date `?ts` massaging tests).
AS_DIR=""
if [ -d /complement/appservice ]; then
    AS_DIR='appservice_registration_dir = "/complement/appservice"'
fi

# Write one node's config. Args: dir id internal client fed seeds
write_config() {
    _dir="$1"; _id="$2"; _internal="$3"; _client="$4"; _fed="$5"; _seeds="$6"
    # Complement's homeservers live on the isolated test network (private
    # IPs), so outbound federation must be allowed to reach them; production
    # keeps this false (pre-auth SSRF guard).
    _fed_tls="
[federation]
allow_private_ips = true"
    if [ -n "$HAVE_TLS" ]; then
        _fed_tls="$_fed_tls
tls_cert = \"/data/fed.crt\"
tls_key = \"/data/fed.key\"
ca_cert = \"$CA_CRT\""
    fi
    cat > "$_dir.toml" <<EOF
server_name = "$SERVER_NAME"
data_dir = "$_dir"

# Complement's corpus predates room v12's privileged-creator semantics
# (tests assert the creator sits in power_levels.users); run the suite at
# v11 so those tests exercise real behavior. The shipped default stays 12
# per spec v1.19.
[client]
default_room_version = "11"
# The suite hammers every endpoint far past real-client rates.
rate_limits_enabled = false
# Complement's URL-preview/pusher targets live on the isolated test network
# (private IPs); allow the server to fetch them.
allow_internal_fetch = true
$AS_DIR

[node]
id = $_id
advertise = "$_internal"

[cluster]
seeds = [$_seeds]
# Multi-shard CI: 4 room groups per suite server — enough to exercise the
# vector-token/routing paths on every test without the raft overhead of
# the 16-group production default (docs/design-room-sharding.md §open
# question 3; e2e/cluster/chaos harnesses cover the default 16).
room_shards = 4

[listeners]
internal = "$_internal"
client = "$_client"
federation = "$_fed"
$_fed_tls
EOF
}

wait_client() {
    _i=0
    while [ $_i -lt 240 ]; do
        curl -fsS "http://$1/_matrix/client/versions" >/dev/null 2>&1 && return 0
        _i=$((_i + 1))
        sleep 0.5
    done
    return 1
}

start_node() {
    # stdout prefixed per node so Complement's server-log dump interleaves
    # all of them readably.
    _n="$1"; _cfg="$2"
    /usr/local/bin/saltator start --config "$_cfg" 2>&1 | sed -u "s/^/[n$_n] /" &
}

if [ "$CLUSTER_NODES" = 1 ]; then
    write_config /data/n1 1 "127.0.0.1:7400" "0.0.0.0:8008" "0.0.0.0:8448" ""
    exec /usr/local/bin/saltator start --config /data/n1.toml
fi

# --- cluster mode -----------------------------------------------------------

# Media blobs are node-local filesystem (metadata rides the user shard);
# share one directory across the in-container nodes — the shared-blob-store
# deployment shape — so any node can serve any upload.
mkdir -p /data/shared-media
i=1
while [ "$i" -le "$CLUSTER_NODES" ]; do
    mkdir -p "/data/n$i"
    [ -e "/data/n$i/media" ] || ln -s /data/shared-media "/data/n$i/media"
    i=$((i + 1))
done

write_config /data/n1 1 "127.0.0.1:7401" "127.0.0.1:8011" "127.0.0.1:8451" ""
i=2
while [ "$i" -le "$CLUSTER_NODES" ]; do
    write_config "/data/n$i" "$i" "127.0.0.1:740$i" "127.0.0.1:801$i" "127.0.0.1:845$i" '"127.0.0.1:7401"'
    i=$((i + 1))
done

echo "[cluster] starting node 1 (founder)"
start_node 1 /data/n1.toml
wait_client 127.0.0.1:8011 || { echo "[cluster] node 1 never came up"; exit 1; }

# The cluster KEK is an operator-provisioned secret, copied to each node.
i=2
while [ "$i" -le "$CLUSTER_NODES" ]; do
    cp /data/n1/master.key "/data/n$i/master.key"
    echo "[cluster] starting node $i (joiner)"
    start_node "$i" "/data/n$i.toml"
    i=$((i + 1))
done
i=2
while [ "$i" -le "$CLUSTER_NODES" ]; do
    wait_client "127.0.0.1:801$i" || { echo "[cluster] node $i never came up"; exit 1; }
    i=$((i + 1))
done
echo "[cluster] all $CLUSTER_NODES nodes up"

# haproxy fronts 8008/8448: every request to the FIRST healthy backend
# (stable affinity → the whole conversation sees one node's applied state
# while it lives), redispatching to the next on failure. Federation is TCP
# passthrough — the nodes serve their own TLS.
client_backends() {
    i=1
    while [ "$i" -le "$CLUSTER_NODES" ]; do
        echo "    server n$i 127.0.0.1:801$i check inter 500ms fall 2 rise 2"
        i=$((i + 1))
    done
}
fed_backends() {
    i=1
    while [ "$i" -le "$CLUSTER_NODES" ]; do
        echo "    server n$i 127.0.0.1:845$i check inter 500ms fall 2 rise 2"
        i=$((i + 1))
    done
}
cat > /data/haproxy.cfg <<EOF
defaults
    timeout connect 5s
    timeout client 305s
    timeout server 305s
    retries 3
    option redispatch

frontend client
    bind 0.0.0.0:8008
    mode http
    default_backend client_nodes

backend client_nodes
    mode http
    balance first
    option httpchk GET /_matrix/client/versions
$(client_backends)

frontend federation
    bind 0.0.0.0:8448
    mode tcp
    default_backend federation_nodes

backend federation_nodes
    mode tcp
    balance first
$(fed_backends)
EOF

if [ "$CHURN_INTERVAL" -gt 0 ] 2>/dev/null; then
    (
        # Kill -9 a random node on the cadence, restart it a few seconds
        # later; its data dir persists so it recovers and rejoins.
        while true; do
            sleep "$CHURN_INTERVAL"
            victim=$(( $(od -An -N2 -tu2 /dev/urandom) % CLUSTER_NODES + 1 ))
            pid=$(pgrep -f "saltator start --config /data/n$victim.toml" | head -1)
            [ -n "$pid" ] || continue
            echo "[churn] kill -9 node $victim (pid $pid)"
            kill -9 "$pid" 2>/dev/null || true
            sleep 5
            echo "[churn] restarting node $victim"
            start_node "$victim" "/data/n$victim.toml"
        done
    ) &
fi

echo "[cluster] haproxy fronting 8008/8448"
exec haproxy -f /data/haproxy.cfg
