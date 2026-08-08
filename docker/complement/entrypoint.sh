#!/bin/sh
# Complement entrypoint: build a node config from SERVER_NAME and start.
# Complement may restart the container, so this must tolerate running
# multiple times: the config and cert are regenerated, /data is reused.
set -eu

: "${SERVER_NAME:=localhost}"
mkdir -p /data

# Complement mounts a CA (ca.crt + ca.key) that all test homeservers trust.
# For federation tests we serve HTTPS on 8448 with a cert signed by it, and
# trust it for outbound. When the CA is absent (csapi-only runs), the
# federation port stays plain HTTP.
FED_TLS=""
CA_CRT="/complement/ca/ca.crt"
CA_KEY="/complement/ca/ca.key"
if [ -f "$CA_CRT" ] && [ -f "$CA_KEY" ]; then
    openssl ecparam -name prime256v1 -genkey -noout -out /data/fed.key
    openssl req -new -key /data/fed.key -subj "/CN=$SERVER_NAME" -out /data/fed.csr
    cat > /data/fed.ext <<EXT
subjectAltName = DNS:$SERVER_NAME
EXT
    openssl x509 -req -in /data/fed.csr \
        -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
        -out /data/fed.crt -days 3650 -sha256 -extfile /data/fed.ext
    FED_TLS="$(cat <<TLS

[federation]
tls_cert = "/data/fed.crt"
tls_key = "/data/fed.key"
ca_cert = "$CA_CRT"
TLS
)"
fi

# Complement copies appservice registration files here for blueprints
# that declare one (e.g. the jump-to-date `?ts` massaging tests).
AS_DIR=""
if [ -d /complement/appservice ]; then
    AS_DIR='appservice_registration_dir = "/complement/appservice"'
fi

cat > /data/saltator.toml <<EOF
server_name = "$SERVER_NAME"
data_dir = "/data"

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
id = 1
advertise = "127.0.0.1:7400"

[listeners]
internal = "127.0.0.1:7400"
client = "0.0.0.0:8008"
federation = "0.0.0.0:8448"
$FED_TLS
EOF

exec /usr/local/bin/saltator start --config /data/saltator.toml
