#!/bin/sh
# Complement entrypoint: build a node config from SERVER_NAME and start.
# Complement may restart the container, so this must tolerate running
# multiple times: the config is regenerated, /data is reused as-is.
set -eu

: "${SERVER_NAME:=localhost}"
mkdir -p /data

cat > /data/saltator.toml <<EOF
server_name = "$SERVER_NAME"
data_dir = "/data"

# Complement's corpus predates room v12's privileged-creator semantics
# (tests assert the creator sits in power_levels.users); run the suite at
# v11 so those tests exercise real behavior. The shipped default stays 12
# per spec v1.19.
[client]
default_room_version = "11"

[node]
id = 1
advertise = "127.0.0.1:7400"

[listeners]
internal = "127.0.0.1:7400"
client = "0.0.0.0:8008"
federation = "0.0.0.0:8448"
EOF

exec /usr/local/bin/saltator start --config /data/saltator.toml
