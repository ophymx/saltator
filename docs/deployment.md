# Deploying a cluster

The operator's walk-through for a multi-node Saltator: founding it,
joining nodes, fronting it, keeping it running, and getting it back.
Three nodes is the worked example because it is the smallest cluster
that survives losing one; nothing here is specific to three.

Everything an operator can set is in `saltator example-config`, and the
reasoning behind the design is in [spec.md](../spec.md). This document
is the order to do things in and the mistakes that are easy to make.
The admin endpoints it names are specified in
[admin-api.md](admin-api.md).

## Decide these first — they cannot change later

| setting | fixed at | why |
| --- | --- | --- |
| `server_name` | founding | It is the identity of every user and room the cluster will ever hold, and the SAN every node's internal certificate carries. |
| `cluster.room_shards` | founding | Shard split and merge do not exist. The default of 16 is right for a handful of nodes; set 64 only if you expect to exceed 16 nodes. |
| `cluster.replication_factor` | founding | Stored in cluster metadata like the shard count. The default of 3 means a three-node cluster holds every room on every node. |
| `node.id` | each node's first start | A node's identity in every Raft group. Never reuse one for a different machine (see "Replacing a node"). |

Both cluster values are read **only** by the founding node. A different
value on a joiner is logged as a warning and ignored; the durable
cluster config is the only truth.

## What a three-node cluster gives you

- Every room shard, the user shard and the federation-out shard are
  replicated on all three nodes. Any node answers any request; a write
  that lands on a node that does not lead the shard is forwarded to the
  one that does.
- It survives losing **one** node: every group keeps a two-of-three
  quorum. Losing a second node stops writes until one returns. There is
  no configuration that changes this; it is what three voters means.
- A node that comes back after a crash or a restart catches up from
  the others. A node that comes back with an empty disk is a new node
  (see "Replacing a node").

## 1. The internal mesh: certificates

Nodes talk to each other over gRPC on the `listeners.internal` port, and
that surface carries the cluster's whole trust: anyone who can reach it
unauthenticated can propose arbitrary commands to any shard. So a node
whose internal listener binds anything but loopback **refuses to start**
without mutual TLS, and every multi-node deployment begins with a
private CA.

What the mesh verifies is deliberately simple:

- every node presents a certificate signed by `cluster.tls_ca`, in both
  directions — holding such a certificate *is* membership;
- the certificate carries `server_name` as a DNS SAN. Nodes dial each
  other by address, often a bare IP, so hostname verification would
  mean nothing; the SAN is pinned instead, and it is the same on every
  node.

With OpenSSL 3, on a machine that is not one of the nodes:

```sh
NAME=matrix.example.org           # the cluster's server_name

# The CA. Keep ca.key off the nodes; they only need ca.crt.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout ca.key -out ca.crt -days 3650 -subj "/CN=saltator internal CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# One certificate per node. The SAN is the server_name on all of them;
# both EKUs are required because every node is a TLS server to its peers
# and a TLS client of them.
cat > node.ext <<EXT
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:$NAME
EXT
for n in 1 2 3; do
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout node$n.key -out node$n.csr -subj "/CN=saltator node $n"
  openssl x509 -req -in node$n.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out node$n.crt -days 825 -extfile node.ext
done
```

On each node, the package has already created `/etc/saltator` as
`0750 root:saltator`; the daemon runs as `saltator`, so the files must
be group-readable:

```sh
install -d -m 0750 -o root -g saltator /etc/saltator/internal
install -m 0640 -o root -g saltator ca.crt node1.crt node1.key /etc/saltator/internal/
```

Expiry is yours to track: the daemon does not watch for it, and a mesh
whose certificates have expired is a cluster whose nodes can no longer
replicate. Rotate by installing new files and restarting one node at a
time, as in "Rolling restart" below — the CA must stay the same, or
the first restarted node cannot talk to the rest.

## 2. The node configuration

One file per node, `/etc/saltator/saltator.toml`. The three differ only
in `node.id`, `node.advertise`, the bind addresses and `cluster.seeds`:

```toml
server_name = "matrix.example.org"
data_dir = "/var/lib/saltator"

[node]
id = 1                          # 2 and 3 on the others
advertise = "10.0.0.1:7400"     # how the OTHER nodes reach this one

[cluster]
seeds = []                      # founder; see below for the rest
# room_shards = 16              # founder only, immutable
# replication_factor = 3        # founder only, immutable
tls_cert = "/etc/saltator/internal/node1.crt"
tls_key  = "/etc/saltator/internal/node1.key"
tls_ca   = "/etc/saltator/internal/ca.crt"

[listeners]
internal = "10.0.0.1:7400"      # a private interface, never a public one
client = "0.0.0.0:8008"         # or the interface your proxy reaches
federation = "0.0.0.0:8448"
metrics = "127.0.0.1:9464"      # or a management interface; unauthenticated

[client]
registration_enabled = true
registration_requires_token = false
admin_users = ["@root:matrix.example.org"]
```

- **`advertise`** is the address written into the cluster roster and
  dialled by peers. It must be reachable from the other nodes and must
  be served by `listeners.internal` — a listener on `0.0.0.0:7400` and
  an advertise of `10.0.0.1:7400` is fine; an advertise of `127.0.0.1`
  on a multi-node cluster is not.
- **`seeds`** decides what a node does on a *fresh* data dir and
  nothing else. Empty means *found a new cluster*; non-empty means
  *join the cluster those addresses belong to*. On a restart the node
  recovers its membership from disk and ignores the list — so after
  founding, set the founder's `seeds` to the other two nodes as well.
  Otherwise a founder whose data dir is ever lost would come back as a
  brand-new one-node cluster with the same `server_name`, rather than
  rejoining the real one.
- The internal port only needs to be reachable between the nodes; the
  client and federation ports from whatever fronts them; the metrics
  port from the monitoring system. Nothing else should see any of them.
- `admin_users` is the bootstrap administrator. A fresh server has no
  admin account and no way to grant one from inside, so the first one
  has to be named here. It must be a full user id on this
  `server_name`; register that account first thing.

## 3. Founding

Start node 1 and only node 1:

```sh
systemctl enable --now saltator
journalctl -fu saltator
```

A founder logs, in order, `internal RPC listening` with `tls=true`,
`metadata group ready`, `cluster topology` (with the room-shard count
and replication factor that are now fixed), `generated cluster
key-encryption key`, then `room shards ready`, `user shard ready` and
`federation-out shard ready`. After that, `GET /_saltator/health/ready`
on the client port answers `200`.

Register the administrator now, while registration is open and the
cluster is one node:

```sh
curl -s http://10.0.0.1:8008/_matrix/client/v3/register \
  -H 'content-type: application/json' \
  -d '{"username":"root","password":"…","auth":{"type":"m.login.dummy"}}'
```

The account is an administrator because its id is in `admin_users`.
From here on, the admin API and `PUT /_saltator/admin/v1/users/{user_id}/admin`
can make others.

## 4. The cluster secret

Founding minted `/var/lib/saltator/master.key`: the key that encrypts
the server's event-signing keys inside the metadata group. It is a
**cluster** secret, minted once and never again; every other node needs
the same file before its first start, and a joiner without it fails at
startup with a message saying so.

Copy it from node 1 to nodes 2 and 3, owner-only, owned by the service
user (the state directory is `0700 saltator:saltator`):

```sh
scp node1:/var/lib/saltator/master.key /tmp/master.key    # as root on the joiner
install -d -m 0700 -o saltator -g saltator /var/lib/saltator
install -m 0600 -o saltator -g saltator /tmp/master.key /var/lib/saltator/master.key
shred -u /tmp/master.key
```

Keep a copy somewhere that is not a node. Losing it on every node at
once loses the signing key, and a server that has lost its signing key
cannot be rebuilt from its peers: the events it signed verify, but it
can never sign another as the same server. The key is 32 raw bytes;
there is nothing in it to rotate or regenerate.

## 5. Joining nodes 2 and 3

On each joiner, the config carries `seeds = ["10.0.0.1:7400"]` (any
already-running node will do; list them all), its own id and advertise
address, its own certificate, and the copied `master.key`. Start them
**one at a time**, and wait for each to be ready before the next:

```sh
systemctl enable --now saltator
journalctl -fu saltator
```

A joiner logs `joining existing cluster`, then `admitted to metadata
group`, then the same `ready` lines a founder does. In between, openraft
emits a burst of `A message will be ignored because vote changed`
warnings while the joiner's groups are being folded in; they are noise,
not a fault. It is admitted to the
metadata group as a voter first, then the placement controller on the
leader folds it into each shard group: add it as a learner, bring it up
to date from a replica's checkpoint over the bulk channel, promote it.
That takes seconds on an empty cluster and as long as the data takes to
copy on a full one.

Confirm from any node, with the administrator's access token:

```sh
curl -s -H "Authorization: Bearer $TOKEN" \
  http://10.0.0.1:8008/_saltator/admin/v1/cluster/nodes
```

Three nodes, each `"status": "active"` and `"metadata_voter": true`,
each listing every group under `groups` (the replication factor is 3
and there are 3 nodes, so every group is everywhere). Until a joiner's
`groups` is full, it is still catching up; it serves reads of what it
has and forwards the rest, which is correct but not what you want to
load-balance onto yet.

Now add the other nodes to node 1's `seeds` (section 2) and restart it
when convenient. It does not need the list today; it needs it on the
day its disk is replaced.

## 6. Fronting it

Saltator serves plain HTTP on the client port. Terminate TLS in front
of it, and spread clients across all three nodes:

- **Health-check the pool with `GET /_saltator/health/ready`**, and
  only that. It is `200` on a node that can serve, `503` on one that is
  draining or has lost a shard leader. It is unauthenticated and
  reveals nothing.
- **Do not point an orchestrator's liveness check at it.** Liveness is
  `GET /_saltator/health/live`, which means "restart me" and never fails
  for anything a restart would not fix. A draining node is live and not
  ready, on purpose; a liveness check on readiness turns every drain
  into a crash loop.
- No session affinity is needed. Any node serves any user. Affinity is
  harmless, and can even help: a write that lands on a node that does
  not lead that room's shard is forwarded and costs a round trip.
  `saltator_shard_proposals_total{outcome="forwarded"}` counts those;
  on a three-node cluster some of it is unavoidable, since a room's
  leader is one node out of three.
- **The admin API is on the client port**, under `/_saltator/admin/`.
  It is protected by the administrator's token, not by the network, but
  an internal cluster has no reason to expose it: block that prefix at
  the proxy for anything but the management network. The web console,
  when the binary is built with it, is under `/_saltator/admin/ui/`
  behind the same rule.
- `/.well-known/matrix/client` is served once `client.well_known_client`
  is set; point it at the proxy's public URL. `public_base_url` is the
  same URL and is required only for OIDC.
- The federation port is only needed if this server federates. If it
  does, either set `federation.tls_cert`/`tls_key` so the node serves
  HTTPS itself, or terminate at the proxy — but then every node, not
  one, must be reachable through it, since any node may be asked to
  serve any federation request. A purely internal cluster can leave the
  port firewalled.

Build the admin console in with `cargo build --features admin-ui`; the
Debian packages do not carry it.

## 7. Watching it

`[listeners] metrics` turns on a Prometheus exporter;
[observability.md](observability.md) is the reference. Four things to
alert on in a cluster:

| condition | meaning |
| --- | --- |
| `sum by (keyspace, shard) (saltator_shard_leader) != 1` for more than an election's worth of seconds | a group has no leader, or two nodes think they lead it |
| `saltator_shard_voters` below the replication factor | a group has been reconfigured without a node; a node is draining, unreachable, or removed |
| `/_saltator/health/ready` not `200` on a node nobody drained | the node cannot reach a shard leader |
| a steady rate of `outcome="forwarded"` far above `outcome="local"` | the proxy is sending most traffic to a node that leads little |

Logs are structured `tracing` on stdout — journald, with the package —
filtered by `RUST_LOG`. `info` is the right production level: the
cluster state transitions above are all logged at it.

## 8. Rolling restart and upgrade

Restarting a node is the ordinary operation, and the one the weekly
rolling-upgrade CI job rehearses on a three-node cluster: stop one,
start it, wait, next. No drain is involved. Draining is for taking a
node *out*; it reconfigures every group without that node, and
undraining puts it back — two rounds of membership change per node that
a restart does not need.

For each node in turn:

1. `systemctl stop saltator`. The proxy's readiness check drops it
   from the pool; SIGTERM stops the listeners and shuts the shards down
   cleanly. Whatever that node led fails over by election within a few
   seconds.
2. Upgrade the package, or change the configuration.
3. `systemctl start saltator`, and wait for `/_saltator/health/ready`
   to answer `200` and for `GET /_saltator/admin/v1/cluster/nodes` to show
   it `active` again. The node replays what it missed from the others.
4. Only then the next node. Two nodes down at once is a cluster that
   cannot write.

An upgrade across a schema change is the same procedure. A migration is
proposed only once **every** voter's binary supports it — the leader
asks each node for its schema version over the internal RPC and waits —
so until the last node is restarted on the new binary the cluster runs
mixed, and the new nodes read the old data shapes. The gate is in code,
not in this document; the rule for you is only *one node at a time,
wait for ready*. The oldest revision an in-place upgrade is supported
from is pinned in the CI job (`OLD_REV` in `.github/workflows/ci.yml`);
a cluster founded from a revision before it is upgraded by stepping
through one inside the window first.

### The dead-node detector on three nodes

A node that fails liveness probes for `cluster.dead_node_grace_secs`
(default 30) is marked unreachable by the metadata leader and taken out
of placement, and its replicas are re-placed onto the surviving active
nodes. On a three-node cluster with replication factor 3 the survivors
already hold everything, so nothing is copied — but every group *is*
reconfigured down to two voters, and reconfigured back up when the node
returns. Availability is identical either way (two of three, or two of
two, both need the same two nodes), so the only effect is the churn,
and a maintenance window that overruns 30 seconds triggers it. Raising
the grace to a few minutes is reasonable on a cluster this size; it
earns its default on a cluster with spare nodes to re-place onto.

## 9. Replacing a node

A node whose disk is gone is not restored from a backup into the live
cluster (see the next section for why). It is replaced:

1. **Drain the old id**, from the leader:
   `POST /_saltator/admin/v1/cluster/nodes/{node_id}/drain`. This works
   on a node that is dead; it is a change to the roster, and each
   group's leader reconfigures the voter set without the drained node
   — the drained node takes no part.
2. **Wait** until `GET /_saltator/admin/v1/cluster/nodes` shows the old
   id with an empty `groups`.
3. **Remove it**: `DELETE /_saltator/admin/v1/cluster/nodes/{node_id}`.
   It leaves the metadata group and the roster.
4. **Join the replacement** as a fresh node with a **new** `node.id`,
   its own certificate, the copied `master.key`, and `seeds` naming the
   survivors. Section 5 applies unchanged.

The window between step 1 and the replacement being caught up is one
where the cluster is two voters per group. That is the same exposure as
the outage itself; the steps do not add to it.

A node that is merely down — a hardware fault fixed in an afternoon —
needs none of this. It restarts on its own data dir and catches up.
Drain is for a node that is not coming back.

## 10. Backup and restore

Three nodes replicate every byte three times, and that is the primary
durability story: a lost node is replaced, not restored. A backup is
for the failures replication does not cover — all three disks at once,
a bad migration, an administrator deleting the wrong room, a ransomware
afternoon — and for those the restore is of the **whole cluster, from
one node's backup**. Both halves of that sentence matter, and the
reasons are below.

The procedure here is exercised by `scripts/restore_smoke.sh`, in both
the case where the backed-up node led its groups and the case where it
did not.

### What is on disk

Per node, under `data_dir`:

| path | holds |
| --- | --- |
| `db/` | RocksDB: every shard's applied state, snapshots and schema versions |
| `raft/` | RocksDB: every Raft group's log, vote and membership |
| `media/blobs/` | media files this node is placed for (all of them, at RF 3 on 3 nodes) |
| `master.key` | the cluster secret (section 4); identical on every node |

`db/` and `raft/` are two databases that only make sense together, at
the same instant. The node id is inside them: a backup is of *a* node,
and goes back onto that node id and no other.

### Keep off the nodes, always

Independent of any data backup: `master.key`, the internal CA and its
key, each node's certificate and key, and the three configuration files.
These are small, change rarely, and without `master.key` a data backup
is a server that cannot sign.

### Taking a backup

The supported method today is a **stopped-node copy**, which the cluster
tolerates for the same reason it tolerates a restart:

```sh
systemctl stop saltator
tar -C /var/lib/saltator -cf - db raft media master.key | zstd > saltator-node1-$(date -u +%FT%H%MZ).tar.zst
systemctl start saltator
```

Wait for the node to be ready again before touching another, as in a
rolling restart. One node's backup is a complete backup of the cluster
— every node holds everything at this size — so backing up one node on
a schedule is enough. Backing up more than one is fine for redundancy,
provided you understand that a restore uses exactly one of them.

A crash-consistent filesystem snapshot (LVM, ZFS, btrfs) of a running
node's data dir is the no-downtime alternative. RocksDB recovers from it
exactly as it recovers from `kill -9`, which the three-node chaos test
exercises on every CI run. Both databases must be in the *same* snapshot.
Copying the directory of a running node with `tar` or `rsync` is not a
backup: the files change under the copy, and the result need not open.

### Restoring the cluster

Pick the newest backup you have. Then:

1. **Stop every node** and clear every data dir. Whatever the other two
   nodes hold is not going to be reconciled with the backup (see
   below); it is being thrown away, so be sure a backup is what you
   want before this step.
2. **Restore the backup onto the node whose id it came from**: unpack
   `db/`, `raft/`, `media/` and `master.key` into its data dir, owned by
   the service user.
3. **Point every node's `seeds` at the restored node**, the restored
   node's own included. The other two are about to start on empty data
   dirs, and an empty data dir with no seeds founds a *new* cluster.
4. **Start the restored node.** It may report ready on its own; do not
   believe it. Its groups still have three voters on the books and can
   commit nothing until a second one is back.
5. **Start the other two on empty data dirs**, each with its
   **original `node.id`** and a copy of `master.key`. This is the one
   place the id is reused on purpose: the restored membership still
   lists ids 2 and 3 as voters, and a node that comes back under its
   old id is folded straight back in and brought up to date from the
   restored one. A fresh id would be a fourth voter that the two absent
   ones can never approve.
6. **Verify** as after founding: three active nodes, every group with
   one leader, every node's `groups` full, readiness `200` everywhere.
   Then a write through each node, read back from the others.

**What a restore loses**: everything after the backup. Clients hold
tokens and devices that may no longer exist, and end-to-end encryption
state is rewound with the rest — one-time keys already claimed are
claimable again, and sessions established in the lost window cannot be
decrypted. Users of the lost window will see undecryptable messages and
may have to re-verify devices. There is no getting that back; it is the
cost of the restore, and the argument for backing up often enough that
the window is short.

### Why one backup, and why never into a live cluster

Both rules come from the same fact about the storage: each Raft group's
vote — which node leads, in which term — is persisted beside its log,
and a node that restarts holding a *committed* vote for itself resumes
leading in that term without an election. That is what makes a
leader's restart cheap. It also means a backup is not just old data; it
is an old claim about who leads.

**Never restore one node from backup into a cluster that is still
running.** The live nodes have moved on; the restored node comes back
believing an old term and possibly an old leadership, and nothing in
the protocol is built to arbitrate that. A node that lost its data
rejoins **empty**, as a replacement (section 9).

**Never restore the three nodes from three backups.** It was tried
while writing this guide, with backups taken minutes apart: the three
nodes came up each holding its own version of history, the restored
leader resumed in its old term without noticing that the other two
logs were longer, and a write after the restore landed on one node and
never reached the others. No error was raised, and nothing would ever
have reconciled them. Raft's election is what picks the most
up-to-date log, and a resumed leadership skips the election. One
backup, two empty nodes, and the question never arises.

### What does not exist yet

A backup taken by the running node itself (a consistent checkpoint of
both databases through the admin API, no downtime, no filesystem
assumptions), and a guard that would refuse the three-backups restore
rather than quietly diverge. Both are feature work, recorded with their
design in [deferred.md](deferred.md).
