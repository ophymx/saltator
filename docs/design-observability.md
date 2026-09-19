# Design: metrics and the exporter that serves them

## Why this exists

`tracing` was wired for *logs* only: no registry, no exporter, no
`/metrics`. The server could be read after the fact, one line at a
time, and not measured at all. An operator who cannot see request rate,
error rate, or whether this node is a shard leader is not operating a
server, they are watching a process.

Measurement was also the blocker for the one open performance question
at the time — federation delivery latency. `delivery.rs` already
*computed* `queue_ms` and `put_ms` and threw them at `tracing::debug!`,
where no aggregate could be taken.

Metrics only. OpenTelemetry tracing is deliberately a separate
decision: it carries an SDK, an exporter, and a batching pipeline, and
none of that is needed to answer the questions above.

## Exposure: its own listener

`listeners.metrics`, `Option<SocketAddr>`, absent by default.

The alternative — a route on the client listener — was rejected. The
client listener is the internet-facing one, and metrics are not health
checks: `/_saltator/health/{live,ready}` are unauthenticated *because*
their bodies say nothing a prober should not see, and that argument
does not transfer. A scrape reveals traffic volume, user and room
counts, cluster size, which shards this node leads, and which remote
servers federation is failing to reach. Gating it behind an admin token
instead would mean handing Prometheus a credential that can also
deactivate accounts.

A separate address makes the bind address itself the boundary: point it
at loopback or a management interface and the exposure question is
answered by the network, which is how every Prometheus target in
existence is already operated.

**Absent by default, not on-by-default-on-loopback.** A server should
not open a port nobody asked for. The example config carries the line,
commented, with `127.0.0.1:9464` — 9464 is the port allocated to the
OpenTelemetry Prometheus exporter, which avoids colliding with
node_exporter (9100) on a host that certainly also runs one.

## Recorder and exporter

`metrics` (the facade) + `metrics-exporter-prometheus` with
`default-features = false`.

The facade choice is spec.md §7's, honored rather than re-litigated.
The `no-default-features` part is the load-bearing detail: the
exporter's defaults drag in its own hyper server, hyper-rustls, ipnet,
and a push-gateway client with prost and protobuf behind it. Stripped
to nothing, the crate is a recorder plus `PrometheusHandle::render()`
returning a `String`, and this server already owns an HTTP stack. One
route, four lines, no second TLS implementation in the tree.

**Where the code lives.** A new leaf crate, `saltator-metrics`: the
recorder install, the exporter's little axum server, the HTTP tower
layer, and a sampler helper. Everything else instruments itself through
the `metrics` facade macros, which are no-ops until a recorder is
installed — so `saltator-shard` and `saltator-federation` take a
dependency on the facade only, never on the exporter, and their tests
keep running with no recorder at all.

`main` installs the recorder exactly once, before anything is built,
and only when the listener is configured. Nothing else may install one:
the facade's global slot is set-once, and a second attempt is a startup
error rather than a silent no-op.

## What is measured

Four families. Each answers a question an operator or the delivery-
latency work actually asks.

**HTTP** (`saltator_http_*`), one tower layer, applied by `main` to the
client and federation routers — which is why neither `saltator-cs-api`
nor `saltator-federation` needs the layer's code. Labels: `surface`
(client|federation), `method`, `route`, `status`.

**Shard** (`saltator_shard_*`), labeled `keyspace` and `shard` — the
spec's own phrasing. Proposal latency and outcome (the forwarding path
in `handle.rs` makes "slow" and "forwarded to a leader elsewhere" two
different problems), apply-batch duration and size, and gauges for
leadership, applied index, and emitted seq.

**Federation delivery** (`saltator_federation_*`). The reason this
branch exists: `queue_ms` (event created → its PUT starts) and `put_ms`
(the round trip) become histograms, plus transaction outcomes, PDUs per
transaction, and the fed-out queue depth. That decomposition is already
the right one — it separates "our worker was slow to pick it up" from
"the remote server was slow to take it", and the fix differs.

**Process** (`saltator_build_info`, uptime). Enough to correlate a
regression with a version.

## Cardinality rules

A metric label is a promise about a bounded set, and Prometheus
enforces that promise with memory. Two rules, and both are about
untrusted input:

- **Route templates, never paths.** `MatchedPath`, so
  `/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` is one
  series and not one per message ever sent. The same rule collapses the
  `method` label: hyper forwards any token a client sends as an
  extension method, so anything outside the standard set becomes
  `<other>` rather than a series a stranger minted.
- **No remote server name as a label.** Federation destinations are
  supplied by attackers — any server can put any `origin` on a request
  and any user id in a room. A `dest` label is an unbounded-cardinality
  write primitive pointed at our own process memory. Delivery metrics
  therefore aggregate; *which* destination is failing stays a log line,
  where it is already emitted with the error attached.

Never labeled, under any argument: user id, room id, event id, device
id, IP.

## Testing

The exporter is a route, so it tests like one: scrape it, assert the
families and the label sets. The recorder is global and set-once, which
makes the interesting test the one that runs *without* it — the
instrumented crates' existing suites, unchanged, proving the facade
stays a no-op and that no code path depends on a recorder existing.
