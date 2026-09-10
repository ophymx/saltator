# Observability

The server exports Prometheus metrics. Design and the reasoning behind
the choices live in `docs/design-observability.md`; this is the operator's
reference.

Logs are the other half and are unchanged: structured `tracing` output on
stdout, filtered with `RUST_LOG`.

## Turning it on

One line, and no exporter exists without it:

```toml
[listeners]
metrics = "127.0.0.1:9464"
```

Then `GET http://127.0.0.1:9464/metrics`. Nothing else is served on that
port.

**The bind address is the access control.** The exporter has no
authentication, and a scrape describes this server: request volume, error
rates, how many accounts and rooms exist, how big the cluster is, which
shards this node leads, and how much federation delivery is failing.
Loopback, or an interface only the monitoring system can reach. Binding
it anywhere else logs a warning at startup, and that warning is the only
thing standing between the address and the internet.

`9464` is the OpenTelemetry Prometheus exporter's port. It is a
suggestion, chosen because `9100` almost certainly already belongs to a
node_exporter on the same host.

A scrape config:

```yaml
scrape_configs:
  - job_name: saltator
    static_configs:
      - targets: ["127.0.0.1:9464"]
```

## What is exported

### HTTP

Labeled `surface` (`client` or `federation`), `method`, `route`, and —
for the counter — `status`.

| metric | type | meaning |
| --- | --- | --- |
| `saltator_http_requests_total` | counter | requests served |
| `saltator_http_request_duration_seconds` | histogram | time to respond |
| `saltator_http_requests_in_flight` | gauge | requests being served now |

`route` is the *route template* — `/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`,
not the path that matched it. Requests that match no route share the
single label value `<unmatched>`. `method` is likewise bounded: anything
outside the standard HTTP methods collapses into `<other>`, because a
client can send any token as a method and a label must not be a thing
strangers can mint.

Both surfaces are counted the same way, but the same status means
different things on each: a 401 on `client` is somebody's password, on
`federation` it is a signature that did not verify.

### Shards

Labeled `keyspace` (`meta`, `room`, `user`, `fedout`) and `shard`.

| metric | type | meaning |
| --- | --- | --- |
| `saltator_shard_proposals_total` | counter | Raft proposals, by `outcome`: `local`, `forwarded`, `error` |
| `saltator_shard_proposal_duration_seconds` | histogram | proposal to response, by `outcome` |
| `saltator_shard_apply_duration_seconds` | histogram | applying one committed batch |
| `saltator_shard_applied_entries_total` | counter | log entries applied |
| `saltator_shard_leader` | gauge | 1 where this node leads the group |
| `saltator_shard_seq` | gauge | latest emitted change sequence |
| `saltator_shard_voters` | gauge | voting members of the group |

`outcome="forwarded"` is worth an alert of its own. It means writes
arrived at a node that does not lead that shard and were relayed — which
works, and costs a round trip on every one of them. A steady stream of it
usually means a load balancer is sending traffic somewhere reasonable and
the leadership is somewhere else.

`saltator_shard_leader` summed across the cluster is 1 per group when
healthy. Zero means an election is in progress. The `meta` group reports
no `saltator_shard_seq`: it has no shard app and so no sequence.

### Federation delivery

Aggregate — see "no destination label" below.

| metric | type | meaning |
| --- | --- | --- |
| `saltator_federation_pdu_queue_delay_seconds` | histogram | event creation → its transaction's PUT starting |
| `saltator_federation_pdu_put_duration_seconds` | histogram | the round trip itself |
| `saltator_federation_pdus_sent_total` | counter | PDUs in acked transactions |
| `saltator_federation_transactions_total` | counter | outbound transactions, by `kind` (`pdu`/`edu`) and `outcome` |
| `saltator_federation_destinations_backed_off` | gauge | remote servers in a backoff window |

The two histograms are the point of the split: `queue_delay` is ours to
shorten (our apply, the worker's wake-up, a pass already in flight),
`put_duration` is the network and the remote server's ingest. When
federation feels slow, which of the two is fat decides what to fix.

Two honesty notes. `queue_delay` samples only transactions carrying at
least one event this server authored: a relayed event's
`origin_server_ts` is the remote author's clock, and its skew would
poison the histogram. And `transactions_total` counts *wire*
transactions — a batch whose local ack failed (mid-election) is re-sent
and counts again, so during cluster unrest `outcome="ok"` can exceed
the number of logical deliveries.

### Process

`saltator_build_info{version}` is always 1 — the label is the payload, so
a regression can be joined to the version it arrived in.
`saltator_uptime_seconds` drops to zero on restart.

## What is deliberately not a label

Nothing carries a user id, room id, event id, device id, or IP address.
Nor does anything carry a **remote server name**: federation destinations
are supplied by whoever federates with us, so a `dest` label would be an
unbounded-cardinality write into this process's memory driven by
strangers. Which destination is failing is a log line — `delivery.rs`
emits it with the error attached — and a log query is the right tool for
a question whose answer is a handful of names.

If you add a metric, that rule is the one to keep. `crates/saltator/tests/e2e.rs`
asserts it: a scrape of a running node with a registered user and a
created room must contain neither.
