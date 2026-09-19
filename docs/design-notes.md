# Design notes

Decisions that are not visible from the code, and that someone would
otherwise reasonably "fix". Everything else — how a thing works — lives
in the code next to the thing.

`spec.md` has the architecture. `deferred.md` has what is deliberately
not built.

## The admin API uses our own namespace only

Admin paths are `/_saltator/admin/v1/...`. No `_synapse`-prefixed paths
are served, and no aliases exist for any other homeserver's admin
tooling.

The accepted cost is that an operator writes against this surface
instead of reusing another server's scripts, which is why the admin API
needs `admin-api.md` to be usable at all. Adding aliases would trade
that for a permanent compatibility obligation to somebody else's
undocumented surface.

Admin routes mount on the client listener by default, so a single-node
deployment needs no extra configuration; an optional listener entry
binds them to a private interface instead.

## Authentication is ours; the IdP only proves identity

MAS / MSC3861 is deliberately not adopted. Under MAS a homeserver
*unregisters* `/login`, `/refresh`, `/logout`, `/register` and the
account-management routes, handing them to a separate service. Keeping
them means every existing Matrix client works unchanged, and OIDC is an
*authentication* provider behind our own session issuance rather than a
replacement for it.

## Shard count is fixed when a cluster is founded

There is no split or merge. A deployment that outgrows its count
migrates by room export/import or cluster rebuild.

The default is 16 room shards, not the 64 the spec first named: 64 Raft
groups on a one-to-three node cluster is heartbeat and log-file
overhead with nothing to show for it, and a high group count is
precisely the condition that would force a rework of the log store. 16
still spreads leaders across any cluster up to 16 nodes. A deployment
expecting more sets a higher count at founding.

A config file that disagrees with the founded value **warns and is
ignored** rather than refusing to boot. Refusing would be louder, but it
turns an edited config file into an outage.

## Remote shard reads are storage ops, not domain commands

The read RPC carries `Get`/`Range`/`Seq` against a shard's applied
state — the store trait's read half — rather than typed domain
read-commands or whole-request forwarding.

Domain commands would be tighter-typed, but they require enumerating
every access pattern, and that enumeration never finishes. Request
forwarding cannot serve `/sync` at all: below RF = N, no single node
hosts all of one user's shards. If domain commands ever win, the
envelope is unchanged — only the op enum moves up a layer.

Reads go to the group leader behind a read-index barrier. Bounded-
staleness follower reads have a reserved field and no implementation.

## Change subscriptions carry their own backfill

`Subscribe` replays from a caller's sequence number and splices into the
live stream server-side, rather than offering a bare live stream and
letting each consumer catch up first. Consumers used to do the latter,
in five separate copies of the same read-then-splice dance, each with
its own off-by-one seam.

## Federation delivery is at-least-once, deduplicated by the receiver

There is no exactly-once machinery. The contract holds only because the
receive side does its part: to-device `message_id` dedupe (bounded and
time-horizoned), an inbound `(origin, txn_id)` response-replay cache,
and a redelivery test that asserts *exactly-once client visibility* —
uniqueness, not mere presence.

One worker owns all outbound delivery, at the federation-out shard's
leader; room and user leaders do not send. That gives one backoff
policy, one place to observe, and `proposer == leader` for cursor
writes. The cost is that outbound work does not spread across shard
leaders, which is worth revisiting if federation-out is ever placed
rather than replicated everywhere.

`saltator-fedout` is a separate crate so cs-api can enqueue without
depending on the whole federation and HTTP stack.

## Migrations run through the log, never on open

Opening a shard compares versions and either refuses or proposes; it
never rewrites state in place. A migration is a log command, so every
replica applies it identically and replay stays deterministic.

The version cell is a reserved table at `APP_TABLE_MIN`, with app
tables allocated above it.

**The all-voters-upgraded gate is enforced in code, not documented as a
rule** — a rule of that kind is a footgun with a manual. Before
proposing a migration the leader asks every voter for its live binary's
schema version over the internal RPC; any voter unreachable or behind
means no proposal, retried on a timer.

## Room shutdown is not room purge

`DELETE /rooms/{id}` kicks local members and blocks re-join. It does not
delete history. A real purge needs a deletion primitive that interacts
with append-only history and the snapshot path, and is its own design.

The same caution applies to account erasure, which clears the profile
and sets a marker but does not redact the user's messages. Calling
either one "complete" would misinform whoever is answering a
data-subject request.
