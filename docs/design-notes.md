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

A stored record's field list is part of that version. Postcard encodes
fields positionally, so appending a field makes every older row
undecodable — `#[serde(default)]` does not help, because the decoder
runs out of bytes before serde is asked for a default. The userserver's
`Account` v2→v3 is the worked example, and it asserts that a v2-shaped
read *fails*: that is what makes the migration load-bearing rather than
cosmetic.

**The all-voters-upgraded gate is enforced in code, not documented as a
rule** — a rule of that kind is a footgun with a manual. Before
proposing a migration the leader asks every voter for its live binary's
schema version over the internal RPC; any voter unreachable or behind
means no proposal, retried on a timer.

## The schema gate protects the log, not reads

A migration is proposed only once every voter's binary supports the target,
which is what stops a replica being handed a command it cannot decode. It
says nothing about reads, and the gap between the two is a real window: a
node restarted on the new binary serves traffic immediately, while the
migration its data needs is still waiting for the slowest node in the
fleet. For that window, new code is reading old data.

Two shapes of this, both found by `scripts/rolling_upgrade_smoke.sh`
rather than by reasoning:

- **A record that gained a field does not decode at all.** Postcard is
  positional, so the read fails outright rather than losing the field —
  `TokenEntry` gaining its mirrored account state turned every
  authenticated request on an upgraded node into a 500. The fix is a
  tolerant read (`decode_token`) that recognises both shapes and tells the
  caller which one it got, so the caller can fall back to what the old
  version did.
- **A table a read depends on is still empty.** `T_USERNAME` is backfilled
  by its migration, so before that an upgraded node asked an empty table
  whether a name was taken and answered "free" for names that were not.
  The fix is to check the stored schema version and fall back until the
  backfill has run.

So the rule for a migration that changes what a read sees: the read has to
work on both sides of it, and the fallback is removable only once the
oldest supported version is past the step. The gate is not a substitute
for that, and neither is the assumption that a restart and its migration
happen together — they cannot, by design.

## A token row answers its own authentication

Authenticating a request reads the token table and nothing else. The
owning account's state is mirrored onto the token row, rather than read
from the account, because the account is per-user state and per-user
state is what the user keyspace will eventually place elsewhere — a
remote read on every authenticated request is not a seam worth having.

A mirror is only as good as what maintains it, so the writers are few and
each is the whole of its case. `write_session` stamps the state from the
account it has just read, which makes a session minted for a
non-authenticating account *born* unusable — a future login path that
forgets its own check cannot hand out a live token. `SetLocked` rewrites
the user's rows in place, reached through their devices, which already
index the live hashes; lock destroys no session and unlock restores it,
so editing beats deleting. Deactivation needs no arm at all: it deletes
every device, and every token with them.

The check itself stays `AccountState::can_authenticate`, so a state added
later is refused until something deliberately stamps it — closed by
default, in one place.

## Transaction records live with whatever they are scoped to

A client transaction ID is scoped to the device and the endpoint path,
and two of the three endpoints carrying one — `/send` and `/redact` —
name a room. So their record goes into that room's shard, in the same
write batch as the event: no retry can observe the event without the
record that deduplicates it, and the send path gains no second Raft
group. The reverse index that stamps `unsigned.transaction_id` rides
along, beside the event the sync path is already reading.

`/sendToDevice` names no room, so its record goes into the user shard —
and there it is a separate command, proposed last, after the inbox write
and the EDU enqueue. Marking before those would turn a failure into lost
messages rather than a duplicate, which is the worse trade.

The uniform alternative, everything in the user shard, reads better on
paper and is worse in fact: a second Raft group on every send, no
atomicity to show for it, and a user-shard lookup on every timeline
event the sync path serves.

## Room shutdown is not room purge

`DELETE /rooms/{id}` kicks local members and blocks re-join. It does not
delete history. A real purge needs a deletion primitive that interacts
with append-only history and the snapshot path, and is its own design.

The same caution applies to account erasure, which clears the profile
and sets a marker but does not redact the user's messages. Calling
either one "complete" would misinform whoever is answering a
data-subject request.
