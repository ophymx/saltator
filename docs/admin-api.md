# Admin API

Saltator's administrative surface lives under `/_saltator/admin/v1`.

It is **our own namespace, and only ours**. No `_synapse`-prefixed paths
are served and no aliases exist for any other homeserver's admin tooling
(`docs/design-admin-identity.md`, decision 1). The accepted cost of that
choice is that an operator writes against this surface rather than
reusing someone else's scripts — which is what this document is for.

## Authentication

An ordinary access token, from an ordinary login, belonging to an account
that is an administrator:

```
Authorization: Bearer <access_token>
```

Administrator-ness resolves through exactly one function and is never
read off an account at a call site. An account is an administrator if
**either**:

- its user id is listed in `client.admin_users` in the node config, or
- its account record carries the admin flag (`PUT …/users/{id}/admin`).

The config list is the bootstrap: a fresh server has no admin account and
no way to grant one from inside, so the first administrator has to come
from outside the database. Application services are never administrators
— an AS identity is synthesized from config and has no account row to
carry a flag.

A non-admin gets `403`, with the same message whether the account lacks
the flag or does not exist: the endpoint must not be an oracle for who is
an administrator.

### Listener

The admin routes mount on the client listener by default, so a
single-node deployment needs no extra configuration. An optional
`Listeners` entry lets an operator bind them to a private interface
instead (decision 2).

## Conventions

- Request and response bodies are JSON.
- `{user_id}` is a full Matrix user id (`@alice:example.org`), percent-
  encoded in the path.
- Endpoints that change an account return that account's detail object,
  so a caller never needs a follow-up GET to see the result.
- Errors use the standard Matrix shape (`errcode`, `error`).
- List endpoints paginate with `?from=` and `?limit=`; pass the previous
  response's `next_from` to continue.

---

## Users

### `GET /users`

List accounts. Query: `from`, `limit`.

### `GET /users/{user_id}`

One account's detail.

### `POST /users/{user_id}/lock` · `POST /users/{user_id}/unlock`

Lock or unlock. Reversible and destroys nothing: no session is deleted,
so unlocking restores the user's existing devices. A locked account
cannot authenticate by any credential — password, SSO, or a login token
minted before the lock.

Locking is the operational kill switch. Synapse's read-only "suspend" is
deliberately not implemented (decision 3): enforcing it means touching
every write path, which is its own step.

### `POST /users/{user_id}/deactivate`

```json
{"erase": false}
```

Terminal — there is no reactivate. `erase` additionally marks the account
erased and clears its profile.

**`erase` does not redact the user's messages.** That is not implemented,
and an operator who needs it should know before relying on this.

### `POST /users/{user_id}/reset_password`

```json
{"new_password": "…", "logout_devices": true}
```

`logout_devices` defaults to **true**: an admin reset is usually a
response to compromise, so leaving the old sessions alive is the wrong
default. The password is hashed at the gateway — the shard command
carries an Argon2 PHC string, never the password.

### `PUT /users/{user_id}/admin`

```json
{"admin": true}
```

Grants or revokes the account admin flag. Does not affect
`client.admin_users`, which is config and outranks the flag.

### `DELETE /users/{user_id}/devices`

Revoke every session the user holds.

### `DELETE /users/{user_id}/devices/{device_id}`

Revoke one.

### `POST /users/{user_id}/notice`

```json
{"content": {"msgtype": "m.text", "body": "Scheduled maintenance at 02:00 UTC."}}
```

Send a server notice. The content is passed through rather than assembled
here, so any message type the users' clients render will work.

Requires `client.server_notices_localpart` to be set. Setting it creates
and reserves that account: the localpart is refused to `/register` from
then on, so nobody can take the name and send what looks like server
mail. The notices room is created on the first notice and reused forever.

---

## Identity links

The mapping between an account and its subject at an external identity
provider. Written here, read by the OIDC login path — see `docs/oidc.md`.

### `PUT /users/{user_id}/external_ids/{auth_provider}`

```json
{"external_id": "the-subject-at-the-idp"}
```

Idempotent. A re-link to a different subject **replaces** the old one —
that is an administrator repointing an account, and it is why the SSO
login path refuses to grandfather an account that already holds a link.

`{auth_provider}` is a stable opaque key, never a display name. For an
OIDC provider it is `oidc-{idp_id}`. **Renaming it orphans every linked
account**, which is why Synapse still carries a grandfathered `oidc-`
prefix.

Claiming a subject another account already holds returns `409`, naming
the current owner. That disclosure is deliberate and safe: only an
administrator reaches this endpoint, and they can already enumerate every
account.

Pre-linking accounts here, *then* enabling the IdP, is the migration path
that avoids a flag day — and the one that does not require the riskier
`allow_existing_users`.

### `DELETE /users/{user_id}/external_ids/{auth_provider}`

Unlink.

### `GET /auth_providers/{auth_provider}/users/{external_id}`

The reverse lookup: which account holds this subject.

---

## Rooms

### `GET /rooms` · `GET /rooms/{room_id}`

List rooms, or one room's detail. Query: `from`, `limit`.

### `DELETE /rooms/{room_id}`

```json
{"block": true, "reason": "…"}
```

**Shutdown, not purge.** Kicks the local members and (by default) blocks
re-join; `reason` is recorded on each leave event. History is not
deleted. Real purge needs a deletion primitive that interacts with
append-only history and the snapshot path, and is deferred to its own
design (decision 4).

### `PUT /rooms/{room_id}/block`

```json
{"blocked": true}
```

Close a room to joins, or reopen it. Takes a room id rather than
requiring the room to exist locally — blocking a room this server does
**not** host is the point, since a remote room that local users keep
rejoining is exactly what an operator blocks.

Note the asymmetry: blocking a remote room *contains* but does not
*evict*. Finding the local members of a non-hosted room needs a
room→users index that does not exist yet.

### `GET /blocked_rooms`

Every room currently blocked, with who blocked it and when.

---

## Registration tokens

Invite codes that authorise `/register` when the server is otherwise
closed. Turn `client.registration_requires_token` on only **after** an
administrator exists: the gate applies to everyone and only an admin can
mint tokens, so enabling it on an empty server locks it with nobody
inside.

### `GET /registration_tokens`

Every token, sorted by token string:

```json
{"registration_tokens": [
  {"token": "abc", "uses_allowed": 10, "used": 3,
   "expiry_ts": 1767225600000, "created_ts": 1760000000000,
   "valid": true}
]}
```

`uses_allowed` and `expiry_ts` are `null` for unlimited and
never-expiring respectively. `valid` is computed — whether the token
would authorise a registration right now — so an operator does not have
to compare clocks and counters themselves.

### `POST /registration_tokens`

```json
{"token": "optional", "uses_allowed": 10, "expiry_ts": 1767225600000}
```

Every field is optional: omit `token` to have the server mint one,
`uses_allowed` for unlimited, `expiry_ts` (ms since epoch) for no expiry.

A token is consumed inside the registration command itself, so a claim
cannot be stranded by an abandoned UIA session.

### `GET /registration_tokens/{token}` · `DELETE /registration_tokens/{token}`

---

## Cluster

### `GET /cluster/nodes`

The roster joined with the placement:

```json
{
  "view_from": 1,
  "leader": 1,
  "nodes": [
    {
      "node_id": 1,
      "advertise_addr": "10.0.0.1:7400",
      "status": "active",
      "groups": ["Room/0", "User/0", "FedOut/0"],
      "metadata_voter": true
    }
  ]
}
```

`view_from` is the node that answered — roster and placement come from
its own applied state, so on a follower they can trail the leader by a
replication round trip. `groups` is empty on a fully drained node, which
is the signal that it is safe to stop and remove.

### Changes must be issued to the leader

`drain`, `undrain` and `remove` are leader-only: they read-modify-write
control-plane records and change metadata group membership. On a follower
they return `409` naming where to go, and `GET /cluster/nodes` reports
the same thing in `leader`. There is no forwarding RPC — these are
operator-frequency calls, and saying plainly where to go beat inventing
one.

### Removing a node is two operations

Deliberately, and the split is the whole design:

1. **`POST /cluster/nodes/{node_id}/drain`** — the node stops being a
   placement target. Each data group's leader then reconciles it out of
   the voter set by the ordinary mechanism, which is why this works even
   for groups the draining node leads. Throughout, it stays a metadata
   voter — that is what lets it *hear* the placement update telling it to
   stand down.

   Draining the last active node is refused. There is no "gracefully shut
   down the whole cluster" operation and this is not it.

2. **`DELETE /cluster/nodes/{node_id}`** — once it holds nothing, it
   leaves the metadata group and the roster. Removing a node that is
   still active is refused; removing the node you are talking to is
   refused (take the leader out of its own group from somewhere else).

Doing both at once would cut the node off from the metadata group while
it still led groups, leaving it unable to learn it should release them.

`POST /cluster/nodes/{node_id}/undrain` is the way back, and is always
allowed — an operator who drained the wrong node needs it.

**A drained node must be taken out of service**, because it keeps its old
local state but stops receiving updates: reads go stale and writes hang.
The readiness probe below reports this, so whatever fronts the node does
it without an operator remembering to.

---

## Health probes

Unauthenticated, because a load balancer holds no token. The bodies carry
a status and a reason and nothing else — no node ids, addresses or
counts.

### `GET /_saltator/health/live`

`200` while the process is working. A failure here means *restart me*, so
it never fails for anything a restart would not fix — **a draining node
is live**.

### `GET /_saltator/health/ready`

`200 {"status": "ready"}`, or `503`:

```json
{"status": "not_ready", "reason": "draining", "detail": "…"}
```

`reason` is one of:

| reason | meaning |
|---|---|
| `draining` | An administrator drained this node. Stop sending traffic; do not restart it. |
| `no_shard_leader` | A shard has no reachable leader — quorum loss or an election in flight — so writes would not complete. |

`draining` is reported ahead of `no_shard_leader` when both hold: a node
standing its groups down has both conditions, and only one of them is the
reason.

Wire these to different orchestrator probes. Pointing a liveness check at
readiness turns a rolling drain into a crash loop.
