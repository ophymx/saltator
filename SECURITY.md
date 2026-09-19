# Security policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**<https://github.com/ophymx/saltator/security/advisories/new>**

Please don't open a public issue for something exploitable.

A useful report says what an attacker can do and how you got there —
the request, the room or federation shape, the server config if it
matters. A proof of concept helps and is never required.

## What to expect

Honestly, and deliberately not dressed up:

- **One person maintains this**, as a side project. There is no team,
  no on-call rotation, and no response-time commitment. Reports are
  read and taken seriously; how fast one is fixed depends on what else
  is happening that week.
- **No bounty.** There is no money behind this project.
- **There are no releases yet.** Nothing has been tagged or published,
  so there is no supported-version matrix and nothing to backport to.
  A fix lands on `main` and that is the whole distribution story today.
- **No deployment is run by the maintainer**, so there is no "actively
  exploited in production" path to escalate through.
- **Nothing here has been audited externally.** The code has had a
  structured self-review — see below — which is not the same thing and
  should not be read as one.

If those expectations don't suit what you've found, that's a fair
reason to disclose on your own timeline. Saying so up front seems
better than implying a process that does not exist.

## What has been done

Stated as work performed, not as a guarantee:

- A full security review of the server, whose findings were fixed and
  closed, including the pre-authentication SSRF surface on outbound
  federation, cross-signing key-chain validation, and host-in-room
  enforcement on the endpoints that serve room data.
- Mutual TLS on the internal cluster RPC, so a node's control plane is
  not reachable by anything that isn't a cluster member.
- Signing keys are encrypted at rest under a cluster key, so backups
  and shipped checkpoints do not carry them in the clear.
- Two CI gates gained from that review, which fail the build rather
  than relying on anyone remembering the rule.

## Known, and accepted

- **A client can make this server fetch media from any server it
  names.** An `mxc://` URI carries the origin server, and serving
  remote media means fetching from it, so this is inherent to the
  protocol rather than a flaw in this implementation. Private,
  loopback and link-local targets are refused before any connection is
  attempted; what remains is that the server can be induced to issue
  signed GETs to arbitrary *public* Matrix servers. Reported again, it
  will be closed as known — but a way around the private-address guard
  is very much a vulnerability, and worth reporting.
- **This is pre-release software.** It has not run in production
  anywhere. Treat unknown-unknowns as likely.

## Scope

In scope: the homeserver itself — the client-server API, federation,
the admin API, the clustering and internal RPC surfaces, and the
storage layer.

Out of scope, because they are not defects in this code:

- Anything requiring an administrator's credentials to begin with. The
  admin API is *designed* to be powerful for whoever holds an admin
  token.
- Endpoints documented as deliberately not implemented, which answer
  with an error by design (`docs/federation-endpoints.md`).
- Vulnerabilities in dependencies, unless this project's use of one is
  what makes it exploitable. Report those upstream; tell us too if we
  should pin or patch around it.
