# Synapse interop test

Proves the M3 exit criterion — *join a room hosted by another server and
converse with its user* — against a **real Synapse**, not just
saltator↔saltator. This is the honest, end-to-end complement to the
Complement conformance jobs (which deploy only saltator instances).

`run.sh`:

1. mints a shared private CA and a full-chain leaf cert for each server
   (`synapse`, `saltator`), both trusting the CA;
2. runs Synapse's `generate` for a signing key, then installs
   `homeserver.yaml`;
3. brings up both on a shared docker network (`docker-compose.yml`), each
   serving federation over HTTPS on 8448 — service names double as Matrix
   server names, so peer resolution lands on the default port;
4. registers `@alice:synapse` and `@bob:saltator`;
5. `@alice` creates a public room; `@bob` **joins it over federation**
   (saltator drives make_join/send_join against Synapse);
6. each user sends a message and the test asserts the other receives it —
   exercising saltator's outbound sender *and* inbound `/send` against a
   real peer.

## Run locally

Needs Docker (with the compose plugin), `openssl`, `jq`, and a saltator
image tagged `interop-saltator:latest`:

```sh
cargo build --release -p saltator
cp target/release/saltator docker/complement/saltator
docker build -t interop-saltator:latest docker/complement
./docker/interop/run.sh
```

Generated artifacts (`ca/`, `certs/`, `synapse-data/`) are gitignored. In
CI this is the `interop (synapse)` job; the Synapse image tag is pinned in
`docker-compose.yml` — bump it deliberately.
