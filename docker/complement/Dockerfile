# Complement-compatible image (https://github.com/matrix-org/complement).
#
# Build context is this directory; CI copies the release binary here first:
#   cargo build --release -p saltator
#   cp target/release/saltator docker/complement/saltator
#   docker build -t complement-saltator docker/complement
#
# Base matches the CI builder (`build` runs on ubuntu-24.04, pinned there
# for exactly this reason) so the prebuilt binary's glibc requirement is
# satisfied. The coupling is the point to notice: a dynamically-linked
# build carries its builder's glibc floor and nothing declares it, so the
# two pins have to be moved together or the image dies at exec with
# `GLIBC_2.xx not found`. Bumping one alone is the failure mode.
#
# The way out is the one pg-agent-rs took — build static against musl and
# the floor stops existing — which saltator cannot do yet: librocksdb-sys
# compiles C++, and Debian's `musl-tools` ships musl-gcc without a musl
# g++. Until that is sorted (a musl cross image such as
# messense/rust-musl-cross, or a C++-capable musl sysroot), keep the pins
# married. INTENTION.md's "single static binary where possible" is the
# standing intent.
#
# The binary carries a second undeclared floor, for the same reason: CI
# builds with `-C target-cpu=x86-64-v2 -C target-feature=+pclmulqdq` so
# RocksDB gets hardware CRC32c, and RocksDB no longer does runtime feature
# detection on x86 — it just runs the instructions. So this image needs a
# host with SSE4.2 and PCLMULQDQ and dies with SIGILL without them.
# PCLMULQDQ is the binding one (Intel Westmere 2010, AMD Bulldozer 2011),
# but the practical floor is 2013: the low-power lines lag, and Silvermont
# and Jaguar are where Atom-class silicon picks these up. Not a concern on
# CI runners or any current server; it is a concern on a small or old box,
# and nothing in the image declares it. See the RUSTFLAGS comment in
# .github/workflows/ci.yml.
FROM ubuntu:24.04

# haproxy + procps serve only CLUSTER_NODES>1 (the local hardening
# harness); they are small and keep this a single image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates openssl haproxy procps \
    && rm -rf /var/lib/apt/lists/*

COPY saltator /usr/local/bin/saltator
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/saltator /entrypoint.sh

ENV SERVER_NAME=localhost
# 1 = single node (CI). Build a local hardening image with
#   docker build --build-arg CLUSTER_NODES=3 [--build-arg CHURN_INTERVAL=20] ...
ARG CLUSTER_NODES=1
ARG CHURN_INTERVAL=0
ENV CLUSTER_NODES=$CLUSTER_NODES
ENV CHURN_INTERVAL=$CHURN_INTERVAL
EXPOSE 8008 8448

HEALTHCHECK --interval=1s --timeout=2s --start-period=2s --retries=60 \
    CMD curl -fsS http://localhost:8008/_matrix/client/versions || exit 1

ENTRYPOINT ["/entrypoint.sh"]
