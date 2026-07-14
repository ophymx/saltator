# Complement-compatible image (https://github.com/matrix-org/complement).
#
# Build context is this directory; CI copies the release binary here first:
#   cargo build --release -p saltator
#   cp target/release/saltator docker/complement/saltator
#   docker build -t complement-saltator docker/complement
#
# Base matches the CI builder (ubuntu-latest) so the prebuilt binary's
# glibc requirement is satisfied.
FROM ubuntu:24.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY saltator /usr/local/bin/saltator
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/saltator /entrypoint.sh

ENV SERVER_NAME=localhost
EXPOSE 8008 8448

HEALTHCHECK --interval=1s --timeout=2s --start-period=2s --retries=60 \
    CMD curl -fsS http://localhost:8008/_matrix/client/versions || exit 1

ENTRYPOINT ["/entrypoint.sh"]
