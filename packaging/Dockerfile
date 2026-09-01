# syntax=docker/dockerfile:1
#
# Builds the two Debian packages. Run it from the repo root:
#
#   DOCKER_BUILDKIT=1 docker build -f packaging/Dockerfile -o type=local,dest=dist .
#
# and the .debs land in ./dist.
#
# WHY DEBIAN 11, AND WHY THAT IS THE WHOLE POINT
#
# A dynamically-linked binary carries its *builder's* glibc floor. Build on
# the dev box (trixie, glibc 2.41) and the deb demands 2.41 from everyone
# who installs it. Bullseye's 2.31 is the oldest floor that still buys
# anything for a deb: it covers Debian 11/12/13 and Ubuntu
# 20.04/22.04/24.04, which is every live deb-consuming distro. Going older
# (buster, 2.28) only adds distros that are long EOL.
#
# Unlike the Complement image, this floor is not undeclared. `depends =
# "$auto"` in crates/saltator/Cargo.toml runs dpkg-shlibdeps, which reads
# the binary's versioned symbols and writes the real `libc6 (>= 2.31)` into
# the control file -- so apt refuses the install on an older system rather
# than letting it die at exec with `GLIBC_2.xx not found`. That is the
# difference between this and the coupling docker/complement/Dockerfile
# warns about.
#
# Bullseye's LTS ended in August 2026. It is a build container, not a
# runtime, so it stops receiving updates rather than becoming exploitable
# here; revisit when the 2.31 floor stops being worth it.
FROM debian:11 AS builder

# clang/libclang: bindgen runs with the `bindgen-runtime` feature and
# dlopens libclang at build time. gcc 10 is the compiler for RocksDB's C++,
# comfortably past its GCC >= 7 / C++17 requirement.
# dpkg-dev: dpkg-shlibdeps, for `depends = "$auto"`.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        libclang-dev \
        llvm-dev \
        pkg-config \
        dpkg-dev \
        fakeroot \
        curl \
        ca-certificates \
        file \
    && rm -rf /var/lib/apt/lists/*

# Only libstdc++.a lives in here, so `-L /opt/staticcxx` ahead of the system
# path makes the linker resolve librocksdb-sys's `-lstdc++` to the archive.
#
# The obvious flag does NOT work: rustc drives the link with `cc`, not
# `g++`, so there is no implicit libstdc++ for `-static-libstdc++` to
# rewrite, and the `-lstdc++` actually comes from librocksdb-sys calling
# `cpp_link_stdlib("stdc++")`. `CXXSTDLIB=` does not help either -- an
# explicit cpp_link_stdlib() call takes priority over that env var in the
# `cc` crate. Verified: this drops libstdc++.so.6 from ldd and leaves zero
# GLIBCXX_* symbols, for about 800 KB.
RUN mkdir -p /opt/staticcxx \
    && ln -s "$(g++ -print-file-name=libstdc++.a)" /opt/staticcxx/libstdc++.a \
    && test -e /opt/staticcxx/libstdc++.a

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# No toolchain named here on purpose: rustup reads rust-toolchain.toml and
# installs the pin the repo already carries, so this image cannot drift from
# what CI and the dev box compile with.
WORKDIR /build
COPY rust-toolchain.toml ./
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --no-modify-path --default-toolchain none \
    && rustup show \
    && rustc --version

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install cargo-deb --locked --version '^2'

COPY . .

# Two full builds, because the variants differ in RUSTFLAGS and that
# invalidates every crate. Both happen in one RUN so the target/ cache mount
# is still alive for the second, and so the .debs get copied to /out before
# the mount goes away.
#
# -C link-arg=-static-libgcc pairs with the -L above: libstdc++.a needs an
# unwinder and this takes it from libgcc_eh.a rather than libgcc_s.so.1.
# It works here and was a no-op on the dev box only because the local
# .cargo/config.toml sets clang as the linker; this image uses gcc's cc.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    set -eux; \
    mkdir -p /out packaging/config; \
    STATIC_CXX="-L /opt/staticcxx -C link-arg=-static-libgcc"; \
    \
    echo '=== baseline (portable x86-64) ==='; \
    RUSTFLAGS="$STATIC_CXX" cargo build --profile dist -p saltator --bin saltator; \
    \
    ldd target/dist/saltator; \
    ! ldd target/dist/saltator | grep -q libstdc++; \
    ! objdump -T target/dist/saltator | grep -q GLIBCXX; \
    \
    ./target/dist/saltator example-config > packaging/config/saltator.toml; \
    \
    echo '--- max versioned glibc symbol (baseline) ---'; \
    objdump -T target/dist/saltator | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1; \
    \
    cargo deb -p saltator --profile dist --no-build --variant baseline --output /out; \
    \
    echo '=== x86-64-v2 (hardware CRC32c) ==='; \
    RUSTFLAGS="$STATIC_CXX -C target-cpu=x86-64-v2 -C target-feature=+pclmulqdq" \
        cargo build --profile dist -p saltator --bin saltator; \
    \
    ! ldd target/dist/saltator | grep -q libstdc++; \
    \
    cargo deb -p saltator --profile dist --no-build --variant v2 --output /out; \
    \
    ls -la /out

FROM scratch AS export
COPY --from=builder /out/ /
