# Debian packages

Two `.deb`s, built in a `debian:11` container so the binary's glibc floor
is 2.31 rather than whatever the build machine happens to run.

```sh
DOCKER_BUILDKIT=1 docker build -f packaging/Dockerfile --target export \
  -o type=local,dest=dist .
packaging/verify.sh dist        # installs them across six distros
```

| package | CPU requirement | RocksDB CRC32c |
| --- | --- | --- |
| `saltator` | any x86-64 | software |
| `saltator-x86-64-v2` | SSE4.2 + PCLMULQDQ (Westmere 2010 / Bulldozer 2011) | hardware |

They `Conflict` with each other and both `Provide: saltator-homeserver`, so
exactly one is installed at a time.

## Why a container, and why bullseye

A dynamically-linked binary carries its *builder's* glibc floor. Built on a
trixie dev box the deb demands glibc 2.41 from everyone who installs it;
built on bullseye it demands 2.31, which covers Debian 11/12/13 and Ubuntu
20.04/22.04/24.04 — every live deb-consuming distro. Going older (buster,
2.28) only adds distros that are long EOL.

The important half is that **the floor is declared**. `depends = "$auto"`
runs `dpkg-shlibdeps`, which reads the binary's versioned symbols and
writes the real `libc6 (>= 2.31)` into the control file, so apt refuses the
install on an older system. That is precisely what
`docker/complement/Dockerfile` warns about and cannot fix: there, a
mismatched base dies at exec with `GLIBC_2.xx not found` and nothing
declares the coupling. Here dpkg declares it.

Bullseye's LTS ended in August 2026. It is a build container, not a
runtime, so it stops receiving updates rather than becoming exposed;
revisit when 2.31 stops being worth targeting.

## The C++ runtime is linked statically

`libstdc++.so.6` is gone from `ldd` and the binary needs zero `GLIBCXX_*`
symbols, which costs about 800 KB and removes a whole version axis from the
package's dependencies.

The obvious flag does not do this. `-static-libstdc++` is a **no-op** here:
rustc drives the link with `cc`, not `g++`, so there is no implicit
libstdc++ for that flag to rewrite, and the `-lstdc++` actually comes from
librocksdb-sys calling `cpp_link_stdlib("stdc++")` (its `build.rs:304`).
`CXXSTDLIB=` does not help either — an explicit `cpp_link_stdlib()` call
takes priority over that env var in the `cc` crate.

What works is putting `libstdc++.a` alone in a directory that precedes the
system one, so the linker resolves `-lstdc++` to the archive:

```sh
ln -s "$(g++ -print-file-name=libstdc++.a)" /opt/staticcxx/libstdc++.a
RUSTFLAGS="-L /opt/staticcxx -C link-arg=-static-libgcc"
```

`-static-libgcc` pairs with it: `libstdc++.a` needs an unwinder, and this
takes it from `libgcc_eh.a` instead of `libgcc_s.so.1`. Note it is silently
dropped if your linker is clang — which is the case on a dev box using the
README's local-acceleration recipe, and is why this belongs in the image
rather than in `.cargo/config.toml`.

glibc itself stays dynamic on purpose: `getaddrinfo` dlopens NSS modules,
and this server resolves SRV and well-known records for federation.

## Why two packages instead of a runtime check

RocksDB stopped doing runtime feature detection on x86, so an
`x86-64-v2`-built binary executes SSE4.2 and PCLMULQDQ unconditionally and
dies with SIGILL on older hardware — at an arbitrary point, with no
diagnostic that points at the build flags.

`Depends:` cannot express "needs PCLMULQDQ". So the v2 package checks
`/proc/cpuinfo` in its `preinst` and fails the install with a message
naming the baseline package, while there is still something to read. The
baseline package has no such check because it needs none.

## Verified

`packaging/verify.sh` installs the baseline deb on each of these, checks the
binary runs, that no `libstdc++` leaked, and that the service account
exists; then bind-mounts a synthetic `/proc/cpuinfo` to exercise the v2
guard both ways.

| target | glibc | result |
| --- | --- | --- |
| debian:11 | 2.31 | pass |
| debian:12 | 2.36 | pass |
| debian:13 | 2.41 | pass |
| ubuntu:20.04 | 2.31 | pass |
| ubuntu:22.04 | 2.35 | pass |
| ubuntu:24.04 | 2.39 | pass |
| pre-Westmere cpuinfo | — | v2 install refused |
| Westmere+ cpuinfo | — | v2 install accepted |

Declared dependencies come out as `adduser, libc6 (>= 2.30)`. The 2.30 is
lower than bullseye's own 2.31 because `dpkg-shlibdeps` reports what the
binary *actually* references, not what the builder happens to run.

`adduser` is listed explicitly and is not optional: Debian 13 and Ubuntu
24.04 dropped it from the base system, so before it was declared, `postinst`
died with `adduser: not found` at configure time on precisely the two
newest targets while every older one passed.

## Installing

```sh
apt-get install ./saltator_0.0.1_amd64.deb
$EDITOR /etc/saltator/saltator.toml     # server_name, at minimum
systemctl enable --now saltator
```

The unit is deliberately **not** enabled or started on install: the shipped
config has `server_name = "example.org"` and the daemon cannot do anything
useful until that is changed. Starting a broken unit on install teaches
people to ignore systemd failures.

| path | what |
| --- | --- |
| `/usr/bin/saltator` | the binary |
| `/etc/saltator/saltator.toml` | conffile, `0640 root:saltator`; dpkg preserves your edits across upgrades |
| `/var/lib/saltator` | signing key and all room state; created by `StateDirectory=` in the unit |

The conffile is generated at package time by running `saltator
example-config`, so it cannot drift from `config.rs`.

`purge` deliberately leaves `/var/lib/saltator` alone and says so: it holds
the signing key and every room this server has ever seen, and losing it is
unrecoverable — a federated server that loses its signing key cannot be
rebuilt from its peers.

## Not covered

- **arm64.** The builder is amd64-only. Cross-building RocksDB's C++ is the
  work; the packaging above is architecture-agnostic apart from the v2
  variant, which is meaningless off x86.
- **A release job.** Nothing in `.github/workflows/ci.yml` builds these.
  Wiring it up means running this image on a tag and attaching `dist/*.deb`
  to the release.
- **An apt repository.** These are standalone files; there is no signed
  suite to `apt-add-repository`.
