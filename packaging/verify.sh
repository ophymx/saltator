#!/usr/bin/env bash
# Proves the two claims the packaging makes, on real distros:
#
#   1. the baseline deb installs and runs everywhere glibc >= 2.31, and
#      pulls in no libstdc++;
#   2. the DEFAULT deb's preinst refuses a CPU without PCLMULQDQ instead
#      of letting the daemon SIGILL later.
#
# The default package is the accelerated one, so the guard is on the
# package `apt install saltator` gives you — which is the whole point of
# that arrangement, and therefore the thing worth proving.
#
# Usage: packaging/verify.sh [dist-dir]   (default ./dist)
set -uo pipefail

DIST="${1:-dist}"
# The underscore is what keeps these apart: `saltator_*.deb` does not
# match `saltator-baseline_*.deb`, because a deb filename separates name
# from version with `_` and the other name has `-` in that position.
DEFAULT=$(ls "$DIST"/saltator_*.deb 2>/dev/null | head -1)
BASE=$(ls "$DIST"/saltator-baseline_*.deb 2>/dev/null | head -1)
[ -n "$DEFAULT" ] || { echo "no default deb in $DIST" >&2; exit 1; }
[ -n "$BASE" ]    || { echo "no baseline deb in $DIST" >&2; exit 1; }
echo "default:  $DEFAULT"
echo "baseline: $BASE"

fails=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fails=$((fails+1)); }

echo
echo "=== declared dependencies ==="
dpkg-deb -f "$BASE" Package Version Depends Provides Conflicts 2>/dev/null \
  || docker run --rm -v "$PWD/$BASE:/p.deb:ro" debian:12 dpkg-deb -f /p.deb Package Version Depends

echo
echo "=== install matrix (baseline) ==="
for img in debian:11 debian:12 debian:13 ubuntu:20.04 ubuntu:22.04 ubuntu:24.04; do
    out=$(docker run --rm -v "$(readlink -f "$BASE")":/pkg.deb:ro "$img" sh -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null 2>&1
        err=$(apt-get install -y /pkg.deb 2>&1) || { echo "INSTALL-FAILED: $(echo "$err" | grep -iE "error|not found" | head -2 | tr "\n" " ")"; exit 1; }
        ldd /usr/bin/saltator | grep -q libstdc++ && { echo "LIBSTDC++-LEAKED"; exit 1; }
        # the daemon really runs, and the account the unit needs really exists
        saltator example-config | grep -q "^data_dir" || { echo "BINARY-DID-NOT-RUN"; exit 1; }
        getent passwd saltator >/dev/null || { echo "NO-SERVICE-USER"; exit 1; }
        echo "OK glibc=$(ldd --version | head -1 | grep -oE "[0-9]+\.[0-9]+$")"
    ' 2>&1 | tail -1)
    case "$out" in
        OK*) pass "$img  ($out)" ;;
        *)   fail "$img  -> $out" ;;
    esac
done

echo
echo "=== default package preinst CPU guard ==="
tmp=$(mktemp -d)
# A Core 2-era flag line: SSE4.2 and PCLMULQDQ both absent.
printf 'processor\t: 0\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr\n' > "$tmp/cpuinfo.old"
# Westmere and later: both present.
printf 'processor\t: 0\nflags\t\t: fpu vme de pse tsc sse4_2 pclmulqdq aes avx\n' > "$tmp/cpuinfo.new"

for case_name in old new; do
    out=$(docker run --rm \
            -v "$(readlink -f "$DEFAULT")":/pkg.deb:ro \
            -v "$tmp/cpuinfo.$case_name":/proc/cpuinfo:ro \
            debian:12 sh -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null 2>&1
        if apt-get install -y -qq /pkg.deb >/dev/null 2>&1; then echo INSTALLED; else echo REFUSED; fi
    ' 2>&1 | tail -1)
    case "$case_name:$out" in
        old:REFUSED)   pass "pre-Westmere cpuinfo -> install refused" ;;
        new:INSTALLED) pass "Westmere+ cpuinfo    -> install accepted" ;;
        *)             fail "cpuinfo.$case_name -> $out" ;;
    esac
done
rm -rf "$tmp"

echo
if [ "$fails" -eq 0 ]; then echo "all checks passed"; else echo "$fails check(s) failed"; fi
exit "$fails"
