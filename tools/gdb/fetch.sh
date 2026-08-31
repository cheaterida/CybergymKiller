#!/usr/bin/env bash
# Build static gdb binaries for the cybergym_gdb tool.
#
# Needs network (netunlock) + docker. Produces fully-static single-file gdbs in
# bin/ (gitignored). Usage:
#   bash fetch.sh            # build both versions in one container (apt once)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
mkdir -p bin build

if [ -x bin/gdb-13 ] && [ -x bin/gdb-8.3 ]; then
  echo "==> bin/gdb-13 and bin/gdb-8.3 already exist (remove to rebuild)"
  exit 0
fi

echo "==> building gdb-13.2 + gdb-8.3.1 (single container, apt once; several minutes)"
docker run --rm \
  -v "$PWD/build:/build" \
  ubuntu:20.04 bash -c '
    set -e
    # Force IPv4: archive.ubuntu.com resolves only to IPv6 here and the docker
    # bridge has no IPv6 route, so plain apt hangs.
    APT="apt-get -o Acquire::ForceIPv4=true"
    $APT update -qq >/dev/null 2>&1
    # -dev libs for gmp/mpfr are needed by the gdb configure step (static-link
    # into the single file, so still no dynamic deps); file + texinfo are needed
    # by the gdb build itself (opcodes/bfd). readline/ncurses stay absent.
    DEBIAN_FRONTEND=noninteractive $APT install -y -qq \
      wget build-essential file texinfo libgmp-dev libmpfr-dev >/dev/null 2>&1
    # NOTE: do NOT delete libgmp.so/libmpfr.so here - the gcc cc1 loads
    # libmpfr.so.6 at runtime, so the compiler would break. gdb-13 links them
    # dynamically (fine on oss-fuzz images); gdb-8.3 links them statically and
    # is the universal fallback for images without these libs.

    build_one() {
      local VER=$1 OUT=$2
      cd /build
      if [ ! -d "gdb-$VER" ]; then
        wget -q "https://ftp.gnu.org/gnu/gdb/gdb-$VER.tar.gz"
        tar xf "gdb-$VER.tar.gz"
      fi
      rm -rf "bld_$VER"
      mkdir -p "bld_$VER"
      cd "bld_$VER"
      ../gdb-$VER/configure --prefix=/usr/local \
        --without-python --without-guile --without-tui --without-readline \
        --without-libexpat --without-lzma --without-zlib --without-babeltrace \
        --without-source-highlight \
        --disable-gdbserver --disable-werror \
        CFLAGS="-O2 -static" LDFLAGS="-static" >/dev/null
      make -j"$(nproc)" all-gdb >/dev/null
      cp gdb/gdb "/build/$OUT"
      cd /build
    }

    if [ ! -x /build/gdb-13 ]; then build_one 13.2 gdb-13; fi
    if [ ! -x /build/gdb-8.3 ]; then build_one 8.3.1 gdb-8.3; fi
  '

mv -f build/gdb-13 bin/gdb-13 2>/dev/null || true
mv -f build/gdb-8.3 bin/gdb-8.3 2>/dev/null || true
echo "==> results:"
file bin/gdb-13 bin/gdb-8.3 2>/dev/null || true
ls -la bin/
