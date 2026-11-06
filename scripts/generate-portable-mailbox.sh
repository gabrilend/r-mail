#!/bin/sh
# generate-portable-mailbox.sh — build a portable mailbox's program from source, for one architecture
#
# Issue #617.  A portable mailbox drive carries its own program (#102,
# #616): the daemon, its own Lua, luasocket and the two rmail libraries.
# This builds that program on purpose, for the drive, instead of copying
# whatever scripts/install.sh happened to build for this machine:
#
#   - Lua built with `make linux`, never linux-readline: it needs libc and
#     libm and nothing else from a host;
#   - OpenSSL configured down to what rmail uses (#619's flag set) and
#     linked into the crypto module, so no host OpenSSL is needed;
#   - luasocket and the two rmail libraries against that Lua;
#   - nothing else: no Android client, no docs, no issues, no transcripts.
#
# Shaped like install.sh: numbered phases, each making one thing, each
# skipping what a previous run already made and saying which it did.  It
# takes arguments and asks no questions: it builds an artefact, it does
# not set up anybody's mail.
#
#   0  target    the architecture and its compiler; refuses, naming the
#                package, when the toolchain is not installed
#   1  sources   the three source archives, from --sources (default
#                deps/sources/), downloaded only when missing and allowed
#   2  Lua       make linux, installed into the build tree
#   3  OpenSSL   static, with everything rmail does not use turned off
#   4  luasocket socket/core.so and mime/core.so against that Lua
#   5  rmail     rmail_crypto.so with OpenSSL linked in (checked to need no
#                libcrypto from a host), rmail_inotify.so
#   6  payload   laid out as a drive's source-code/ folder, with each
#                dependency's licence, BUILD-NOTES.txt and ARCH (the
#                target, for make-mailbox-drive.sh); checked: on this
#                machine's own architecture the built Lua loads the built
#                libraries and round-trips an encryption, on another every
#                binary is checked to be for the architecture asked for
#
# What it makes, under --out (default deps/portable/):
#
#   <target>/build/      unpacked sources and each phase's output
#   <target>/payload/    the program, ready for make-mailbox-drive.sh
#                        --payload to place on a drive
#
# Usage:
#   scripts/generate-portable-mailbox.sh [--target x86_64|aarch64]
#       [--out DIR] [--sources DIR] [--offline] [--force]
#
#   --target    the architecture to build for (default: this machine's)
#   --out       where builds and payloads go (default: deps/portable/)
#   --sources   where the source archives are kept (default: deps/sources/)
#   --offline   never download: a missing archive is refused, naming it
#   --force     rebuild every phase, ignoring what a previous run made
#
# Exit status 0 when the payload is built and checked, 1 otherwise.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

LUA_VERSION="5.4.7"
LUASOCKET_VERSION="3.1.0"
# #619 measured the minimal configuration on 3.5.1
OPENSSL_VERSION="3.5.1"

# Everything rmail does not use, turned off (#619): rmail needs AES-256-GCM
# and SHA-256 and nothing else.  The provider machinery stays, because
# OpenSSL 3 routes AES-GCM through it.
OPENSSL_OFF="no-shared no-tests no-docs no-apps no-tls no-dtls no-quic no-ec no-dh no-dsa no-engine no-legacy no-comp no-deprecated"

info() { printf "  %s\n" "$*"; }
ok()   { printf "  \033[32m%s\033[0m\n" "$*"; }
warn() { printf "  \033[33m%s\033[0m\n" "$*"; }
err()  { printf "  \033[31merror: %s\033[0m\n" "$*" >&2; }
phase() { echo ""; echo "[$1] $2"; }

TARGET=""
OUT="$ROOT/deps/portable"
SOURCES="$ROOT/deps/sources"
OFFLINE=false
FORCE=false

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) sed -n '2,/^# Exit status/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        --target) TARGET="${2:-}"; shift 2 ;;
        --target=*) TARGET="${1#*=}"; shift ;;
        --out) OUT="${2:-}"; shift 2 ;;
        --out=*) OUT="${1#*=}"; shift ;;
        --sources) SOURCES="${2:-}"; shift 2 ;;
        --sources=*) SOURCES="${1#*=}"; shift ;;
        --offline) OFFLINE=true; shift ;;
        --force) FORCE=true; shift ;;
        *) err "unknown argument: $1 (see --help)"; exit 1 ;;
    esac
done

[ -n "$OUT" ] || { err "--out needs a folder"; exit 1; }
[ -n "$SOURCES" ] || { err "--sources needs a folder"; exit 1; }

# ============================================================
# 0 — the target and its toolchain
# ============================================================

# uname's names and the GNU triple's agree for these two
host_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        *) uname -m ;;
    esac
}
HOST=$(host_arch)
TARGET="${TARGET:-$HOST}"

case "$TARGET" in
    x86_64)  OPENSSL_TARGET="linux-x86_64";  ELF_MACHINE="Advanced Micro Devices X86-64" ;;
    aarch64) OPENSSL_TARGET="linux-aarch64"; ELF_MACHINE="AArch64" ;;
    *) err "no build for '$TARGET': the targets are x86_64 and aarch64 (#619)"; exit 1 ;;
esac

phase 0 "target: $TARGET"

# needs <command> <package that has it>
needs() {
    if ! command -v "$1" >/dev/null 2>&1; then
        err "$1 is not installed: it comes with $2"
        exit 1
    fi
}

if [ "$TARGET" = "$HOST" ]; then
    CROSS=""
    CC="${CC:-cc}"
    needs "$CC" "your distribution's C compiler (gcc or build-essential)"
else
    CROSS="$TARGET-linux-gnu-"
    CC="${CROSS}gcc"
    if ! command -v "$CC" >/dev/null 2>&1; then
        err "no compiler for $TARGET: $CC is not installed"
        err "  it comes with gcc-$TARGET-linux-gnu (Debian, Ubuntu)"
        err "  or cross-$TARGET-linux-gnu (Arch); install it and run this again"
        exit 1
    fi
fi
AR="${CROSS}ar"
RANLIB="${CROSS}ranlib"
needs "$AR" "binutils"
needs make "make"
needs perl "perl (OpenSSL's Configure is a perl script)"
needs tar "tar"
needs readelf "binutils (readelf checks what each binary needs)"
ok "compiler: $CC"

WORK="$OUT/$TARGET"
BUILD="$WORK/build"
PAYLOAD="$WORK/payload"
if $FORCE; then rm -rf "$BUILD"; fi
mkdir -p "$BUILD" "$SOURCES"

# ============================================================
# 1 — the sources
# ============================================================

phase 1 "sources ($SOURCES)"

download() {  # <url> <file>
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$2.part" "$1"
    elif command -v curl >/dev/null 2>&1; then
        curl -sfL -o "$2.part" "$1"
    else
        err "neither wget nor curl is installed, and $(basename "$2") is not in $SOURCES"
        return 1
    fi
}

# source <file name> <url>: present in SOURCES, or downloaded there
source_archive() {
    if [ -s "$SOURCES/$1" ]; then
        ok "found $1"
        return 0
    fi
    if $OFFLINE; then
        err "$1 is not in $SOURCES, and --offline says not to download it"
        err "  it is at $2"
        exit 1
    fi
    info "downloading $1"
    if ! download "$2" "$SOURCES/$1"; then
        rm -f "$SOURCES/$1.part"
        err "could not download $1 from $2"
        err "  put it in $SOURCES by hand, or run this where that address can be reached"
        exit 1
    fi
    mv "$SOURCES/$1.part" "$SOURCES/$1"
    ok "downloaded $1"
}

source_archive "lua-$LUA_VERSION.tar.gz" "https://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz"
source_archive "openssl-$OPENSSL_VERSION.tar.gz" \
    "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
source_archive "luasocket-$LUASOCKET_VERSION.tar.gz" \
    "https://github.com/lunarmodules/luasocket/archive/refs/tags/v$LUASOCKET_VERSION.tar.gz"

# unpack <archive> <folder it unpacks to>: a fresh copy in BUILD
unpack() {
    rm -rf "$BUILD/$2"
    tar xzf "$SOURCES/$1" -C "$BUILD"
    if [ ! -d "$BUILD/$2" ]; then
        err "$1 did not unpack to $2/"
        exit 1
    fi
}

# The licence harvest is install.sh's own routine, lifted out of it the
# way scripts/test-license-harvest.sh lifts it, so the two cannot drift.
# It writes to $DEPS/licenses/<name>/, so DEPS is pointed at the build.
DEPS="$BUILD/harvest"
sed -n '/^save_notice() {$/,/^}$/p' "$ROOT/scripts/install.sh" > "$BUILD/.save_notice.sh"
if ! grep -q '^save_notice() {$' "$BUILD/.save_notice.sh"; then
    err "could not find save_notice in scripts/install.sh to keep the licences"
    exit 1
fi
. "$BUILD/.save_notice.sh"

# ============================================================
# 2 — Lua
# ============================================================

phase 2 "Lua $LUA_VERSION"

LUA_TOP="$BUILD/lua-install"
if [ -x "$LUA_TOP/bin/lua" ] && [ -f "$LUA_TOP/include/lua.h" ]; then
    ok "found in build/lua-install/"
else
    unpack "lua-$LUA_VERSION.tar.gz" "lua-$LUA_VERSION"
    info "compiling (make linux: no readline, needs only libc and libm)"
    ( cd "$BUILD/lua-$LUA_VERSION" \
        && make -s linux CC="$CC" AR="$AR rcu" RANLIB="$RANLIB" > "$BUILD/lua.log" 2>&1 \
        && make -s install INSTALL_TOP="$LUA_TOP" >> "$BUILD/lua.log" 2>&1 ) || {
        err "Lua did not build; the last lines of build/lua.log:"
        tail -5 "$BUILD/lua.log" >&2
        exit 1
    }
    save_notice lua "$BUILD/lua-$LUA_VERSION" doc/readme.html src/lua.h
    ok "compiled into build/lua-install/"
fi

# ============================================================
# 3 — OpenSSL
# ============================================================

phase 3 "OpenSSL $OPENSSL_VERSION"

SSL_TOP="$BUILD/openssl-install"
if [ -f "$SSL_TOP/lib/libcrypto.a" ] && [ -f "$SSL_TOP/include/openssl/evp.h" ]; then
    ok "found in build/openssl-install/"
else
    unpack "openssl-$OPENSSL_VERSION.tar.gz" "openssl-$OPENSSL_VERSION"
    info "configuring for $OPENSSL_TARGET with everything rmail does not use turned off"
    info "compiling: this is the long phase, several minutes, and prints nothing until it ends"
    ( cd "$BUILD/openssl-$OPENSSL_VERSION" \
        && CC="$CC" AR="$AR" RANLIB="$RANLIB" ./Configure "$OPENSSL_TARGET" --prefix="$SSL_TOP" --libdir=lib \
            $OPENSSL_OFF -fPIC > "$BUILD/openssl.log" 2>&1 \
        && make -s -j"$(nproc 2>/dev/null || echo 2)" >> "$BUILD/openssl.log" 2>&1 \
        && make -s install_sw >> "$BUILD/openssl.log" 2>&1 ) || {
        err "OpenSSL did not build; the last lines of build/openssl.log:"
        tail -5 "$BUILD/openssl.log" >&2
        exit 1
    }
    save_notice openssl "$BUILD/openssl-$OPENSSL_VERSION"
    ok "compiled into build/openssl-install/ ($(du -h "$SSL_TOP/lib/libcrypto.a" | cut -f1) libcrypto.a)"
fi

# ============================================================
# 4 — luasocket
# ============================================================

phase 4 "luasocket $LUASOCKET_VERSION"

SOCK_OUT="$BUILD/luasocket-out"
if [ -f "$SOCK_OUT/socket/core.so" ] && [ -f "$SOCK_OUT/mime/core.so" ]; then
    ok "found in build/luasocket-out/"
else
    unpack "luasocket-$LUASOCKET_VERSION.tar.gz" "luasocket-$LUASOCKET_VERSION"
    info "compiling socket/core.so and mime/core.so against build/lua-install/"
    rm -rf "$SOCK_OUT"
    mkdir -p "$SOCK_OUT/socket" "$SOCK_OUT/mime"
    ( cd "$BUILD/luasocket-$LUASOCKET_VERSION/src" && {
        for src in luasocket.c timeout.c buffer.c io.c auxiliar.c compat.c options.c inet.c usocket.c \
                   except.c select.c tcp.c udp.c mime.c; do
            $CC -I"$LUA_TOP/include" -DLUASOCKET_NODEBUG -Wall -O2 -fPIC -c -o "${src%.c}.o" "$src" || exit 1
        done
        $CC -shared -fPIC -O -o "$SOCK_OUT/socket/core.so" luasocket.o timeout.o buffer.o io.o auxiliar.o \
            compat.o options.o inet.o usocket.o except.o select.o tcp.o udp.o \
        && $CC -shared -fPIC -O -o "$SOCK_OUT/mime/core.so" mime.o compat.o \
        && cp socket.lua mime.lua ltn12.lua "$SOCK_OUT/" \
        && cp http.lua url.lua tp.lua ftp.lua smtp.lua headers.lua "$SOCK_OUT/socket/"
    } ) > "$BUILD/luasocket.log" 2>&1 || {
        err "luasocket did not build; the last lines of build/luasocket.log:"
        tail -5 "$BUILD/luasocket.log" >&2
        exit 1
    }
    save_notice luasocket "$BUILD/luasocket-$LUASOCKET_VERSION"
    ok "compiled into build/luasocket-out/"
fi

# ============================================================
# 5 — the two rmail libraries
# ============================================================

phase 5 "rmail_crypto.so and rmail_inotify.so"

RMAIL_OUT="$BUILD/rmail-out"
mkdir -p "$RMAIL_OUT"

# what a binary asks of the system it runs on
needed() { readelf -d "$1" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\].*/\1/p' | tr '\n' ' '; }

if [ -f "$RMAIL_OUT/rmail_crypto.so" ] && [ "$RMAIL_OUT/rmail_crypto.so" -nt "$ROOT/rmail_crypto.c" ]; then
    ok "found rmail_crypto.so"
else
    info "compiling rmail_crypto.so with build/openssl-install/lib/libcrypto.a linked in"
    $CC -shared -fPIC -O2 -Wall -I"$LUA_TOP/include" -I"$SSL_TOP/include" \
        -o "$RMAIL_OUT/rmail_crypto.so" "$ROOT/rmail_crypto.c" "$SSL_TOP/lib/libcrypto.a" -lpthread \
        > "$BUILD/rmail.log" 2>&1 || {
        err "rmail_crypto.so did not build; the last lines of build/rmail.log:"
        tail -5 "$BUILD/rmail.log" >&2
        exit 1
    }
    ok "compiled rmail_crypto.so ($(du -h "$RMAIL_OUT/rmail_crypto.so" | cut -f1))"
fi
# The check that the link took: a module that still names libcrypto loads
# here and fails on a host whose OpenSSL is another version, silently
# until then.
case " $(needed "$RMAIL_OUT/rmail_crypto.so") " in
    *libcrypto*|*libssl*)
        err "rmail_crypto.so still needs OpenSSL from a host: $(needed "$RMAIL_OUT/rmail_crypto.so")"
        rm -f "$RMAIL_OUT/rmail_crypto.so"
        exit 1 ;;
esac
ok "rmail_crypto.so needs no OpenSSL from a host"

if [ -f "$RMAIL_OUT/rmail_inotify.so" ] && [ "$RMAIL_OUT/rmail_inotify.so" -nt "$ROOT/rmail_inotify.c" ]; then
    ok "found rmail_inotify.so"
else
    $CC -shared -fPIC -O2 -Wall -I"$LUA_TOP/include" -o "$RMAIL_OUT/rmail_inotify.so" "$ROOT/rmail_inotify.c" \
        >> "$BUILD/rmail.log" 2>&1 || {
        err "rmail_inotify.so did not build; the last lines of build/rmail.log:"
        tail -5 "$BUILD/rmail.log" >&2
        exit 1
    }
    ok "compiled rmail_inotify.so"
fi

# ============================================================
# 6 — the payload
# ============================================================

phase 6 "payload ($PAYLOAD)"

# Built fresh every time: it is a copy of the phases' outputs and takes no
# time, and a payload left over from older sources must not survive.
rm -rf "$PAYLOAD"
mkdir -p "$PAYLOAD/libs/socket" "$PAYLOAD/libs/mime" "$PAYLOAD/deps/lua/bin" "$PAYLOAD/licenses"

# The program: an allowlist, as make-mailbox-drive.sh always had it.
for f in rmail.lua run-rmail.sh rmail_crypto.c rmail_inotify.c LICENSE; do
    if [ ! -f "$ROOT/$f" ]; then err "missing from the checkout: $f"; exit 1; fi
    cp "$ROOT/$f" "$PAYLOAD/$f"
done
chmod +x "$PAYLOAD/run-rmail.sh"
# the plain-Lua libraries carried with rmail (tracked in git)
for f in "$ROOT"/libs/*.lua "$ROOT"/libs/zip-library.version; do
    [ -f "$f" ] && cp "$f" "$PAYLOAD/libs/"
done
cp "$SOCK_OUT"/*.lua "$PAYLOAD/libs/"
cp "$SOCK_OUT"/socket/* "$PAYLOAD/libs/socket/"
cp "$SOCK_OUT"/mime/core.so "$PAYLOAD/libs/mime/"
cp "$RMAIL_OUT"/rmail_crypto.so "$RMAIL_OUT"/rmail_inotify.so "$PAYLOAD/libs/"
# the interpreter, and the headers BUILD-NOTES.txt says it can be rebuilt
# against; not luac or liblua.a, which nothing runs
cp "$LUA_TOP/bin/lua" "$PAYLOAD/deps/lua/bin/lua"
cp -R "$LUA_TOP/include" "$PAYLOAD/deps/lua/include"
# what source this program is (#615): the revision of the checkout it was
# copied from, and the digest of the copy, so a later edit on the drive
# shows as a difference rather than inheriting the claim
if ! sh "$SCRIPT_DIR/build-stamp.sh" --by generate-portable-mailbox.sh \
        --revision-from "$ROOT" "$PAYLOAD" >/dev/null; then
    err "could not write the build stamp into $PAYLOAD"
    exit 1
fi
# each dependency's licence, kept from its own source tree
if [ -d "$DEPS/licenses" ]; then cp -R "$DEPS/licenses/." "$PAYLOAD/licenses/"; fi
for name in lua openssl luasocket; do
    if [ -z "$(ls -A "$PAYLOAD/licenses/$name" 2>/dev/null)" ]; then
        err "no licence kept for $name: its binary would travel without its notice"
        exit 1
    fi
done

# which kind of machine this is for, read by make-mailbox-drive.sh to
# place it in the drive's source-code/<arch>/ (#619)
echo "$TARGET" > "$PAYLOAD/ARCH"

cat > "$PAYLOAD/BUILD-NOTES.txt" <<NOTES
How the compiled parts of this program were built
=================================================

Built by scripts/generate-portable-mailbox.sh (r-mail issue #617)
for $TARGET, with $CC, from these sources:

  lua-$LUA_VERSION.tar.gz         https://www.lua.org/ftp/
  openssl-$OPENSSL_VERSION.tar.gz     https://github.com/openssl/openssl/releases
  luasocket-$LUASOCKET_VERSION.tar.gz   https://github.com/lunarmodules/luasocket

Lua, stock, without readline (needs only libc and libm from a host):

  make linux CC=$CC
  make install INSTALL_TOP=<build>/lua-install

OpenSSL, static, with everything rmail does not use turned off:

  ./Configure $OPENSSL_TARGET --prefix=<build>/openssl-install --libdir=lib \\
      $OPENSSL_OFF -fPIC
  make && make install_sw

luasocket's socket/core.so and mime/core.so, stock, against that Lua:

  $CC -I<build>/lua-install/include -DLUASOCKET_NODEBUG -O2 -fPIC -c <each .c>
  $CC -shared -fPIC -o socket/core.so <the socket objects>
  $CC -shared -fPIC -o mime/core.so mime.o compat.o

The two rmail libraries, from the source beside this file:

  $CC -shared -fPIC -O2 -Wall -I deps/lua/include -I <build>/openssl-install/include \\
      -o libs/rmail_crypto.so rmail_crypto.c <build>/openssl-install/lib/libcrypto.a -lpthread
  $CC -shared -fPIC -O2 -Wall -I deps/lua/include -o libs/rmail_inotify.so rmail_inotify.c

Each dependency's licence is in licenses/<name>/.  The full project is at
https://github.com/gabrilend/r-mail
NOTES

# --- checks ---------------------------------------------------------------

# every binary is for the target, and the interpreter needs only libc and libm
for bin in deps/lua/bin/lua libs/socket/core.so libs/mime/core.so libs/rmail_crypto.so libs/rmail_inotify.so; do
    machine=$(readelf -h "$PAYLOAD/$bin" 2>/dev/null | sed -n 's/^ *Machine: *//p')
    if [ "$machine" != "$ELF_MACHINE" ]; then
        err "$bin is not built for $TARGET: readelf says '${machine:-not an ELF file}'"
        err "  the compiler may have fallen back to this machine's own"
        exit 1
    fi
done
ok "every binary is built for $TARGET"

for lib in $(needed "$PAYLOAD/deps/lua/bin/lua"); do
    case "$lib" in
        libc.so*|libm.so*|ld-linux*) ;;
        *) err "the interpreter needs $lib from a host; a drive's Lua needs only libc and libm"; exit 1 ;;
    esac
done
ok "the interpreter needs only libc and libm from a host"

if [ "$TARGET" = "$HOST" ]; then
    if ! LUA_PATH="$PAYLOAD/libs/?.lua;;" LUA_CPATH="$PAYLOAD/libs/?.so;;" "$PAYLOAD/deps/lua/bin/lua" -e '
        local socket, mime = require("socket.core"), require("mime.core")
        local crypto = require("rmail_crypto")
        require("rmail_inotify")
        local key, nonce = string.rep("k", 32), string.rep("n", 12)
        local sealed = crypto.aes_gcm_encrypt(key, nonce, "portable")
        assert(crypto.aes_gcm_decrypt(key, nonce, sealed) == "portable", "the round trip failed")
        assert(#crypto.sha256("x") == 32, "sha256 is not 32 bytes")' > "$BUILD/check.log" 2>&1; then
        err "the payload's own Lua cannot use the payload's own libraries:"
        sed 's/^/    /' "$BUILD/check.log" >&2
        exit 1
    fi
    ok "checked: the payload's Lua loads its libraries and round-trips an encryption"
else
    warn "built for $TARGET on $HOST: the binaries' architecture is checked, but they are not run here"
fi

echo ""
ok "payload for $TARGET: $PAYLOAD ($(du -sh "$PAYLOAD" | cut -f1))"
for bin in deps/lua/bin/lua libs/rmail_crypto.so libs/socket/core.so; do
    info "  $(du -h "$PAYLOAD/$bin" | cut -f1)	$bin"
done
info "place it on a drive with: scripts/make-mailbox-drive.sh --payload $PAYLOAD ..."
info "  (give --payload once for each kind of machine the drive should run on)"
