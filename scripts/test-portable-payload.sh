#!/bin/sh
# test-portable-payload.sh — check that generate-portable-mailbox.sh builds a drive's program on purpose, and make-mailbox-drive.sh only places it
#
# Issue #617.  Building the real sources needs them downloaded and takes
# minutes (OpenSSL alone), so by default the generator is run against
# stand-in source archives shaped like the real ones, made here from what
# this machine already has:
#
#   lua        a Makefile whose `linux` target builds a working Lua 5.4
#              interpreter from the system's liblua5.4.a and records how
#              it was called; `install` lays out bin/ and include/
#   openssl    a Configure that records its arguments and a Makefile
#              whose install_sw lays out the system's libcrypto.a and
#              headers (so the crypto module is a real one)
#   luasocket  C files making socket.core and mime.core, and its .lua files
#
# Each carries a LICENSE.  With RMAIL_TEST_OPENSSL=<openssl-3.5.1.tar.gz>
# the real OpenSSL is built instead of the stand-in (several minutes).
#
# Cases:
#   built       a payload laid out as a drive's source-code/: the program,
#               libs/ with luasocket and the two rmail libraries, its own
#               Lua, a licence for each dependency, BUILD-NOTES.txt naming
#               the target and the flags, a build stamp naming the
#               checkout's revision and the payload's digest; Lua made with `make linux` (never
#               linux-readline) and this compiler; OpenSSL configured
#               static with what rmail does not use turned off; the
#               generator's own check (the payload's Lua loads its
#               libraries and round-trips an encryption) passed
#   again       a second run builds nothing and says each was found; the
#               payload is laid out again
#   force       --force builds every phase again
#   refused     --offline with an archive missing names it and its address;
#               an unknown target; a target whose cross compiler is not
#               installed names the package
#   checks      a crypto module that still needs libcrypto from a host is
#               refused, and so is a Lua that needs more than libc and libm
#   placed      make-mailbox-drive.sh --payload places the payload as the
#               mailbox's source-code/ and compiles nothing; a payload with
#               no Lua is refused
#
# Usage:
#   scripts/test-portable-payload.sh          # use the enclosing checkout
#   scripts/test-portable-payload.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
GEN="$DIR/scripts/generate-portable-mailbox.sh"
DRIVE="$DIR/scripts/make-mailbox-drive.sh"
WORK="/tmp/rmail/tests/portable-payload"
SRC="$WORK/sources"
OUT="$WORK/out"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail portable-payload test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

for need in cc readelf /usr/lib/x86_64-linux-gnu/liblua5.4.a /usr/include/lua5.4/lua.h \
            /usr/lib/x86_64-linux-gnu/libcrypto.a /usr/include/openssl/evp.h; do
    if ! command -v "$need" >/dev/null 2>&1 && [ ! -e "$need" ]; then
        note_fail "this test makes its stand-ins from $need, which is not here"
        exit 1
    fi
done
if [ "$(uname -m)" != x86_64 ]; then
    note_fail "the stand-ins are made from x86_64 system libraries; this is $(uname -m)"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$SRC" "$WORK/make"

# {{{ the stand-in archives
# stand_ins <lua extra link flags> <openssl mode: static | dynamic>
stand_ins() {
    rm -rf "$WORK/make" && mkdir -p "$WORK/make"
    # lua: a real interpreter (lua -e CODE, lua FILE) from liblua5.4.a
    L="$WORK/make/lua-5.4.7"
    mkdir -p "$L/src" "$L/doc"
    printf 'Lua stand-in licence\n' > "$L/doc/readme.html"
    cp /usr/include/lua5.4/lua.h "$L/src/lua.h"
    cat > "$L/src/standin.c" <<'C'
#include <stdio.h>
#include <string.h>
#include <lua5.4/lua.h>
#include <lua5.4/lualib.h>
#include <lua5.4/lauxlib.h>
int main(int argc, char **argv) {
    lua_State *L = luaL_newstate();
    luaL_openlibs(L);
    int status = 0;
    for (int i = 1; i < argc && status == 0; i++) {
        if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) status = luaL_dostring(L, argv[++i]);
        else status = luaL_dofile(L, argv[i]);
    }
    if (status) fprintf(stderr, "%s\n", lua_tostring(L, -1));
    lua_close(L);
    return status ? 1 : 0;
}
C
    cat > "$L/Makefile" <<MAKE
linux:
	echo "linux CC=\$(CC)" >> $WORK/lua-make.log
	\$(CC) -O2 -o src/lua src/standin.c /usr/lib/x86_64-linux-gnu/liblua5.4.a $1 -Wl,-E -lm
linux-readline:
	echo "linux-readline" >> $WORK/lua-make.log
	exit 1
install:
	mkdir -p \$(INSTALL_TOP)/bin \$(INSTALL_TOP)/include
	cp src/lua \$(INSTALL_TOP)/bin/lua
	cp /usr/include/lua5.4/lua.h /usr/include/lua5.4/luaconf.h /usr/include/lua5.4/lualib.h \
	   /usr/include/lua5.4/lauxlib.h /usr/include/lua5.4/lua.hpp \$(INSTALL_TOP)/include/
MAKE
    # openssl: records its configuration; installs the system's archive
    O="$WORK/make/openssl-3.5.1"
    mkdir -p "$O"
    printf 'OpenSSL stand-in licence\n' > "$O/LICENSE.txt"
    cat > "$O/Configure" <<CONF
#!/bin/sh
echo "\$*" >> $WORK/openssl-configure.log
prefix=""
for a in "\$@"; do case "\$a" in --prefix=*) prefix="\${a#--prefix=}" ;; esac; done
cat > Makefile <<EOF
all:
	@true
install_sw:
	mkdir -p \$prefix/lib \$prefix/include
	cp -R /usr/include/openssl \$prefix/include/openssl
	cp /usr/include/x86_64-linux-gnu/openssl/*.h \$prefix/include/openssl/ 2>/dev/null || true
EOF
if [ "$2" = dynamic ]; then
    printf '\tprintf "INPUT(-lcrypto)\\\\n" > %s/lib/libcrypto.a\n' "\$prefix" >> Makefile
else
    printf '\tcp /usr/lib/x86_64-linux-gnu/libcrypto.a %s/lib/libcrypto.a\n' "\$prefix" >> Makefile
fi
CONF
    chmod +x "$O/Configure"
    # luasocket: the files the generator compiles and copies
    S="$WORK/make/luasocket-3.1.0"
    mkdir -p "$S/src"
    printf 'luasocket stand-in licence\n' > "$S/LICENSE"
    for f in timeout buffer io auxiliar compat options inet usocket except select tcp udp; do
        printf 'int standin_%s;\n' "$f" > "$S/src/$f.c"
    done
    cat > "$S/src/luasocket.c" <<'C'
#include <lua.h>
#include <lauxlib.h>
int luaopen_socket_core(lua_State *L) { lua_newtable(L); lua_pushstring(L, "stand-in"); lua_setfield(L, -2, "_VERSION"); return 1; }
C
    cat > "$S/src/mime.c" <<'C'
#include <lua.h>
int luaopen_mime_core(lua_State *L) { lua_newtable(L); return 1; }
C
    for f in socket mime ltn12 http url tp ftp smtp headers; do printf 'return {}\n' > "$S/src/$f.lua"; done
    rm -f "$SRC"/*.tar.gz
    tar czf "$SRC/lua-5.4.7.tar.gz" -C "$WORK/make" lua-5.4.7
    tar czf "$SRC/luasocket-3.1.0.tar.gz" -C "$WORK/make" luasocket-3.1.0
    if [ -n "$RMAIL_TEST_OPENSSL" ] && [ "$2" = static ]; then
        cp "$RMAIL_TEST_OPENSSL" "$SRC/openssl-3.5.1.tar.gz"
    else
        tar czf "$SRC/openssl-3.5.1.tar.gz" -C "$WORK/make" openssl-3.5.1
    fi
}
# }}}

# gen <args...>: the generator, offline, into OUT; output in $WORK/gen.out
gen() {
    sh "$GEN" --offline --sources "$SRC" --out "$OUT" "$@" > "$WORK/gen.out" 2>&1
}

P="$OUT/x86_64/payload"

echo ""
echo "built"
stand_ins "" static
rm -f "$WORK/lua-make.log" "$WORK/openssl-configure.log"
if gen; then
    ok "the generator built a payload from the archives in --sources"
else
    note_fail "the generator failed: $(tail -5 "$WORK/gen.out" | tr '\n' ' ')"
fi
missing=""
for f in rmail.lua run-rmail.sh rmail_crypto.c rmail_inotify.c LICENSE BUILD-NOTES.txt libs/dkjson.lua \
         libs/zip-writer.lua libs/socket.lua libs/ltn12.lua libs/socket/core.so libs/socket/http.lua \
         libs/mime/core.so libs/rmail_crypto.so libs/rmail_inotify.so deps/lua/bin/lua deps/lua/include/lua.h; do
    [ -e "$P/$f" ] || missing="$missing $f"
done
[ -z "$missing" ] && ok "laid out as a drive's source-code/: the program, libs/, its own Lua" \
    || note_fail "missing from the payload:$missing"
for f in deps/lua/bin/luac deps/lua/lib/liblua.a issues docs clients llm-transcripts; do
    [ -e "$P/$f" ] && note_fail "the payload carries $f"
done
if [ -s "$P/licenses/lua/readme.html" ] && [ -s "$P/licenses/openssl/LICENSE.txt" ] \
   && [ -s "$P/licenses/luasocket/LICENSE" ]; then
    ok "each dependency's licence travels, kept from its own source tree"
else
    note_fail "a licence is missing: $(cd "$P/licenses" 2>/dev/null && find . -type f | tr '\n' ' ')"
fi
if [ "$(cat "$WORK/lua-make.log" 2>/dev/null)" = "linux CC=cc" ]; then
    ok "Lua was made with make linux, never linux-readline, and this compiler"
else
    note_fail "Lua was made as: $(cat "$WORK/lua-make.log" 2>/dev/null | tr '\n' ' ')"
fi
# The stand-in records what Configure was given; the real OpenSSL keeps it
# in configdata.pm, one quoted argument a line.
if [ -n "$RMAIL_TEST_OPENSSL" ]; then
    conf=$(sed -n '/"perlargv" => \[/,/\]/p' "$OUT/x86_64/build/openssl-3.5.1/configdata.pm" 2>/dev/null \
           | sed -n 's/^ *"\(.*\)",\{0,1\}$/\1/p' | tr '\n' ' ')
else
    conf=$(cat "$WORK/openssl-configure.log" 2>/dev/null)
fi
all=yes
for flag in linux-x86_64 no-shared no-tls no-dtls no-quic no-ec no-dh no-dsa no-engine no-legacy no-comp \
            no-deprecated -fPIC; do
    case " $conf " in *" $flag "*) ;; *) all="no ($flag)" ;; esac
done
[ "$all" = yes ] && ok "OpenSSL configured static, with what rmail does not use turned off" \
    || note_fail "OpenSSL's Configure was given: $conf, missing $all"
if readelf -d "$P/libs/rmail_crypto.so" | grep -q "libcrypto\|libssl"; then
    note_fail "the crypto module still needs OpenSSL from a host"
else
    ok "the crypto module needs no OpenSSL from a host"
fi
grep -q "checked: the payload's Lua loads its libraries and round-trips an encryption" "$WORK/gen.out" \
    && ok "the generator ran the payload's Lua against its libraries" || note_fail "no load check was reported"
grep -q "for x86_64, with cc" "$P/BUILD-NOTES.txt" && grep -q "no-tls" "$P/BUILD-NOTES.txt" \
    && ok "BUILD-NOTES.txt names the target, the compiler and the flags" \
    || note_fail "BUILD-NOTES.txt does not say how it was built"
[ "$(cat "$P/ARCH" 2>/dev/null)" = x86_64 ] && ok "ARCH names the target, for the drive maker (#619)" \
    || note_fail "no ARCH file naming x86_64: $(cat "$P/ARCH" 2>/dev/null)"
# the build stamp (#615): the checkout's revision, the payload's own digest
want_rev=unknown
_top=$(git -C "$DIR" rev-parse --show-toplevel 2>/dev/null) || _top=""
if [ -n "$_top" ] && [ "$(cd "$_top" && pwd -P)" = "$(cd "$DIR" && pwd -P)" ]; then
    want_rev=$(git -C "$DIR" describe --always --dirty --abbrev=12 2>/dev/null)
fi
if grep -q "^by = generate-portable-mailbox.sh$" "$P/build-stamp" 2>/dev/null \
   && grep -q "^revision = $want_rev$" "$P/build-stamp" \
   && grep -q "^digest = $(sh "$DIR/scripts/build-stamp.sh" --digest "$P")$" "$P/build-stamp"; then
    ok "build-stamp names the checkout's revision and the payload's own digest (#615)"
else
    note_fail "the payload's build-stamp: $(tr '\n' ' ' < "$P/build-stamp" 2>/dev/null) (wanted revision $want_rev)"
fi
if LUA_PATH="$P/libs/?.lua;;" LUA_CPATH="$P/libs/?.so;;" "$P/deps/lua/bin/lua" \
     -e 'local c = require("rmail_crypto"); assert(c.aes_gcm_decrypt(string.rep("k",32), string.rep("n",12),
         c.aes_gcm_encrypt(string.rep("k",32), string.rep("n",12), "hi")) == "hi")' 2>/dev/null; then
    ok "and here, independently: the payload's Lua decrypts what its crypto module encrypted"
else
    note_fail "the payload's Lua cannot round-trip with its crypto module"
fi

echo ""
echo "again"
gen
if [ "$(grep -c "^linux" "$WORK/lua-make.log")" = "1" ] && ! grep -q "compiled into build/openssl-install/" "$WORK/gen.out" \
   && [ "$(grep -c "found in build/" "$WORK/gen.out")" = "3" ]; then
    ok "a second run builds nothing and says each phase's output was found"
else
    note_fail "a second run built again: $(grep -c "" "$WORK/lua-make.log") Lua build(s), $(grep -c "found" "$WORK/gen.out") found"
fi
[ -x "$P/deps/lua/bin/lua" ] && ok "and lays the payload out again" || note_fail "the second run left no payload"

echo ""
echo "force"
gen --force
[ "$(grep -c "^linux" "$WORK/lua-make.log")" = "2" ] && grep -q "compiled into build/openssl-install/" "$WORK/gen.out" \
    && ok "--force builds every phase again" || note_fail "--force did not rebuild"

echo ""
echo "refused"
mv "$SRC/luasocket-3.1.0.tar.gz" "$WORK/luasocket.keep"
rm -rf "$OUT"
if gen; then
    note_fail "--offline built with an archive missing"
elif grep -q "luasocket-3.1.0.tar.gz is not in" "$WORK/gen.out" \
     && grep -q "https://github.com/lunarmodules/luasocket/archive/refs/tags/v3.1.0.tar.gz" "$WORK/gen.out"; then
    ok "--offline with an archive missing: refused, naming it and where it is"
else
    note_fail "the refusal does not name the archive: $(tr '\n' ' ' < "$WORK/gen.out")"
fi
mv "$WORK/luasocket.keep" "$SRC/luasocket-3.1.0.tar.gz"
gen --target sparc && note_fail "an unknown target was built"
grep -q "no build for 'sparc'" "$WORK/gen.out" && ok "an unknown target is refused" \
    || note_fail "an unknown target was not refused by name"
if ! command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    gen --target aarch64 && note_fail "aarch64 was built without its compiler"
    grep -q "gcc-aarch64-linux-gnu" "$WORK/gen.out" && ok "aarch64 without its cross compiler: refused, naming the package" \
        || note_fail "the refusal does not name the package: $(tr '\n' ' ' < "$WORK/gen.out")"
else
    info "aarch64-linux-gnu-gcc is installed here: the missing-compiler case is not run"
fi

echo ""
echo "checks"
stand_ins "" dynamic
rm -rf "$OUT"
if gen; then
    note_fail "a crypto module that needs libcrypto from a host was accepted"
elif grep -q "rmail_crypto.so still needs OpenSSL from a host" "$WORK/gen.out"; then
    ok "a crypto module that still needs libcrypto from a host is refused"
else
    note_fail "refused, but not for the crypto module: $(tail -3 "$WORK/gen.out" | tr '\n' ' ')"
fi
stand_ins "-Wl,--no-as-needed -l:libutil.so.1" static
rm -rf "$OUT"
if gen; then
    note_fail "a Lua that needs libutil from a host was accepted"
elif grep -q "the interpreter needs libutil.so.1 from a host" "$WORK/gen.out"; then
    ok "a Lua that needs more than libc and libm is refused"
else
    note_fail "refused, but not for the interpreter: $(tail -3 "$WORK/gen.out" | tr '\n' ' ')"
fi

echo ""
echo "placed"
stand_ins "" static
rm -rf "$OUT"
gen || note_fail "the payload for the drive did not build"
DEST="$WORK/drive"
mkdir -p "$DEST"
if sh "$DRIVE" --name me --port 59527 --dest "$DEST" --payload "$P" > "$WORK/drive.out" 2>&1; then
    ok "make-mailbox-drive.sh placed a mailbox with the payload"
else
    note_fail "make-mailbox-drive.sh failed: $(tail -4 "$WORK/drive.out" | tr '\n' ' ')"
fi
SC="$DEST/mailbox-0/source-code"
# laid out per architecture (#619): the compiled part in source-code/x86_64/
if cmp -s "$SC/x86_64/libs/rmail_crypto.so" "$P/libs/rmail_crypto.so" \
   && cmp -s "$SC/x86_64/deps/lua/bin/lua" "$P/deps/lua/bin/lua" \
   && cmp -s "$SC/rmail.lua" "$P/rmail.lua" \
   && [ -s "$SC/licenses/openssl/LICENSE.txt" ] && cmp -s "$SC/x86_64/BUILD-NOTES.txt" "$P/BUILD-NOTES.txt" \
   && cmp -s "$SC/build-stamp" "$P/build-stamp"; then
    ok "source-code/ is the payload, byte for byte, licences, build notes and build stamp included"
else
    note_fail "source-code/ is not the payload: $(ls "$SC" 2>/dev/null | tr '\n' ' ')"
fi
if grep -qi "linking\|compil" "$WORK/drive.out"; then
    note_fail "the drive maker compiled or linked something: $(grep -i "linking\|compil" "$WORK/drive.out" | head -2 | tr '\n' ' ')"
else
    ok "the drive maker compiled and linked nothing"
fi
[ -f "$DEST/mailbox-0/config" ] && [ -x "$DEST/mailbox-0/sync-with-contacts.sh" ] \
    && ok "and wrote the mailbox's config and launchers as before" || note_fail "no config or launcher on the drive"
mkdir -p "$WORK/no-lua"
cp -R "$P/." "$WORK/no-lua/"
rm -f "$WORK/no-lua/deps/lua/bin/lua"
mkdir -p "$WORK/drive2"
if sh "$DRIVE" --name me --port 59527 --dest "$WORK/drive2" --payload "$WORK/no-lua" > "$WORK/drive2.out" 2>&1; then
    note_fail "a payload with no Lua was placed"
elif grep -q "no Lua" "$WORK/drive2.out"; then
    ok "a payload with no Lua is refused"
else
    note_fail "refused, but not for the missing Lua: $(tail -3 "$WORK/drive2.out" | tr '\n' ' ')"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "generator output: $WORK/gen.out"
exit 1
