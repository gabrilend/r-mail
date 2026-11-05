#!/bin/sh
# test-drive-architectures.sh — check that one drive carries a program for several kinds of machine, and its launchers pick this one's (#619)
#
# make-mailbox-drive.sh takes --payload once per architecture.  The drive's
# source-code/ holds what every kind shares (rmail.lua, the plain-Lua
# libraries, the C sources, the licences) once, and each kind's compiled
# part (its Lua, its .so files, its BUILD-NOTES.txt) in source-code/<arch>/.
# The launchers ask `uname -m`, put the shared part and that kind's part
# together in a temporary copy, and run it.
#
# Building real payloads takes OpenSSL and minutes, and an aarch64 one a
# cross compiler (scripts/test-portable-payload.sh tests the generator).
# So the payloads here are made by hand: this machine's from this
# checkout's own interpreter and libraries, and an aarch64 one whose
# binaries are ELF headers that say AArch64 (all readelf reads) and run
# nowhere.  A stand-in `uname` makes the launchers think they are on
# another kind of machine.
#
# Cases:
#   placed        two payloads make one drive: the shared files once, each
#                 kind's compiled files in its own folder, nothing compiled
#                 in the shared libs/; this machine's checked by loading,
#                 the other's by readelf; a payload with no ARCH file is
#                 placed by its interpreter's machine; the drive's README
#                 and the summary name both kinds
#   this machine  the launcher runs the daemon from this machine's part
#   other kinds   on aarch64 the launcher picks the aarch64 part, which
#                 does not run, and says so; on riscv64 it names the kinds
#                 the drive holds; both stop with the mailbox untouched
#   refused       two payloads for one kind; payloads that differ in more
#                 than their compiled parts (named); an aarch64 payload
#                 holding an x86-64 library (named)
#   again         --force over an older drive leaves none of its old
#                 single-machine layout behind
#
# Usage:
#   scripts/test-drive-architectures.sh          # use the enclosing checkout
#   scripts/test-drive-architectures.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
DRIVE="$DIR/scripts/make-mailbox-drive.sh"
WORK="/tmp/rmail/tests/drive-architectures"
PORT=59574

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail drive-architectures test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

case "$(uname -m)" in
    x86_64|amd64) HOST=x86_64; OTHER=aarch64; OTHER_MACHINE='\267\000' ;;
    aarch64|arm64) HOST=aarch64; OTHER=x86_64; OTHER_MACHINE='\076\000' ;;
    *) note_fail "this test needs an x86_64 or aarch64 machine, not $(uname -m)"; exit 1 ;;
esac
LUA="$DIR/deps/lua/bin/lua"
if [ ! -x "$LUA" ] || ! command -v readelf >/dev/null 2>&1; then
    note_fail "this test needs the checkout's Lua ($LUA) and readelf"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK"
# the launchers' temporary copies go here, not to /tmp
XDG_RUNTIME_DIR="$WORK/run"
export XDG_RUNTIME_DIR
mkdir -p "$XDG_RUNTIME_DIR"

# where this checkout's Lua finds a module: the checkout's libs/ first
find_module() {  # <path|cpath> <module>
    "$LUA" -e "package.path = '$DIR/libs/?.lua;' .. package.path
               package.cpath = '$DIR/libs/?.so;' .. package.cpath
               print(package.searchpath('$2', package.$1) or '')"
}

# {{{ the payloads
# this machine's: the checkout's own program, interpreter and libraries
P1="$WORK/payload-$HOST"
mkdir -p "$P1/libs/socket" "$P1/libs/mime" "$P1/deps/lua/bin" "$P1/licenses/lua"
for f in rmail.lua run-rmail.sh rmail_crypto.c rmail_inotify.c LICENSE; do cp "$DIR/$f" "$P1/"; done
cp "$DIR"/libs/*.lua "$P1/libs/"
cp -L "$LUA" "$P1/deps/lua/bin/lua"
for m in rmail_crypto rmail_inotify; do cp -L "$(find_module cpath $m)" "$P1/libs/$m.so"; done
cp -L "$(find_module cpath socket.core)" "$P1/libs/socket/core.so"
cp -L "$(find_module cpath mime.core)" "$P1/libs/mime/core.so"
for m in socket mime ltn12; do cp -L "$(find_module path $m)" "$P1/libs/$m.lua"; done
printf 'built for %s, by hand, for a test\n' "$HOST" > "$P1/BUILD-NOTES.txt"
printf 'stand-in licence\n' > "$P1/licenses/lua/LICENSE"
printf '%s\n' "$HOST" > "$P1/ARCH"
for f in libs/socket/core.so libs/mime/core.so libs/rmail_crypto.so libs/socket.lua; do
    [ -s "$P1/$f" ] || note_fail "could not make this machine's payload: no $f"
done

# the other kind's: the same shared files, and binaries that are only an
# ELF header saying they are for it; no ARCH file, as a payload made
# before the generator wrote one
elf_for_other() {  # <file>
    { printf '\177ELF\002\001\001\000\000\000\000\000\000\000\000\000'
      printf "\\003\\000${OTHER_MACHINE}\\001\\000\\000\\000"
      head -c 40 /dev/zero; } > "$1"
}
P2="$WORK/payload-$OTHER"
cp -R "$P1" "$P2"
rm -f "$P2/ARCH"
for f in deps/lua/bin/lua libs/socket/core.so libs/mime/core.so libs/rmail_crypto.so libs/rmail_inotify.so; do
    elf_for_other "$P2/$f"
done
chmod +x "$P2/deps/lua/bin/lua"
printf 'built for %s, by hand, for a test\n' "$OTHER" > "$P2/BUILD-NOTES.txt"
# }}}

make_drive() {  # <dest> <payload>...
    _dest=$1; shift
    mkdir -p "$_dest"
    _args=""
    for _p in "$@"; do _args="$_args --payload $_p"; done
    # shellcheck disable=SC2086
    sh "$DRIVE" --name me --port "$PORT" --dest "$_dest" --force $_args > "$_dest.out" 2>&1
}

echo ""
echo "placed"
D="$WORK/drive"
if make_drive "$D" "$P1" "$P2"; then
    ok "two payloads make one drive"
else
    note_fail "the drive was not made: $(tail -4 "$D.out" | tr '\n' ' ')"
fi
SC="$D/mailbox-0/source-code"
if cmp -s "$SC/rmail.lua" "$P1/rmail.lua" && cmp -s "$SC/libs/socket.lua" "$P1/libs/socket.lua" \
   && [ -s "$SC/licenses/lua/LICENSE" ] && [ -f "$SC/rmail_crypto.c" ]; then
    ok "the shared files are there once: rmail.lua, the plain-Lua libraries, the licences, the C sources"
else
    note_fail "the shared files are not in source-code/: $(ls "$SC" 2>/dev/null | tr '\n' ' ')"
fi
if cmp -s "$SC/$HOST/deps/lua/bin/lua" "$P1/deps/lua/bin/lua" && cmp -s "$SC/$HOST/libs/socket/core.so" "$P1/libs/socket/core.so" \
   && cmp -s "$SC/$HOST/libs/rmail_crypto.so" "$P1/libs/rmail_crypto.so" && cmp -s "$SC/$HOST/BUILD-NOTES.txt" "$P1/BUILD-NOTES.txt" \
   && cmp -s "$SC/$OTHER/deps/lua/bin/lua" "$P2/deps/lua/bin/lua" && cmp -s "$SC/$OTHER/libs/mime/core.so" "$P2/libs/mime/core.so" \
   && cmp -s "$SC/$OTHER/BUILD-NOTES.txt" "$P2/BUILD-NOTES.txt"; then
    ok "each kind's interpreter, libraries and build notes are in source-code/$HOST/ and source-code/$OTHER/"
else
    note_fail "the compiled parts are not where they belong: $(cd "$SC" 2>/dev/null && find . -name '*.so' -o -name lua | tr '\n' ' ')"
fi
if [ -z "$(find "$SC/libs" -name '*.so' 2>/dev/null)" ] && [ ! -e "$SC/deps" ] && [ ! -e "$SC/BUILD-NOTES.txt" ] \
   && [ ! -e "$SC/ARCH" ] && [ ! -e "$D/mailbox-0/.source-code-staging" ]; then
    ok "nothing compiled in the shared part, and nothing left of the staging"
else
    note_fail "compiled or leftover files in the shared part: $(find "$SC/libs" -name '*.so'; ls -a "$D/mailbox-0")"
fi
grep -q "checked: the drive's own $HOST Lua loads the drive's own libraries" "$D.out" \
    && ok "this machine's part is checked by loading it" || note_fail "no load check for $HOST in the output"
grep -q "checked: every $OTHER binary is built for $OTHER" "$D.out" \
    && ok "the other's by reading every binary's machine, its kind found with no ARCH file" \
    || note_fail "no readelf check for $OTHER: $(grep -i "$OTHER" "$D.out" | head -3 | tr '\n' ' ')"
if grep -q "This drive runs" "$D/README.md" && grep -q "$HOST (" "$D/README.md" && grep -q "$OTHER (" "$D/README.md" \
   && grep -q "for: .*$HOST.*$OTHER\|for: .*$OTHER.*$HOST" "$D.out"; then
    ok "the drive's README and the summary name both kinds"
else
    note_fail "the README or the summary does not name both kinds"
fi

echo ""
echo "this machine"
printf 'mallory.token = "not-a-secret"\n' > "$D/mailbox-0/contacts"
if timeout 60 "$D/mailbox-0/sync-with-contacts.sh" 2 > "$WORK/launch.out" 2>&1; then
    ok "sync-with-contacts.sh ran the daemon from this machine's part and stopped"
else
    note_fail "the launcher did not run: $(tail -4 "$WORK/launch.out" | tr '\n' ' ')"
fi
[ -z "$(ls -A "$XDG_RUNTIME_DIR")" ] && ok "and removed its temporary copy" \
    || note_fail "the temporary copy is left: $(ls "$XDG_RUNTIME_DIR")"

echo ""
echo "other kinds"
mkdir -p "$WORK/bin"
fake_uname() {  # <what uname -m says>
    printf '#!/bin/sh\ncase "$1" in -m) echo %s ;; *) exec /bin/uname "$@" ;; esac\n' "$1" > "$WORK/bin/uname"
    chmod +x "$WORK/bin/uname"
}
before=$(cd "$D/mailbox-0" && ls -lR inbox outbox contacts config 2>/dev/null | cksum)
fake_uname "$OTHER"
if PATH="$WORK/bin:$PATH" "$D/mailbox-0/sync-with-contacts.sh" 2 > "$WORK/other.out" 2>&1; then
    note_fail "the launcher ran on a machine that says it is $OTHER"
elif grep -q "this drive's $OTHER program does not run on this machine" "$WORK/other.out" \
     && grep -q "This drive:  .*$HOST" "$WORK/other.out"; then
    ok "on $OTHER it picks the $OTHER part, which does not run here, and says so"
else
    note_fail "on $OTHER: $(tr '\n' ' ' < "$WORK/other.out")"
fi
fake_uname riscv64
if PATH="$WORK/bin:$PATH" "$D/mailbox-0/auto-sync.sh" > "$WORK/riscv.out" 2>&1; then
    note_fail "the launcher ran on a machine that says it is riscv64"
elif grep -q "this drive was not built for this kind of machine" "$WORK/riscv.out" \
     && grep -q "This drive:  $HOST, $OTHER\|This drive:  $OTHER, $HOST" "$WORK/riscv.out" \
     && grep -q "This host:   riscv64" "$WORK/riscv.out"; then
    ok "on riscv64 it names the kinds the drive holds, and this one"
else
    note_fail "on riscv64: $(tr '\n' ' ' < "$WORK/riscv.out")"
fi
after=$(cd "$D/mailbox-0" && ls -lR inbox outbox contacts config 2>/dev/null | cksum)
[ "$before" = "$after" ] && ok "the mailbox is untouched" || note_fail "the mailbox changed"

echo ""
echo "refused"
mkdir -p "$WORK/twice"
cp -R "$P1" "$WORK/twice-payload"
if make_drive "$WORK/twice" "$P1" "$WORK/twice-payload"; then
    note_fail "two payloads for $HOST were placed"
elif grep -q "two payloads for $HOST" "$WORK/twice.out"; then
    ok "two payloads for one kind are refused"
else
    note_fail "refused, but not for that: $(tail -2 "$WORK/twice.out" | tr '\n' ' ')"
fi
P3="$WORK/payload-changed"
cp -R "$P2" "$P3"
printf -- '-- changed\n' >> "$P3/rmail.lua"
if make_drive "$WORK/changed" "$P1" "$P3"; then
    note_fail "payloads with different rmail.lua files were placed"
elif grep -q "differ in more than their compiled parts" "$WORK/changed.out" && grep -q "rmail.lua" "$WORK/changed.out"; then
    ok "payloads that differ in more than their compiled parts are refused, naming the file"
else
    note_fail "refused, but not for that: $(tail -3 "$WORK/changed.out" | tr '\n' ' ')"
fi
P4="$WORK/payload-mixed"
cp -R "$P2" "$P4"
cp "$P1/libs/rmail_inotify.so" "$P4/libs/rmail_inotify.so"
if make_drive "$WORK/mixed" "$P1" "$P4"; then
    note_fail "an $OTHER payload holding a $HOST library was placed"
elif grep -q "the $OTHER payload holds binaries for another kind of machine: libs/rmail_inotify.so" "$WORK/mixed.out"; then
    ok "an $OTHER payload holding a $HOST library is refused, naming it"
else
    note_fail "refused, but not for that: $(tail -3 "$WORK/mixed.out" | tr '\n' ' ')"
fi

echo ""
echo "again"
# an older drive: the whole program flat in source-code/
mkdir -p "$D/mailbox-0/source-code/deps/lua/bin"
printf 'old\n' > "$D/mailbox-0/source-code/deps/lua/bin/lua"
printf 'old\n' > "$D/mailbox-0/source-code/libs/rmail_crypto.so"
printf 'kept\n' > "$D/mailbox-0/inbox/a-letter"
if make_drive "$D" "$P1" && [ ! -e "$SC/deps" ] && [ ! -e "$SC/libs/rmail_crypto.so" ] && [ ! -e "$SC/$OTHER" ] \
   && [ -x "$SC/$HOST/deps/lua/bin/lua" ]; then
    ok "--force over an older drive leaves nothing of its old program"
else
    note_fail "the old program is still there: $(ls "$SC" | tr '\n' ' ')"
fi
[ "$(cat "$D/mailbox-0/inbox/a-letter" 2>/dev/null)" = kept ] && ok "and the mail is kept" \
    || note_fail "the mail went with it"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
