#!/bin/sh
# test-build-identity.sh — check that a daemon says which source it runs and where to get it (#615)
#
# scripts/build-stamp.sh writes `build-stamp` beside rmail.lua: a revision
# (a claim) and the digest of rmail's own Lua.  The daemon works out the
# digest again as it starts (evidence), and answers a contact's
# GET /source with both, whether they agree, the licence and the
# `source_url` setting.
#
# Cases:
#   the stamp     the two lists of files (rmail.lua's identity.FILES and
#                 build-stamp.sh's) agree; the digest is sha-256 over
#                 "<sha-256>  <path>" lines, recomputed here by hand, with a
#                 missing file hashed as "absent"; at a checkout's top the
#                 revision is `git describe --dirty`, marked dirty after an
#                 edit; a folder inside another repository is not stamped
#                 with its commit; with no git a stamp is kept while its
#                 files still match and becomes "unknown, changed since
#                 <it>" when they do not, never nested; no time is in it,
#                 so two stamps of one source are the same file
#   asked         GET /source from a contact and from the owner's phone:
#                 the stamp's revision and digest, the daemon's own digest
#                 equal to build-stamp.sh's, "as stamped", the licence, the
#                 files covered, the project as source_url; the log says
#                 it; a listen-only contact is refused; the plaintext
#                 health check still says only {"ok":true}
#   worked out once  rmail.lua edited while the daemon runs: the answer
#                 does not follow it
#   changed       the daemon started on an edited rmail.lua says "changed
#                 since stamped", with both digests, and its log asks for
#                 source_url; with source_url set, the answer names it and
#                 the log does not ask; source_url = "" is the project
#   no stamp      no build-stamp: "no stamp", no revision, and the log
#                 says install.sh writes one
#   install.sh    the new config names source_url with the licence's ask,
#                 and the stamp is written before the mailboxes restart
#   drive         a payload stamped from a checkout, placed on a drive: the
#                 launcher's copy keeps the stamp and the daemon says "as
#                 stamped"; rmail.lua edited on the drive: "changed since
#                 stamped"
#
# Usage:
#   scripts/test-build-identity.sh          # use the enclosing checkout
#   scripts/test-build-identity.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/build-identity"
PORT=59575
TEST_NAME="build-identity"
. "$SCRIPT_DIR/lib/test-receiver.sh"

STAMP="$DIR/scripts/build-stamp.sh"
UPSTREAM="https://github.com/gabrilend/r-mail"
FILES="rmail.lua libs/dkjson.lua libs/zip-compat.lua libs/zip-inflate.lua libs/zip-reader.lua libs/zip-writer.lua"
LUA_FILES="libs/dkjson.lua libs/zip-compat.lua libs/zip-inflate.lua libs/zip-reader.lua libs/zip-writer.lua"

# A program folder of our own: the daemon reads its stamp from beside
# rmail.lua, and the cases change both.
PROG="$WORK/prog"
make_prog() {  # <folder>
    rm -rf "$1"
    mkdir -p "$1/deps/lua/bin"
    cp "$DIR/rmail.lua" "$DIR/run-rmail.sh" "$1/"
    cp -R "$DIR/libs" "$1/libs"
    ln -s "$LUA" "$1/deps/lua/bin/lua"
}
make_prog "$PROG"
LAUNCHER="$PROG/run-rmail.sh"

# the digest by hand: one "<sha-256>  <path>" line per file, then sha-256
by_hand() {  # <tree>
    for f in $FILES; do
        if [ -f "$1/$f" ]; then printf '%s  %s\n' "$(sha256sum < "$1/$f" | cut -d' ' -f1)" "$f"
        else printf 'absent  %s\n' "$f"; fi
    done | sha256sum | cut -d' ' -f1
}
stamp_value() {  # <stamp file> <key>
    sed -n "s/^$2 *= *//p" "$1" | head -n 1
}

# {{{ the stamp
echo ""
echo "the stamp"
in_lua=$(grep -m1 '^    FILES = {' "$DIR/rmail.lua" | grep -o '"[^"]*"' | tr -d '"' | tr '\n' ' ' | sed 's/ $//')
in_sh=$(sed -n 's/^FILES="\(.*\)"$/\1/p' "$STAMP" | head -n 1)
if [ -n "$in_lua" ] && [ "$in_lua" = "$in_sh" ] && [ "$in_sh" = "$FILES" ]; then
    ok "rmail.lua and build-stamp.sh list the same files in the same order"
else
    note_fail "the lists differ: rmail.lua [$in_lua], build-stamp.sh [$in_sh]"
fi

D_PROG=$(sh "$STAMP" --digest "$PROG")
if [ -n "$D_PROG" ] && [ "$D_PROG" = "$(by_hand "$PROG")" ]; then
    ok "the digest is sha-256 over one \"<sha-256>  <path>\" line per file"
else
    note_fail "the digest $D_PROG is not the one made by hand, $(by_hand "$PROG")"
fi
T="$WORK/partial"
make_prog "$T"
rm -f "$T/libs/zip-compat.lua"
D_PART=$(sh "$STAMP" --digest "$T")
if [ -n "$D_PART" ] && [ "$D_PART" = "$(by_hand "$T")" ] && [ "$D_PART" != "$D_PROG" ]; then
    ok "a missing file is hashed as \"absent\", and changes the digest"
else
    note_fail "with a file missing the digest is $D_PART, by hand $(by_hand "$T")"
fi

G="$WORK/checkout"
make_prog "$G"
rm -f "$G/deps/lua/bin/lua"
# no one's git settings: a global one may sign commits, through a program
# this test cannot reach
(cd "$G" && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 && git init -q \
    && git add rmail.lua run-rmail.sh libs/*.lua \
    && git -c user.name=t -c user.email=t@t -c commit.gpgsign=false commit -q -m one) > /dev/null 2>&1
COMMIT=$(git -C "$G" rev-parse --short=12 HEAD 2>/dev/null)
sh "$STAMP" --by a-test "$G" > /dev/null 2>&1
if [ -n "$COMMIT" ] && [ "$(stamp_value "$G/build-stamp" revision)" = "$COMMIT" ] \
   && [ "$(stamp_value "$G/build-stamp" digest)" = "$(by_hand "$G")" ] \
   && [ "$(stamp_value "$G/build-stamp" by)" = a-test ]; then
    ok "at a checkout's top: the revision is git describe, with the digest and who stamped"
else
    note_fail "the checkout's stamp: $(tr '\n' ' ' < "$G/build-stamp" 2>/dev/null) (commit $COMMIT)"
fi
printf '\n-- an edit\n' >> "$G/rmail.lua"
sh "$STAMP" "$G" > /dev/null 2>&1
[ "$(stamp_value "$G/build-stamp" revision)" = "$COMMIT-dirty" ] \
    && ok "an uncommitted edit stamps the revision dirty" \
    || note_fail "after an edit the revision is $(stamp_value "$G/build-stamp" revision)"
grep -qi 'time\|date\|stamped_at' "$G/build-stamp" && note_fail "the stamp holds a time: $(tr '\n' ' ' < "$G/build-stamp")"

N="$G/inner"
make_prog "$N"
sh "$STAMP" "$N" > /dev/null 2>&1
[ "$(stamp_value "$N/build-stamp" revision)" = unknown ] \
    && ok "a folder inside another repository is not stamped with that repository's commit" \
    || note_fail "the inner folder was stamped $(stamp_value "$N/build-stamp" revision)"

C="$WORK/copied"
make_prog "$C"
printf 'revision = abc123\ndigest = %s\nby = elsewhere\n' "$D_PROG" > "$C/build-stamp"
sh "$STAMP" "$C" > /dev/null 2>&1
[ "$(stamp_value "$C/build-stamp" revision)" = abc123 ] \
    && ok "with no git, the revision of a stamp whose files still match is kept" \
    || note_fail "a matching stamp's revision became $(stamp_value "$C/build-stamp" revision)"
printf '\n-- changed after it was stamped\n' >> "$C/rmail.lua"
sh "$STAMP" "$C" > /dev/null 2>&1
first=$(stamp_value "$C/build-stamp" revision)
printf '\n-- and again\n' >> "$C/rmail.lua"
sh "$STAMP" "$C" > /dev/null 2>&1
second=$(stamp_value "$C/build-stamp" revision)
if [ "$first" = "unknown, changed since abc123" ] && [ "$second" = "$first" ] \
   && [ "$(stamp_value "$C/build-stamp" digest)" = "$(by_hand "$C")" ]; then
    ok "files changed since a copied stamp: \"unknown, changed since abc123\", never nested"
else
    note_fail "a stamp copied onto changed files: [$first] then [$second]"
fi

A="$WORK/twin-a"; B="$WORK/twin-b"
make_prog "$A"; make_prog "$B"
sh "$STAMP" --by g --revision-from "$G" "$A" > /dev/null 2>&1
sh "$STAMP" --by g --revision-from "$G" "$B" > /dev/null 2>&1
if [ -s "$A/build-stamp" ] && cmp -s "$A/build-stamp" "$B/build-stamp" \
   && [ "$(stamp_value "$A/build-stamp" revision)" = "$COMMIT-dirty" ]; then
    ok "two copies stamped from one checkout carry the same stamp, its revision from --revision-from"
else
    note_fail "two copies' stamps differ: $(tr '\n' ' ' < "$A/build-stamp") / $(tr '\n' ' ' < "$B/build-stamp")"
fi
# }}}

# {{{ the daemon
printf 'revision = v-test-1\ndigest = %s\nby = a-test\n' "$D_PROG" > "$PROG/build-stamp"
printf '\n// a website: its token is in every page\ndoor.token = "build-identity-door-token"\ndoor.listen = true\n' \
    >> "$BOX/contacts"
start_receiver
run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)
local json = mallory.json
print("section asked")
local s, b = mallory:request("GET", "/source")
local a = json.decode(b) or {}
local f = io.open(WORK .. "/answer.json", "w"); f:write(b); f:close()
print(s == 200 and "ok a contact's GET /source is answered" or ("-- GET /source answered " .. tostring(s) .. " " .. b))
print((a.revision == "v-test-1" and a.stamped_by == "a-test") and "ok with the stamp's revision and who stamped it"
      or ("-- revision " .. tostring(a.revision) .. ", by " .. tostring(a.stamped_by)))
print((a.state == "as stamped" and a.digest == a.stamped_digest) and "ok its own digest agrees with the stamp's: \"as stamped\""
      or ("-- state " .. tostring(a.state) .. ", digests " .. tostring(a.digest) .. " / " .. tostring(a.stamped_digest)))
print((a.license == "AGPL-3.0-or-later WITH AdditionRef-rmail-hook-exception"
       and a.source_url == "https://github.com/gabrilend/r-mail")
      and "ok the licence, and the project as where to get the source" or
      ("-- licence " .. tostring(a.license) .. ", source_url " .. tostring(a.source_url)))
local covers = type(a.covers) == "table" and table.concat(a.covers, " ") or tostring(a.covers)
print(covers == "rmail.lua libs/dkjson.lua libs/zip-compat.lua libs/zip-inflate.lua libs/zip-reader.lua libs/zip-writer.lua"
      and "ok and the files the digest is over" or ("-- covers " .. covers))
local s2, b2 = phone:request("GET", "/source")
print((s2 == 200 and b2 == b) and "ok the owner's phone gets the same answer" or ("-- the phone got " .. tostring(s2) .. " " .. b2))
local door = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), "build-identity-door-token")
local s3 = door:request("GET", "/source")
print(s3 == 403 and "ok a listen-only contact is refused" or ("-- a listen-only contact got " .. tostring(s3)))
local raw = mallory:raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
local body = raw:match("\r\n\r\n(.*)$")
print(body == '{"ok":true}' and "ok the plaintext health check still says only that something listens"
      or ("-- the health check said " .. tostring(body)))

print("section worked out once")
local p = io.open(WORK .. "/prog/rmail.lua", "a"); p:write("\n-- edited while running\n"); p:close()
local s4, b4 = mallory:request("GET", "/source")
local a4 = json.decode(b4) or {}
print((a4.digest == a.digest and a4.state == "as stamped") and "ok an edit on disk while it runs does not change the answer"
      or ("-- after an edit the answer is " .. b4))
LUA
stop_receiver
D_ANSWER=$(sed -n 's/.*"digest":"\([0-9a-f]*\)".*/\1/p' "$WORK/answer.json")
[ -n "$D_ANSWER" ] && [ "$D_ANSWER" = "$D_PROG" ] \
    && ok "the daemon's digest is build-stamp.sh's, worked out apart" \
    || note_fail "the daemon's digest $D_ANSWER is not build-stamp.sh's $D_PROG"
grep -q "source: v-test-1, digest $(printf '%s' "$D_PROG" | cut -c1-12) (as stamped); offered at $UPSTREAM" "$WORK/daemon.log" \
    && ok "the log says which source this is and where it is offered" \
    || note_fail "no source line in the log: $(grep 'source' "$WORK/daemon.log" | head -2 | tr '\n' ' ')"

# ask a restarted daemon; its answer is left in $got, as
# `<state>|<digest>|<stamped>|<revision>|<source_url>`.  Not called
# inside $(...): run_lua_cases counts failures in this shell.
ask_source() {
    : > "$WORK/daemon.log"
    start_receiver
    run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory = fc.for_test(arg)
local s, b = mallory:request("GET", "/source")
local a = mallory.json.decode(b) or {}
local f = io.open(arg[5] .. "/asked", "w")
f:write(table.concat({tostring(a.state), tostring(a.digest), tostring(a.stamped_digest),
    tostring(a.revision), tostring(a.source_url)}, "|"))
f:close()
if s ~= 200 then print("-- GET /source answered " .. tostring(s)) end
LUA
    stop_receiver
    got=$(cat "$WORK/asked" 2>/dev/null)
}

echo ""
echo "changed"
printf '\n-- a change of the operator'"'"'s own\n' >> "$PROG/rmail.lua"
D_EDITED=$(by_hand "$PROG")
ask_source
if [ "$got" = "changed since stamped|$D_EDITED|$D_PROG|v-test-1|$UPSTREAM" ]; then
    ok "started on an edited rmail.lua: \"changed since stamped\", with both digests"
else
    note_fail "an edited program answered $got"
fi
grep -q "source_url still names the project" "$WORK/daemon.log" && grep -q "AGPL section 13" "$WORK/daemon.log" \
    && ok "and its log asks for source_url to name the changed version" \
    || note_fail "the log does not ask for source_url: $(grep -A2 'source:' "$WORK/daemon.log" | tr '\n' ' ')"
printf 'source_url = https://example.org/my-rmail.git\n' >> "$BOX/config"
ask_source
[ "$got" = "changed since stamped|$D_EDITED|$D_PROG|v-test-1|https://example.org/my-rmail.git" ] \
    && ok "with source_url set, the answer names it" || note_fail "with source_url set the answer is $got"
grep -q "source_url still names the project" "$WORK/daemon.log" \
    && note_fail "the log asks for source_url though it is set" || ok "and the log does not ask"
sed -i 's|^source_url = .*|source_url = ""|' "$BOX/config"
ask_source
[ "${got##*|}" = "$UPSTREAM" ] && ok "source_url = \"\" is the project" \
    || note_fail "source_url = \"\" answered ${got##*|}"

echo ""
echo "no stamp"
rm -f "$PROG/build-stamp"
ask_source
[ "$got" = "no stamp|$D_EDITED|nil|nil|$UPSTREAM" ] \
    && ok "with no build-stamp: \"no stamp\" and no revision, its own digest still given" \
    || note_fail "with no stamp the answer is $got"
grep -q "no build stamp beside rmail.lua: scripts/install.sh writes one" "$WORK/daemon.log" \
    && ok "and the log says install.sh writes one" || note_fail "the log does not say there is no stamp"
# }}}

# {{{ install.sh
echo ""
echo "install.sh"
INSTALL="$DIR/scripts/install.sh"
CONFIG_BLOCK=$(sed -n '/cat > "$CONFIG_FILE" <<CONFIG/,/^CONFIG$/p' "$INSTALL")
if printf '%s\n' "$CONFIG_BLOCK" | grep -q "^source_url = $UPSTREAM$" \
   && printf '%s\n' "$CONFIG_BLOCK" | grep -q "section 13"; then
    ok "a new config names source_url, with the licence's ask beside it"
else
    note_fail "the config install.sh writes has no source_url line with the licence's ask"
fi
line_stamp=$(grep -n 'build-stamp.sh" --by install.sh "$ROOT"' "$INSTALL" | head -n 1 | cut -d: -f1)
line_restart=$(grep -n '^# RESTART' "$INSTALL" | head -n 1 | cut -d: -f1)
line_service=$(grep -n '^# SERVICE SETUP' "$INSTALL" | head -n 1 | cut -d: -f1)
if [ -n "$line_stamp" ] && [ -n "$line_restart" ] && [ "$line_stamp" -lt "$line_service" ] \
   && [ "$line_stamp" -lt "$line_restart" ]; then
    ok "install.sh stamps the checkout before it sets up and restarts the mailboxes"
else
    note_fail "install.sh does not stamp before restarting (stamp line ${line_stamp:-none}, restart ${line_restart:-none})"
fi
# }}}

# {{{ drive
echo ""
echo "drive"
case "$(uname -m)" in x86_64|amd64) ARCH=x86_64 ;; aarch64|arm64) ARCH=aarch64 ;; *) ARCH=$(uname -m) ;; esac
P="$WORK/payload"
make_prog "$P"
rm -f "$P/deps/lua/bin/lua" "$P/libs/"*.so
cp -L "$LUA" "$P/deps/lua/bin/lua"
# the compiled modules where this Lua finds them, as a payload carries them
for m in rmail_crypto rmail_inotify socket.core mime.core; do
    so=$("$LUA" -e "package.cpath = '$DIR/libs/?.so;' .. package.cpath print(package.searchpath('$m', package.cpath) or '')")
    [ -n "$so" ] || { note_fail "this machine has no $m for a payload"; continue; }
    rel=$(printf '%s' "$m" | tr . /).so
    mkdir -p "$P/libs/$(dirname "$rel")"
    cp -L "$so" "$P/libs/$rel"
done
for m in socket mime ltn12; do
    lf=$("$LUA" -e "package.path = '$DIR/libs/?.lua;' .. package.path print(package.searchpath('$m', package.path) or '')")
    [ -n "$lf" ] && cp -L "$lf" "$P/libs/$m.lua"
done
cp "$DIR/rmail_crypto.c" "$DIR/rmail_inotify.c" "$DIR/LICENSE" "$P/"
mkdir -p "$P/licenses/lua"; printf 'stand-in licence\n' > "$P/licenses/lua/LICENSE"
printf 'built by hand, for a test\n' > "$P/BUILD-NOTES.txt"
printf '%s\n' "$ARCH" > "$P/ARCH"
sh "$STAMP" --by generate-portable-mailbox.sh --revision-from "$G" "$P" > /dev/null 2>&1
DV=$(by_hand "$P")
DRV="$WORK/drive"
mkdir -p "$DRV" "$WORK/run"
if sh "$DIR/scripts/make-mailbox-drive.sh" --name me --port "$PORT" --dest "$DRV" --force --payload "$P" \
     > "$WORK/drive.out" 2>&1 && cmp -s "$DRV/mailbox-0/source-code/build-stamp" "$P/build-stamp"; then
    ok "the payload's stamp is placed with the shared program"
else
    note_fail "the drive has no stamp: $(tail -3 "$WORK/drive.out" | tr '\n' ' ')"
fi
printf 'mallory.token = "not-a-secret"\n' > "$DRV/mailbox-0/contacts"
XDG_RUNTIME_DIR="$WORK/run" timeout 60 "$DRV/mailbox-0/sync-with-contacts.sh" 2 > "$WORK/launch.out" 2>&1
grep -q "source: $COMMIT-dirty, digest $(printf '%s' "$DV" | cut -c1-12) (as stamped)" "$WORK/launch.out" \
    && ok "the launcher's copy keeps it: the daemon on the drive says \"as stamped\"" \
    || note_fail "the drive's daemon said: $(grep 'source' "$WORK/launch.out" | head -2 | tr '\n' ' ') $(tail -2 "$WORK/launch.out" | tr '\n' ' ')"
printf '\n-- edited on the drive\n' >> "$DRV/mailbox-0/source-code/rmail.lua"
XDG_RUNTIME_DIR="$WORK/run" timeout 60 "$DRV/mailbox-0/sync-with-contacts.sh" 2 > "$WORK/launch2.out" 2>&1
grep -q "source: $COMMIT-dirty, digest .* (changed since stamped)" "$WORK/launch2.out" \
    && ok "rmail.lua edited on the drive: \"changed since stamped\"" \
    || note_fail "after an edit on the drive: $(grep 'source' "$WORK/launch2.out" | head -2 | tr '\n' ' ')"
# }}}

finish
