#!/bin/sh
# test-attachments-to-self.sh — check that a message sent to the mailbox's own name brings its attached files with it
#
# Issue #315.  A message to oneself (`to: <own name>`, which is how the
# phone sends to its own mailbox) used to deliver its body and drop every
# attach: line without a word.  Its files now go through the receiving
# half of a transfer -- packed, checksum checked, unpacked by the zip
# reader and filed in attachments/, on_package run -- in-process, with no
# consent form, since there is nobody to ask.
#
# One throwaway mailbox named "me", sending to itself:
#   held        one of three attached files does not exist yet: the body
#               waits, and the outbox file says which file is missing
#   delivered   the file appears: the body is in the inbox, and the three
#               files -- one staged under attachments/.uploads as the phone
#               leaves it, one folder, one plain file -- are in attachments/
#               byte for byte; the missing-file note is gone
#   as received no consent form; on_package ran for each, naming the
#               message's inbox file; the record answers each "complete";
#               nothing is left in the pending folder
#   added later an attach: line added after delivery is filed too, and
#               nothing already filed is filed again
#
# Usage:
#   scripts/test-attachments-to-self.sh          # use the enclosing checkout
#   scripts/test-attachments-to-self.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/attachments-to-self"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-attachments-to-self-*"
PORT=59524
BOX="$WORK/box"
ATT="$BOX/attachments"
FILES="$WORK/files"
DEADLINE_SECONDS=60

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# wait_until <shell test>: 0 once it holds, 1 at the deadline; sets $waited
wait_until() {
    waited=0
    while [ "$waited" -lt "$DEADLINE_SECONDS" ]; do
        eval "$1" && return 0
        sleep 1
        waited=$((waited + 1))
    done
    return 1
}

# answers: each attached path's answer in the record, "path=answer" per line
answers() {
    "$LUA" - "$DIR" "$BOX/.state/outbox.json" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local f = io.open(arg[2]) if not f then return end
local s = require("dkjson").decode(f:read("*a")) f:close()
local r = s and s["to-me"] and s["to-me"].recipients and s["to-me"].recipients.me
for path, a in pairs(r and r.attachments or {}) do print(path .. "=" .. a) end
LUA
}

echo ""
echo "rmail attachments-to-self test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LUA" ]; then
    note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$BOX/inbox" "$BOX/outbox" "$BOX/.state" "$BOX/hooks" "$ATT/.uploads/1a009c19" \
    "$FILES/notes/sub"
rm -f $RAM_FILES
printf 'name = me\nport = %s\non_package = ./hooks/package.sh\n' "$PORT" > "$BOX/config"
: > "$BOX/contacts"
cat > "$BOX/hooks/package.sh" <<EOF
#!/bin/sh
printf '%s|%s|%s|%s\n' "\$1" "\$2" "\$3" "\$4" >> "$WORK/packaged"
EOF
chmod +x "$BOX/hooks/package.sh"

head -c 300000 /dev/urandom > "$ATT/.uploads/1a009c19/photo.jpg"
printf 'first note\n' > "$FILES/notes/a.txt"
printf 'second note\n' > "$FILES/notes/sub/b.txt"
head -c 20000 /dev/urandom > "$WORK/later.src"
printf 'one more\n' > "$FILES/extra.txt"

printf 'to: me\nattach: %s\nattach: %s\nattach: %s\n\nhello me\n' \
    "$ATT/.uploads/1a009c19/photo.jpg" "$FILES/notes" "$FILES/later.bin" > "$BOX/outbox/to-me"

"$LAUNCHER" "$BOX/config" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!

echo ""
echo "held"
if wait_until 'grep -q "MISSING ATTACHMENT: $FILES/later.bin" "$BOX/outbox/to-me"'; then
    ok "the outbox file says later.bin is missing"
else
    note_fail "no missing-file note in the outbox file"
fi
sleep 2
[ -e "$BOX/inbox/to-me" ] && note_fail "the body was delivered before every file existed" \
    || ok "the body waits for it"
[ -e "$ATT/photo.jpg" ] && note_fail "a file was filed before the body was delivered"

echo ""
echo "delivered"
cp "$WORK/later.src" "$FILES/later.bin"
if wait_until '[ -e "$BOX/inbox/to-me" ] && [ -e "$ATT/later.bin" ]'; then
    ok "the file appeared: the body and the files arrived (after ${waited}s)"
else
    note_fail "the body or the files never arrived: $(ls "$ATT" | tr '\n' ' ')"
fi
grep -q "hello me" "$BOX/inbox/to-me" 2>/dev/null || note_fail "the body is not in the inbox"
if cmp -s "$ATT/photo.jpg" "$ATT/.uploads/1a009c19/photo.jpg" \
   && cmp -s "$ATT/notes/a.txt" "$FILES/notes/a.txt" \
   && cmp -s "$ATT/notes/sub/b.txt" "$FILES/notes/sub/b.txt" \
   && cmp -s "$ATT/later.bin" "$WORK/later.src"; then
    ok "the staged photo, the folder and later.bin are in attachments/, byte for byte"
else
    note_fail "attachments/ does not hold the files as sent: $(ls -R "$ATT" | tr '\n' ' ')"
fi
grep -q "MISSING ATTACHMENT" "$BOX/outbox/to-me" && note_fail "the missing-file note stayed" \
    || ok "the missing-file note is gone"

echo ""
echo "as received"
if ls "$BOX/inbox" | grep -qi consent; then
    note_fail "a consent form was written: $(ls "$BOX/inbox" | tr '\n' ' ')"
else
    ok "no consent form"
fi
wait_until '[ "$(grep -c "" "$WORK/packaged" 2>/dev/null)" -ge 3 ]'
runs=$(grep -c "^me|.*|$BOX/inbox/to-me$" "$WORK/packaged" 2>/dev/null)
if [ "$runs" = "3" ]; then
    ok "on_package ran for each file, from me, naming the message's inbox file"
else
    note_fail "on_package ran $runs time(s) as expected: $(tr '\n' ' ' < "$WORK/packaged" 2>/dev/null)"
fi
complete=$(answers | grep -c "=complete$")
[ "$complete" = "3" ] && ok "the record answers all three complete" \
    || note_fail "the record answers: $(answers | tr '\n' ' ')"
left=$(find "$ATT/.pending" -mindepth 1 ! -name .pending 2>/dev/null | tr '\n' ' ')
[ -z "$left" ] && ok "nothing is left in the pending folder" || note_fail "left in the pending folder: $left"

echo ""
echo "added later"
sed -i "s|^to: me\$|to: me\nattach: $FILES/extra.txt|" "$BOX/outbox/to-me"
if wait_until 'cmp -s "$ATT/extra.txt" "$FILES/extra.txt"'; then
    ok "an attach: line added after delivery is filed too"
else
    note_fail "the added file was never filed"
fi
sleep 2
twice=$(ls "$ATT" | grep -c "photo\|later\|notes")
if [ "$twice" = "3" ] && [ "$(grep -c "attachment received: photo.jpg" "$WORK/daemon.log")" = "1" ]; then
    ok "nothing already filed was filed again"
else
    note_fail "files were filed again: $(ls "$ATT" | tr '\n' ' ')"
fi

kill "$DAEMON_PID" 2>/dev/null
wait "$DAEMON_PID" 2>/dev/null
rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "daemon log: $WORK/daemon.log"
exit 1
