#!/bin/sh
# test-their-name.sh — check that a contact who calls themselves by another name is mentioned once in the inbox, and nothing is renamed
#
# Issue #506.  A mailbox's address announcement carries its own name
# (scripts/test-address-announcements.sh checks the sending side).  When
# that name is not the one the owner's contacts file uses for them, the
# daemon writes inbox/THEIR-NAME-<local name> once, saying how to rename
# them by hand, and changes nothing: their mail keeps its local name.
#
# Cases, against one throwaway mailbox named "receiver" whose contact
# "mallory" sends announcements:
#   no name          an announcement without a name (an older rmail), and
#                    one with the name the owner uses: no notice
#   another name     "suzie": the notice names both and says nothing was
#                    changed; the contacts file still says mallory; logged
#   once             deleted, then the same name again: not written again,
#                    including after a restart
#   not a name       "../suzie" and a name with a space: no notice
#   a new name       "sue": written again, naming sue
#   a clash          "phone", already another contact: the notice says so
#   back again       "mallory" once more: the notice goes
#   renamed          "suzie" again, then the owner renames mallory to suzie
#                    in contacts: the next announcement removes the notice
#   mail             a message from her through all this is filed under
#                    the local name, never under the announced one
#
# Usage:
#   scripts/test-their-name.sh          # use the enclosing checkout
#   scripts/test-their-name.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/their-name"
PORT=59520
TEST_NAME="their-name"
. "$SCRIPT_DIR/lib/test-receiver.sh"

NOTICE="$BOX/inbox/THEIR-NAME-mallory"

# announce <name or "-" for none>: mallory announces, prints the status
announce() {
    "$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$1" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local m = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local body = {ip = "127.0.0.1", port = 59521}
if arg[4] ~= "-" then body.name = arg[4] end
local status = m:request("POST", "/update-address", m.json.encode(body))
print(status)
LUA
}

# say <words> <file>: mallory sends a message with that subject
say() {
    "$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$1" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local m = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
print((m:request("POST", "/deliver", m.json.encode({type = "message", subject = arg[4],
    body = "hello\n", message_id = arg[4] .. "-" .. os.time()}))))
LUA
}

# expect_status <what> <status>
expect_status() {
    [ "$2" = "200" ] || note_fail "$1 was answered $2"
}

start_receiver
waited=0
while [ "$waited" -lt 30 ] && ! grep -q "listening\|Listening" "$WORK/daemon.log" 2>/dev/null; do
    sleep 1; waited=$((waited + 1))
done
sleep 1

echo ""
echo "no name"
expect_status "an announcement with no name" "$(announce -)"
expect_status "an announcement as mallory" "$(announce mallory)"
sleep 1
[ -e "$NOTICE" ] && note_fail "a notice was written with no name, or the same name" \
    || ok "no name, or the name the owner uses: no notice"

echo ""
echo "another name"
expect_status "an announcement as suzie" "$(announce suzie)"
if [ -e "$NOTICE" ] && grep -q "Your contact mallory calls themselves suzie" "$NOTICE" \
   && grep -q "nothing has been changed" "$NOTICE"; then
    ok "inbox/THEIR-NAME-mallory names both and says nothing was changed"
else
    note_fail "no notice naming mallory and suzie: $(cat "$NOTICE" 2>/dev/null | head -2)"
fi
if grep -q "^mallory.token" "$BOX/contacts" && ! grep -q "suzie" "$BOX/contacts"; then
    ok "the contacts file still says mallory"
else
    note_fail "the contacts file changed: $(tr '\n' ' ' < "$BOX/contacts")"
fi
grep -q "mallory calls themselves suzie: wrote THEIR-NAME-mallory" "$WORK/daemon.log" \
    && ok "the log says so" || note_fail "no log line for the notice"
[ "$(say first-note)" = "200" ] || note_fail "mallory's message was refused"

echo ""
echo "once"
rm -f "$NOTICE"
expect_status "suzie again" "$(announce suzie)"
sleep 1
[ -e "$NOTICE" ] && note_fail "the same name wrote the deleted notice again" \
    || ok "the same name again: a deleted notice stays deleted"
stop_receiver
start_receiver
sleep 3
expect_status "suzie after a restart" "$(announce suzie)"
sleep 1
[ -e "$NOTICE" ] && note_fail "a restart forgot the owner had been told" \
    || ok "and after a restart"

echo ""
echo "not a name"
announce "../suzie" > /dev/null
announce "su zie" > /dev/null
sleep 1
[ -e "$NOTICE" ] && note_fail "something that is not a name produced a notice" \
    || ok "../suzie and a name with a space: no notice"
[ -e "$BOX/THEIR-NAME-mallory" ] && note_fail "a notice was written outside the inbox"

echo ""
echo "a new name"
expect_status "an announcement as sue" "$(announce sue)"
grep -q "calls themselves sue" "$NOTICE" 2>/dev/null \
    && ok "a different name is said again, naming sue" || note_fail "no notice for the new name"
grep -q "someone else called" "$NOTICE" 2>/dev/null && note_fail "a clash was claimed where there is none"

echo ""
echo "a clash"
expect_status "an announcement as phone" "$(announce phone)"
grep -q "already has someone else called phone" "$NOTICE" 2>/dev/null \
    && ok "a name another contact holds is said to clash" || note_fail "the clash is not mentioned"

echo ""
echo "back again"
expect_status "an announcement as mallory" "$(announce mallory)"
sleep 1
[ -e "$NOTICE" ] && note_fail "the notice stayed after the names agreed again" \
    || ok "the names agree again: the notice is gone"

echo ""
echo "renamed"
expect_status "suzie once more" "$(announce suzie)"
[ -e "$NOTICE" ] && ok "suzie once more: the notice is back" || note_fail "no notice for suzie once more"
sed -i 's/^mallory\./suzie./' "$BOX/contacts"
gone=""
tries=0
while [ "$tries" -lt 15 ]; do
    announce suzie > /dev/null
    if [ ! -e "$NOTICE" ]; then gone=yes; break; fi
    sleep 1; tries=$((tries + 1))
done
[ -n "$gone" ] && ok "renamed to suzie in contacts: her next announcement removes the notice" \
    || note_fail "the notice stayed after the owner renamed her"
[ -e "$BOX/inbox/THEIR-NAME-suzie" ] && note_fail "a notice was written under her new name"
grep -q "suzie's name in contacts now matches their own: removed THEIR-NAME-mallory" "$WORK/daemon.log" \
    && ok "the log says the notice was removed" || note_fail "no log line for the removal"

echo ""
echo "mail"
if [ -e "$BOX/inbox/first-note" ] && grep -rlq "mallory" "$BOX/.state/inbox.json" \
   && ! grep -q '"suzie"' "$BOX/.state/inbox.json"; then
    ok "her message before the rename is filed under mallory"
else
    note_fail "her message is not filed under mallory: $(tr '\n' ' ' < "$BOX/.state/inbox.json" 2>/dev/null | cut -c1-200)"
fi

stop_receiver
finish
