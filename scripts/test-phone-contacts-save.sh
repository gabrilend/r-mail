#!/bin/sh
# test-phone-contacts-save.sh — check that saving contacts from the phone changes only what was changed
#
# The phone keeps the contacts in a plain sorted form with no comments,
# and sends the whole of it back after an edit.  Until 2026-10-04 (issue
# #504) the daemon wrote that over the contacts file, so one save from the
# phone erased every comment, blank line and the person's own order.  Now
# the daemon works out which contacts changed and edits only their lines.
#
# One mailbox, a contacts file with comments, blank lines and an order
# that is not alphabetical.  The stand-in phone fetches the contacts,
# edits them, and saves:
#
#   nothing changed    the file is byte for byte as it was
#   one address        alice's ip changes: that line alone changes
#   one new contact    carol is added: appended at the end
#   one removed        bob is removed: his lines and the comment directly
#                      above them go; every other comment stays
#   a reshaped one     dave's only address is written ip[1] in the file,
#                      which the phone sees as plain ip; changing it
#                      rewrites dave's lines, and the comment above stays
#
# Spacing around "=" is not compared: the daemon lines up the "=" signs of
# a contact's lines after every change, as it always has.  For the same
# reason a comment in the middle of one contact's lines was never kept
# (the daemon gathers a contact's lines together, at startup too), so the
# file here keeps its comments between contacts.
#
# Usage:
#   scripts/test-phone-contacts-save.sh          # use the enclosing checkout
#   scripts/test-phone-contacts-save.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/phone-contacts-save"
PORT=59497
TEST_NAME="phone-contacts-save"
. "$SCRIPT_DIR/lib/test-receiver.sh"

# The harness wrote mallory and phone; the file under test keeps them
# (the phone has to be allowed to save) among the person's own contacts.
cat > "$BOX/contacts" <<CONTACTS
// my contacts -- written by hand

// the phone
phone.token = "$PHONE_TOKEN"
phone.own   = true

// zed comes first on purpose
zed.ip    = "203.0.113.9"
zed.port  = 8025
zed.token = "zed-token"

# alice: home computer
alice.ip    = "203.0.113.1"
alice.port  = 8025
alice.token = "alice-token"

// bob moved away
bob.ip    = "203.0.113.2"
bob.port  = 8025
bob.token = "bob-token"

// dave's port never changes
dave.ip[1] = "203.0.113.4"
dave.port  = 8025
dave.token = "dave-token"

mallory.token = "$MALLORY_TOKEN"
CONTACTS
cp "$BOX/contacts" "$WORK/contacts.before"

start_receiver
run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)

-- {{{ local function squeeze
-- The file with runs of spaces made one, for comparing everything but
-- the alignment of "=".
local function squeeze(s)
    return (s:gsub("[ \t]+", " "))
end
-- }}}

-- {{{ local function save
-- Fetch the phone's copy, change it with `edit`, post it back.
local function save(edit)
    local status, text = phone:request("GET", "/api/contacts")
    assert(status == 200, "GET /api/contacts answered " .. tostring(status))
    local edited = edit(text)
    return phone:request("POST", "/api/contacts", edited)
end
-- }}}

-- {{{ local function check
local function check(what, status, want)
    local got = fc.read_file(BOX .. "/contacts")
    if status ~= 200 then
        print("-- " .. what .. ": the save answered " .. tostring(status))
    elseif squeeze(got) == squeeze(want) then
        print("ok " .. what)
    else
        print("-- " .. what .. ": the file is now:")
        print(got)
    end
end
-- }}}

-- The file as the daemon left it after starting (it lines up "=" signs);
-- the file written above is already lined up, so this should be it.
local before = fc.read_file(BOX .. "/contacts")
if before ~= fc.read_file(WORK .. "/contacts.before") then
    print("the daemon re-aligned the starting file; comparing against its version")
end

print("section nothing changed")
local st = save(function(t) return t end)
if st == 200 and fc.read_file(BOX .. "/contacts") == before then
    print("ok the file is byte for byte as it was")
else
    print("-- the file changed, or the save answered " .. tostring(st))
end

print("section one address changed")
st = save(function(t)
    return (t:gsub('alice%.ip = "203%.0%.113%.1"', 'alice.ip = "198.51.100.1"'))
end)
local want = before:gsub('"203%.0%.113%.1"', '"198.51.100.1"')
check("only alice's address line changed", st, want)

print("section one contact added")
st = save(function(t)
    return t .. 'carol.ip = "198.51.100.3"\ncarol.port = 8025\ncarol.token = "carol-token"\n'
end)
want = want .. '\ncarol.ip = "198.51.100.3"\ncarol.port = 8025\ncarol.token = "carol-token"\n'
check("carol appended at the end, nothing else moved", st, want)

print("section one contact removed")
st = save(function(t)
    return (t:gsub("bob%.[^\n]*\n", ""))
end)
want = want:gsub("// bob moved away\nbob%.ip [^\n]*\nbob%.port [^\n]*\nbob%.token [^\n]*\n\n", "")
check("bob's lines and the comment above them gone, the rest kept", st, want)

print("section a contact the phone sees in another shape")
st = save(function(t)
    return (t:gsub('dave%.ip = "203%.0%.113%.4"', 'dave.ip = "198.51.100.4"'))
end)
want = want:gsub('dave%.ip%[1%] = "203%.0%.113%.4"\n', 'dave.ip = "198.51.100.4"\n')
check("dave's lines rewritten, the comment above them kept", st, want)
LUA

stop_receiver
finish
