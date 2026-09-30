#!/bin/sh
# test-received-links.sh — check that a contact's zip can never plant a symbolic link
#
# A symbolic link is a tiny file whose content is a path; opening the link
# opens whatever that path names.  A zip file can carry links, and unzip
# recreates them.  Until 2026-09-29 (issue #404a) a contact could send a
# zip holding "photo -> ~/.ssh/id_rsa"; it was filed into attachments/,
# and the owner's phone -- and the on_package hook -- read the private key
# through it.
#
# Now no link is ever created from a received zip.  In its place is a
# plain note, <name>.symlink.txt, saying where the link pointed, so a
# person or an agent who wonders why something is missing finds out why
# and can make the link by hand if it is valid.  And nothing in
# attachments/ is served to the phone through a link.
#
# This script runs one throwaway mailbox and plays two parts against it
# with a stand-in contact (scripts/lib/fake-contact.lua), which speaks the
# daemon's encrypted wire format directly and so can send what no honest
# daemon would:
#
#   links become notes   a zip with a file, a link to a secret outside the
#                        mailbox, a link inside a folder, and a link whose
#                        target holds a newline.  Afterwards no link exists
#                        in attachments/, each link has its note with the
#                        right text, and the secret's content is in no
#                        filed file.
#   hidden link name     a link whose own name holds a newline.  Since #405
#                        the shared zip reader checks every name before
#                        anything is made, and refuses a control character
#                        in a name ("bad-name"): the whole transfer is
#                        refused and nothing is filed.  (With unzip, only a
#                        search for links after extracting caught it.)
#   phone and links      the owner's phone (a contact marked own) asks for a
#                        link planted in attachments/ by hand: the file, its
#                        info and its first piece are all refused, and the
#                        listing leaves it out.
#
# Usage:
#   scripts/test-received-links.sh          # use the enclosing checkout
#   scripts/test-received-links.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/received-links"
PORT=59480
TEST_NAME="received-links"
. "$SCRIPT_DIR/lib/test-receiver.sh"

# The secret a link would expose.  Outside the mailbox, like ~/.ssh.
SECRET="$WORK/secret-key.txt"
printf 'SECRET-KEY-MATERIAL-DO-NOT-SERVE\n' > "$SECRET"

# ---- The zips a hostile contact sends --------------------------------
NL='
'
mkdir -p "$WORK/build1/pkg/inner"
printf 'an ordinary file\n' > "$WORK/build1/pkg/hello.txt"
ln -s "$SECRET" "$WORK/build1/pkg/key"
ln -s /etc/hostname "$WORK/build1/pkg/inner/lnk"
ln -s "/tmp/a${NL}b" "$WORK/build1/pkg/newline-target"
(cd "$WORK/build1" && zip -qry "$WORK/links.zip" pkg)

mkdir -p "$WORK/build2"
printf 'an ordinary file\n' > "$WORK/build2/plain.txt"
ln -s "$SECRET" "$WORK/build2/hidden${NL}name"
(cd "$WORK/build2" && zip -qry "$WORK/hidden.zip" .)

start_receiver
run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, BOX, WORK = fc.for_test(arg)

print("section links become notes")
local s, a = mallory:send_whole(BOX, "11111111-1111-4111-8111-111111111111", "pkg",
                                fc.read_file(WORK .. "/links.zip"), 100000)
print(s == 200 and a.ok == true and "ok the zip was taken" or
      ("-- the zip was not taken: " .. tostring(s) .. " " .. mallory.json.encode(a or {})))

print("section hidden link name")
s, a = mallory:send_whole(BOX, "22222222-2222-4222-8222-222222222222", "hidden",
                          fc.read_file(WORK .. "/hidden.zip"), 100000)
print(s == 200 and a.cancelled == true and "ok the transfer was refused" or
      ("-- the transfer was not refused: " .. tostring(s) .. " " .. mallory.json.encode(a or {})))
local rec = mallory:consent_record(BOX, "22222222-2222-4222-8222-222222222222")
print(rec and rec.rejection_reason == "bad-name" and "ok its record says bad-name" or
      ("-- its record says " .. tostring(rec and rec.rejection_reason)))

print("section phone and links")
os.execute("ln -s '" .. WORK .. "/secret-key.txt' '" .. BOX .. "/attachments/planted'")
local st = phone:request("GET", "/api/attachments/planted")
print(st == 403 and "ok the file is refused" or ("-- the file answered " .. st))
st = phone:request("GET", "/api/attachments/planted/info")
print(st == 403 and "ok its info is refused" or ("-- its info answered " .. st))
st = phone:request("GET", "/api/attachments/planted/chunk/0")
print(st == 403 and "ok its first piece is refused" or ("-- its first piece answered " .. st))
local _, body = phone:request("GET", "/api/attachments")
print(not body:find("planted", 1, true) and "ok the listing leaves it out" or "-- the listing shows it")
LUA
stop_receiver

ATT="$BOX/attachments"
echo ""
echo "what was filed"
LINKS=$(find "$ATT" -type l ! -name planted)
if [ -z "$LINKS" ]; then
    ok "no symbolic link exists in attachments/"
else
    note_fail "links were filed: $LINKS"
fi
# -R follows links, so a filed link to the secret counts as exposing it.
if grep -Rq "SECRET-KEY-MATERIAL" "$ATT" --exclude=planted; then
    note_fail "the secret's content is in a filed file"
else
    ok "the secret's content is in no filed file"
fi
if [ -f "$ATT/pkg/hello.txt" ] && [ "$(cat "$ATT/pkg/hello.txt")" = "an ordinary file" ]; then
    ok "the ordinary file arrived"
else
    note_fail "the ordinary file did not arrive"
fi

# note_says <file> <exact first line> -- the note exists and says this
note_says() {
    [ -f "$1" ] && [ "$(head -n 1 "$1")" = "$2" ] && [ "$(wc -l < "$1")" -eq 2 ]
}
if note_says "$ATT/pkg/key.symlink.txt" "This was a symbolic link to: $SECRET" \
   && grep -qx "It was not recreated, because a link can point at any file on this computer. If it is valid here, make it by hand." "$ATT/pkg/key.symlink.txt"; then
    ok "the link to the secret became a two-line note naming its target"
else
    note_fail "no correct note for the link to the secret"
fi
if note_says "$ATT/pkg/inner/lnk.symlink.txt" "This was a symbolic link to: /etc/hostname"; then
    ok "the link inside a folder became a note"
else
    note_fail "no note for the link inside a folder"
fi
if note_says "$ATT/pkg/newline-target.symlink.txt" 'This was a symbolic link to: /tmp/a\x0Ab'; then
    ok "a newline in a target is written as \\x0A, keeping the note two lines"
else
    note_fail "the newline in a target was not escaped"
fi
if [ -e "$ATT/plain.txt" ]; then
    note_fail "the refused transfer still filed its ordinary file"
else
    ok "the refused transfer filed nothing"
fi

finish
