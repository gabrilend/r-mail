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
#                        mailbox at the top, a link inside a folder, and a
#                        link whose target holds a newline.  Afterwards no
#                        link exists in attachments/, each link has its note
#                        with the right text, and the secret's content is
#                        in no filed file.
#   hidden link name     a link whose own name holds a newline, which the
#                        zip listing cannot show faithfully, so the first
#                        line of defence misses it; unzip makes it, and the
#                        second line (a search for links after extracting)
#                        must refuse the whole transfer.
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

LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"

# RAM-backed scratch space, per project convention.  Rebuilt every run.
WORK="/tmp/rmail/tests/received-links"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-received-links-*"

PORT=59480
MALLORY_TOKEN="received-links-test-contact-token-not-a-secret"
PHONE_TOKEN="received-links-test-phone-token-not-a-secret"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail received-links test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LUA" ]; then
    note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"
    exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK/box/inbox" "$WORK/box/outbox" "$WORK/box/.state" "$WORK/box/attachments"
rm -f $RAM_FILES
printf 'name = receiver\nport = %s\nattachment_pending_dir = %s\n' "$PORT" "$WORK/pending" > "$WORK/box/config"
printf 'mallory.token = "%s"\n\nphone.token = "%s"\nphone.own = true\n' \
    "$MALLORY_TOKEN" "$PHONE_TOKEN" > "$WORK/box/contacts"

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

"$LAUNCHER" "$WORK/box/config" > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!

# The Lua half: talks to the daemon, prints one "ok ..." / "-- ..." line
# per check, which the shell below counts.
"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" > "$WORK/lua.out" 2>&1 <<'LUA'
local DIR, PORT, MALLORY, PHONE, WORK = arg[1], tonumber(arg[2]), arg[3], arg[4], arg[5]
package.path = DIR .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory = fc.new(DIR, "127.0.0.1", PORT, MALLORY)
local phone   = fc.new(DIR, "127.0.0.1", PORT, PHONE)
local BOX = WORK .. "/box"

-- wait for the daemon to answer at all
local up = mallory:wait_for(30, function()
    return pcall(function() mallory:request("GET", "/") end)
end)
if not up then print("-- the daemon never answered"); os.exit(1) end

-- {{{ local function send_zip
-- Ask, accept, and send the whole zip in one piece.
local function send_zip(att_id, filename, zip_path)
    local bytes = fc.read_file(zip_path)
    if not mallory:ask_and_accept(BOX, att_id, filename, 100000, 30) then
        print("-- " .. filename .. ": consent never recorded")
        return nil
    end
    local status, answer = mallory:send_chunk(att_id, bytes, 0, 5242880)
    return status, answer
end
-- }}}

print("section links become notes")
local s, a = send_zip("11111111-1111-4111-8111-111111111111", "pkg", WORK .. "/links.zip")
print(s == 200 and a.ok == true and "ok the zip was taken" or
      ("-- the zip was not taken: " .. tostring(s) .. " " .. mallory.json.encode(a)))

print("section hidden link name")
s, a = send_zip("22222222-2222-4222-8222-222222222222", "hidden", WORK .. "/hidden.zip")
print(s == 200 and a.cancelled == true and "ok the transfer was refused" or
      ("-- the transfer was not refused: " .. tostring(s) .. " " .. mallory.json.encode(a)))
local rec = mallory:consent_record(BOX, "22222222-2222-4222-8222-222222222222")
print(rec and rec.rejection_reason == "link-in-archive" and "ok its record says link-in-archive" or
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
LUA_STATUS=$?

kill "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null

# Relay the Lua half's verdicts.
while IFS= read -r line; do
    case "$line" in
        "section "*) echo ""; echo "${line#section }" ;;
        "ok "*)      ok "${line#ok }" ;;
        "-- "*)      note_fail "${line#-- }" ;;
        *)           info "$line" ;;
    esac
done < "$WORK/lua.out"
if [ "$LUA_STATUS" -ne 0 ]; then
    note_fail "the stand-in contact stopped with status $LUA_STATUS"
fi

ATT="$WORK/box/attachments"
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
if [ "$(cat "$ATT/pkg/hello.txt" 2>&1)" = "an ordinary file" ]; then
    ok "the ordinary file arrived"
else
    note_fail "the ordinary file did not arrive"
fi
EXPECTED_KEY="This was a symbolic link to: $SECRET
It was not recreated, because a link can point at any file on this computer. If it is valid here, make it by hand."
if [ "$(cat "$ATT/pkg/key.symlink.txt" 2>&1)" = "$EXPECTED_KEY" ]; then
    ok "the link to the secret became a note naming its target"
else
    note_fail "no correct note for the link to the secret"
    info "$(cat "$ATT/pkg/key.symlink.txt" 2>&1)"
fi
if grep -q "^This was a symbolic link to: /etc/hostname$" "$ATT/pkg/inner/lnk.symlink.txt" 2>/dev/null; then
    ok "the link inside a folder became a note"
else
    note_fail "no note for the link inside a folder"
fi
if grep -q '^This was a symbolic link to: /tmp/a\\x0Ab$' "$ATT/pkg/newline-target.symlink.txt" 2>/dev/null; then
    ok "a newline in a target is written as \\x0A, keeping the note one line"
else
    note_fail "the newline in a target was not escaped"
    info "$(cat "$ATT/pkg/newline-target.symlink.txt" 2>&1)"
fi
if [ -e "$ATT/plain.txt" ]; then
    note_fail "the refused transfer still filed its ordinary file"
else
    ok "the refused transfer filed nothing"
fi

rm -f $RAM_FILES

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "daemon log: $WORK/daemon.log"
exit 1
