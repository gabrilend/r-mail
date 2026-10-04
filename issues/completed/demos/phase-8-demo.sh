#!/bin/sh
# phase-8-demo.sh — the Android client, measured: its source by part, its screens, its sync timing, and one exchange played the way the app makes it
#
# Phase 8 is the phone app.  It cannot be built or run on a machine with no
# Android SDK, so this shows what can be measured without one: the app's
# source by part and screen, its sync timing next to the daemon's (they
# are meant to match), and one sync exchange with a real mailbox made
# step by step the way the app's sync makes it (the phone's side is played
# by scripts/lib/fake-contact.lua).  The daemon-side tests the app depends
# on are run at the end.
#
# Usage: issues/completed/demos/phase-8-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=8
PHASE_NAME="the Android client"
. "$SCRIPT_DIR/lib/demo.sh"
start

K="$DIR/clients/android/app/src/main/kotlin/com/rmail/app"
heading "The app's source"
for part in data net sync crypto ui ui/screens; do
    n=$(find "$K/$part" -maxdepth 1 -name "*.kt" | wc -l)
    l=$(cat "$K/$part"/*.kt 2>/dev/null | wc -l)
    show "$(printf '%-12s %2d files %6d lines' "$part/" "$n" "$l")"
done
show "screens:"
for f in "$K"/ui/screens/*.kt; do
    printf "      %-26s %5d lines\n" "$(basename "$f" .kt)" "$(wc -l < "$f")"
done

heading "Its sync timing, next to the daemon's"
show "the app (sync/SyncBackoff.kt) and the daemon (ctimer in rmail.lua) are meant to agree:"
for pair in FLOOR:floorMs STEP:stepMs CEILING:ceilingMs JITTER:jitterMs; do
    d_name=${pair%%:*}; a_name=${pair#*:}
    a_ms=$(grep -o "$a_name: Long = [0-9_]*L" "$K/sync/SyncBackoff.kt" | head -1 | grep -o "[0-9_]*L$" | tr -d '_L')
    d=$(grep -o "^ *$d_name *= *[0-9]*" "$DIR/rmail.lua" | head -1 | grep -o "[0-9]*$")
    a=$([ -n "$a_ms" ] && echo $((a_ms / 1000)) || echo "?")
    same=$([ "$a" = "$d" ] && echo "same" || echo "DIFFERENT")
    show "$(printf '%-8s app %5s s   daemon %5s s   %s' "$d_name" "$a" "${d:-?}" "$same")"
done

heading "One sync, step by step, as the app makes it"
PORT=$DEMO_PORT_BASE; PHONE="demo-phase-8-phone"
demo_box home "$PORT"
printf 'phone.token = "%s"\nphone.own = true\n\nalice.token = "a"\n' "$PHONE" > "$BOX_home/contacts"
printf 'the train is late\n' > "$BOX_home/inbox/train"
printf '{"train":{"from":"alice","message_id":"m-7"}}' > "$BOX_home/.state/inbox.json"
start_daemon home
wait_for 30 'grep -q "listening on" "$DEMO_WORK/home.log" 2>/dev/null'
# let its start-up cycle finish first: a request during a cycle waits for it
wait_for 30 '[ -f "$BOX_home/.state/public_ip" ]'; sleep 3
"$LUA" - "$DIR" "$PORT" "$PHONE" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local phone = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local clock = phone.socket.gettime
local t0 = clock()
local function step(n, what, t) print(string.format("    %d  %-52s %6.1f ms", n, what, (clock() - t) * 1000)) end
local t = clock()
local _, answer = phone:post_json("/api/sync", {inbox = {}, outbox = {"note-from-phone"}, deleted_inbox = {}, deleted_outbox = {}})
step(1, "POST /api/sync: what do I lack?", t)
for _, e in ipairs(answer.fetch_inbox or {}) do
    t = clock()
    phone:request("GET", "/api/file/inbox/" .. e.filename)
    step(2, "GET /api/file/inbox/" .. e.filename .. " (keeps its date)", t)
end
t = clock()
phone:request("POST", "/api/file/outbox/note-from-phone", "to: alice\n\nwritten on the phone\n")
step(3, "POST /api/file/outbox/note-from-phone", t)
print(string.format("    the whole exchange: %.1f ms; the server's name for the mailbox: %s", (clock() - t0) * 1000, tostring(answer.mailbox_name)))
LUA
sleep 1
[ -f "$BOX_home/outbox/note-from-phone" ] && show "the phone's message is now in the home outbox, to be sent like any other"

stop_all

heading "The daemon-side tests the app stands on"
run_tests test-phone-upload-checks.sh test-phone-contacts-save.sh test-received-links.sh
show "(the app itself has no automated tests that run on this machine: no Android SDK)"
echo ""
