#!/bin/sh
# phase-2-demo.sh — messages as files, measured: a saved file arriving, its date kept, an edit, a hook, a note to oneself, a delete
#
# Phase 2 is the mail itself: a message is a file in one outbox that
# appears in another's inbox.  This runs a real mailbox ("home") sending to
# a stand-in recipient ("alice", scripts/lib/fake-recipient.lua, which
# records everything it is sent), measures how long each kind of news takes
# to arrive, shows what arrived, then runs phase 2's tests.
#
# Usage: issues/completed/demos/phase-2-demo.sh [checkout]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"
PHASE=2
PHASE_NAME="messages as files"
. "$SCRIPT_DIR/lib/demo.sh"
start

PORT=$DEMO_PORT_BASE
ALICE_PORT=$((PORT + 1))
TOKEN="demo-phase-2-alice-token"
demo_box home "$PORT"
printf 'alice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n' "$ALICE_PORT" "$TOKEN" > "$BOX_home/contacts"
# a hook: every message sent gets a line added at the end
mkdir -p "$BOX_home/hooks"
printf '#!/bin/sh\n# on_send: print the body to send, with a line added\nprintf "%%s\\n-- sent from the phase 2 demo\\n" "$3"\n' > "$BOX_home/hooks/on_send.sh"
chmod +x "$BOX_home/hooks/on_send.sh"
printf 'on_send = ./hooks/on_send.sh\n' >> "$BOX_home/config"

start_recipient alice "$ALICE_PORT" "$TOKEN"
start_daemon home
wait_for 30 'grep -q "listening on" "$DEMO_WORK/home.log" 2>/dev/null'
sleep 10   # its start-up: address lookups, then the first cycle

# {{{ events — print alice's events of one kind as "field=value" lines
events() {
    "$LUA" - "$DIR" "$DEMO_WORK/alice/events" "$1" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local f = io.open(arg[2]) if not f then return end
for line in f:lines() do
    local e = json.decode(line)
    if e and e.kind == arg[3] then
        print(string.format("%s %s %s %s", e.subject or e.message_id or "", tostring(e.mtime), tostring(e.body_bytes), tostring(e.frame)))
    end
end
f:close()
LUA
}
# }}}

heading "A file saved in the outbox"
# written under a hidden name (which the daemon skips), dated, then moved
# into place, so the date it carries is the one it was written with
printf 'to: alice\n\nThe garden needs water on Thursday.\n' > "$BOX_home/outbox/.garden"
touch -d "2021-05-01 09:30" "$BOX_home/outbox/.garden"
t0=$(now_ms)
mv "$BOX_home/outbox/.garden" "$BOX_home/outbox/garden"
wait_for 60 '[ -f "$DEMO_WORK/alice/inbox/garden" ]'
t1=$(now_ms)
show "arrived $((t1 - t0)) ms after it was saved: the outbox watcher woke the daemon at once,"
show "and the message went when alice's timer came due (every 30 s +/- 30 while she answers)"
show "what alice's inbox file holds:"
sed 's/^/      | /' "$DEMO_WORK/alice/inbox/garden"
events message | while read -r subject mtime bytes frame; do
    [ "$subject" = "garden" ] || continue
    show "it carried its own date: $(date -d "@$mtime" '+%Y-%m-%d %H:%M') (written then, not when it arrived)"
    show "$bytes bytes of body travelled in a $frame-byte sealed frame"
done

heading "An edit"
t0=$(now_ms)
printf 'to: alice\n\nThe garden needs water on Friday instead.\n' > "$BOX_home/outbox/garden"
wait_for 90 'grep -q Friday "$DEMO_WORK/alice/inbox/garden"'
t1=$(now_ms)
show "the new version reached alice $((t1 - t0)) ms later (when her timer came due)"
sed 's/^/      | /' "$DEMO_WORK/alice/inbox/garden"

heading "A note to oneself"
printf 'to: home\n\nbuy stamps\n' > "$BOX_home/outbox/stamps"
wait_for 30 '[ -f "$BOX_home/inbox/stamps" ]' && show "written straight into home's own inbox: $(head -1 "$BOX_home/inbox/stamps")"

heading "A delete"
t0=$(now_ms)
rm "$BOX_home/outbox/garden"
wait_for 90 'grep -q "\"kind\":\"delete\"" "$DEMO_WORK/alice/events"'
t1=$(now_ms)
show "alice was told, $((t1 - t0)) ms after the outbox file went"

heading "What alice was sent, by kind"
"$LUA" - "$DIR" "$DEMO_WORK/alice/events" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local n, bytes = {}, {}
for line in io.lines(arg[2]) do
    local e = json.decode(line)
    if e then n[e.kind] = (n[e.kind] or 0) + 1; bytes[e.kind] = (bytes[e.kind] or 0) + (e.frame or 0) end
end
for _, k in ipairs({"message", "update", "delete", "address"}) do
    if n[k] then print(string.format("    %-8s %2d request(s), %6d bytes on the wire", k, n[k], bytes[k])) end
end
LUA

stop_all

heading "Phase 2's tests"
run_tests test-outbox-headers.sh test-authoring-time.sh test-edit-delivery.sh
echo ""
