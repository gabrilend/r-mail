#!/bin/sh
# test-public-link-notes.sh — check that a link's readers may leave notes and the author may answer (#714)
#
# A message published with `to: url` (scripts/test-public-link.sh) is a
# conversation: anyone holding the link may leave a note on the page, and
# the author answers by putting the same URL line under `to: url` in a new
# outbox file.  The page seals a note under a key of its own made from
# the link's words and posts it to the port that served the page; the
# daemon files it in the inbox, in `<file>-notes/`, as a message from the
# link's own sender, which no contacts file names.  The inbox is where the
# notes are kept: deleting or editing a note's file there is what the page
# shows next.
#
# Cases, against one throwaway mailbox whose outbox already holds a file
# published under a code the test chose:
#   the cipher        the page's sealing is AES-256-GCM: Node's own opens
#                     it at every length around the block size, and the
#                     page's own opening reads it back
#   a note            a sealed note is answered 200 and filed under
#                     inbox/talk-notes/ under the reader's name, made safe
#                     (no folders, no leading dots, at most 40 bytes), or
#                     "a-reader" without one; a second note under the same
#                     name gets a name of its own; inbox.json records the
#                     link's sender, the name and when it came; the log
#                     says a reader left a note and never holds the code
#   the conversation  GET /m/<address> answers, sealed, the notes in the
#                     order they came, with their names and times, and
#                     `notes` true and `every` the sync period
#   an answer         an outbox file with `to: url` and the same URL line
#                     is shown as the author's, after the notes before it,
#                     with its own files numbered after the message's; its
#                     piece opens; the message itself is still the oldest
#                     file, even after an edit to it
#   the owner's hand  editing a note's file changes it on the page, and
#                     deleting it takes it off
#   refused           a note sealed under another key, with a field more,
#                     empty, or over 8 KiB; no Content-Length; a request
#                     over 32 KiB; a POST that is not to /notes (405); a
#                     note for an address with nothing published (404);
#                     nothing of these reaches the inbox
#   full              a link that holds 500 notes takes no more (403), and
#                     the log says so once
#   no notes          with public_url_notes = no a note is refused (403)
#                     and the conversation says notes are closed
#
# Node (`node`, or /opt/node22/bin/node) seals the notes with the page's
# own program; without it this test cannot run and says so.
#
# Usage:
#   scripts/test-public-link-notes.sh          # use the enclosing checkout
#   scripts/test-public-link-notes.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/public-link-notes"
PORT=59591
PUBLIC_PORT=59592
TEST_NAME="public-link-notes"
. "$SCRIPT_DIR/lib/test-receiver.sh"

NODE=$(command -v node 2>/dev/null)
[ -z "$NODE" ] && [ -x /opt/node22/bin/node ] && NODE=/opt/node22/bin/node
if [ -z "$NODE" ]; then
    note_fail "node is not installed: the notes are sealed by the page's own program"
    finish
fi

WORDS="ivory-chair-signal-maple-river-stone"
FULL_WORDS="quiet-lamp-harbor-violet-ember-cloud"
printf 'public_http_port = %s\n' "$PUBLIC_PORT" >> "$BOX/config"
FILES="$WORK/files"
mkdir -p "$FILES"
printf 'the message file\n' > "$FILES/first.txt"
printf 'the answer file, a little longer\n' > "$FILES/answer.txt"
{
    printf 'to: url\nattach: %s\n\nCome to the party.\n\nURL: http://localhost:%s/#%s\n' \
        "$FILES/first.txt" "$PUBLIC_PORT" "$WORDS"
} > "$BOX/outbox/talk"

# {{{ the page's program, used from both sides
cat > "$WORK/page.js" <<'JS'
"use strict";
const fs = require("fs"), crypto = require("crypto");
const html = fs.readFileSync(process.argv[2], "utf8");
const src = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));
const mod = { exports: null };
new Function("module", "document", src)(mod, undefined);
const L = mod.exports, work = process.argv[3], step = process.argv[4];
const check = (passed, words, detail) =>
  console.log(passed ? "ok " + words : "-- " + words + (detail === undefined ? "" : ": " + detail));
const words = fs.readFileSync(work + "/words", "utf8");
const d = L.derive(words);
const nonce = () => new Uint8Array(crypto.randomBytes(12));
const put = (name, bytes) => fs.writeFileSync(work + "/" + name, Buffer.from(bytes));
const sealJson = (key, obj) => L.seal(key, nonce(), new TextEncoder().encode(JSON.stringify(obj)));

if (step === "seal") {
  console.log("section the cipher");
  let agree = true, back = true;
  for (const len of [0, 1, 15, 16, 17, 31, 32, 33, 100, 1000, 8192]) {
    const key = crypto.randomBytes(32), pt = crypto.randomBytes(len);
    const sealed = L.seal(new Uint8Array(key), nonce(), new Uint8Array(pt));
    const iv = sealed.subarray(0, 12), tag = sealed.subarray(sealed.length - 16);
    try {
      const dc = crypto.createDecipheriv("aes-256-gcm", key, iv);
      dc.setAuthTag(tag);
      const out = Buffer.concat([dc.update(sealed.subarray(12, sealed.length - 16)), dc.final()]);
      if (Buffer.compare(out, pt) !== 0) agree = false;
    } catch (e) { agree = false; }
    const opened = L.open(new Uint8Array(key), sealed);
    if (!opened || Buffer.compare(Buffer.from(opened), pt) !== 0) back = false;
  }
  check(agree, "Node's AES-256-GCM opens what the page sealed, at every length tried");
  check(back, "the page's own opening reads back what it sealed");
  check(Buffer.from(d.noteKey).toString("hex") ===
    crypto.createHash("sha256").update("rmail public link note\0" + words).digest("hex"),
    "the note key is SHA-256 of its label and the words");

  put("note-ann.sealed", L.sealNote(d.noteKey, nonce(), "../Ann/Lee\n", "I will bring a cake."));
  put("note-anon.sealed", L.sealNote(d.noteKey, nonce(), "", "Who else is coming?"));
  put("note-ann2.sealed", L.sealNote(d.noteKey, nonce(), "Ann Lee", "And candles."));
  put("note-late.sealed", L.sealNote(d.noteKey, nonce(), "Bo", "Running late."));
  put("note-long-name.sealed", L.sealNote(d.noteKey, nonce(), "a" + "é".repeat(30), "a long name"));
  put("bad-key.sealed", L.sealNote(d.key, nonce(), "Eve", "sealed under the message key"));
  put("bad-field.sealed", sealJson(d.noteKey, { v: 1, name: "Eve", body: "hi", attachments: ["x"] }));
  put("bad-empty.sealed", L.sealNote(d.noteKey, nonce(), "Eve", "  \n "));
  put("bad-long.sealed", L.sealNote(d.noteKey, nonce(), "Eve", "x".repeat(8193)));
  put("ok-8k.sealed", L.sealNote(d.noteKey, nonce(), "Max", "y".repeat(8192)));
  const full = L.derive(fs.readFileSync(work + "/full-words", "utf8"));
  put("note-full.sealed", L.sealNote(full.noteKey, nonce(), "Late", "one too many"));
} else {
  console.log("section the conversation, opened by the page");
  const open = (name) => {
    const p = L.open(d.key, new Uint8Array(fs.readFileSync(work + "/" + name)));
    return p ? JSON.parse(new TextDecoder().decode(p)) : null;
  };
  const m = open("talk.sealed");
  check(m !== null, "the conversation opens with the code");
  const talk = (m && m.talk) || [];
  check(m && m.body === "Come to the party.\n", "the message is the oldest file's body", m && JSON.stringify(m.body));
  check(talk.length === 5, "five entries: four notes and an answer", talk.length);
  const who = talk.map((t) => t.who === "author" ? "author" : (t.name || "-")).join(",");
  check(who === "Ann Lee,-,Ann Lee,Max,author", "notes in the order they came, then the answer", who);
  check(talk[0] && talk[0].body === "I will bring a cake." && typeof talk[0].time === "number",
    "a note carries its text and when it came", JSON.stringify(talk[0]));
  const answer = talk[4] || {};
  check(answer.body === "Thanks, see you there.\n" && answer.part === 1, "the answer is the author's, part 1",
    JSON.stringify(answer));
  const files = (m && m.files) || [];
  check(files.length === 2 && files[0].part === 0 && files[1].part === 1 && files[1].name === "answer.txt",
    "the answer's file is numbered after the message's", JSON.stringify(files));
  const piece = L.open(d.key, new Uint8Array(fs.readFileSync(work + "/answer-piece.sealed")));
  const bytes = piece && files[1] && L.pieceBytes(piece, 2, 0, files[1].size, files[1].mtime);
  check(bytes && Buffer.from(bytes).toString() === "the answer file, a little longer\n",
    "the answer's file opens as file 2");
  check(m && m.notes === true && m.every === 30, "notes are open, and the page asks again every 30 seconds",
    m && (m.notes + " " + m.every));
  const later = open("talk-later.sealed");
  const lt = (later && later.talk) || [];
  check(lt.length === 5 && lt[0].body === "Who else is coming?\nedited by the owner\n",
    "an edit of a note's file shows", JSON.stringify(lt[0]));
  check(!lt.some((t) => t.body === "I will bring a cake."), "a deleted note's file takes it off");
  check(lt.length === 5 && lt[4].who === "reader" && lt[4].name === "Bo", "the last note is after the answer",
    JSON.stringify(lt[4]));
  const closed = open("talk-closed.sealed");
  check(closed && closed.notes === false, "with public_url_notes = no the conversation says notes are closed",
    closed && closed.notes);
}
JS
relay() {
    while IFS= read -r line; do
        case "$line" in
            "section "*) echo ""; echo "${line#section }" ;;
            "ok "*)      ok "${line#ok }" ;;
            "-- "*)      note_fail "${line#-- }" ;;
            *)           info "$line" ;;
        esac
    done < "$1"
}
printf '%s' "$WORDS" > "$WORK/words"
printf '%s' "$FULL_WORDS" > "$WORK/full-words"
"$NODE" "$WORK/page.js" "$DIR/data/public-link-page.html" "$WORK" seal > "$WORK/node1.out" 2>&1
[ $? -eq 0 ] || note_fail "the page's program stopped while sealing"
relay "$WORK/node1.out"
# }}}

# {{{ a link that already holds 500 notes
FULL_ADDR=$("$LUA" - "$DIR" "$FULL_WORDS" <<'LUA'
package.cpath = arg[1] .. "/libs/?.so;" .. package.cpath
local c = require("rmail_crypto")
io.write((c.sha256("rmail public link address\0" .. arg[2]):gsub(".", function(x) return string.format("%02x", x:byte()) end)))
LUA
)
printf 'to: url\n\nA crowded page.\n\nURL: http://localhost:%s/#%s\n' "$PUBLIC_PORT" "$FULL_WORDS" > "$BOX/outbox/full"
mkdir -p "$BOX/inbox/full-notes"
"$LUA" - "$DIR" "$BOX" "$FULL_ADDR" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local box, sender = arg[2], "url-" .. arg[3]:sub(1, 12)
local state = {}
for i = 1, 500 do
    local name = "full-notes/n" .. i
    local f = assert(io.open(box .. "/inbox/" .. name, "w")); f:write("note " .. i .. "\n"); f:close()
    state[name] = { from = sender, message_id = "seed-" .. i, time = i }
end
local f = assert(io.open(box .. "/.state/inbox.json", "w")); f:write(json.encode(state)); f:close()
LUA
# }}}

start_receiver

# {{{ the Lua half: posting, and what the inbox and the page get
"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$PUBLIC_PORT" > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box, work = fc.for_test(arg)
local socket, crypto, json = mallory.socket, mallory.crypto, mallory.json
local public_port = tonumber(arg[6])
local words = fc.read_file(work .. "/words")

local function check(passed, words_, detail)
    if passed then print("ok " .. words_)
    else print("-- " .. words_ .. (detail and (": " .. tostring(detail)) or "")) end
end
local function write(path, bytes)
    local f = assert(io.open(path, "wb")); f:write(bytes); f:close()
end
local function exists(path)
    local f = io.open(path, "rb"); if f then f:close() end
    return f ~= nil
end
local function sha_hex(s) return (crypto.sha256(s):gsub(".", function(c) return string.format("%02x", c:byte()) end)) end

-- {{{ local function request
local function request(method, path, body, headers)
    local c = socket.tcp()
    c:settimeout(10)
    local okc, err = c:connect("127.0.0.1", public_port)
    if not okc then return nil, err end
    local head = method .. " " .. path .. " HTTP/1.1\r\nHost: localhost\r\n"
    if headers then head = head .. headers
    elseif body then head = head .. "Content-Length: " .. #body .. "\r\n" end
    c:send(head .. "\r\n" .. (body or ""))
    local answer = c:receive("*a") or ""
    c:close()
    local h, b = answer:match("^(.-)\r\n\r\n(.*)$")
    if not h then return nil, "no answer" end
    return tonumber(h:match("^HTTP/%d%.%d (%d+)")), b
end
-- }}}

local address = sha_hex("rmail public link address\0" .. words)
local notes_path = "/m/" .. address .. "/notes"
local function post(name) return request("POST", notes_path, fc.read_file(work .. "/" .. name)) end
local function inbox_state() return json.decode(fc.read_file(box .. "/.state/inbox.json")) or {} end

-- the daemon serves the link once it has seen the file
check(mallory:wait_for(40, function() return request("GET", "/m/" .. address) == 200 end),
    "the link is served")

print("section a note")
local s, b = post("note-ann.sealed")
check(s == 200, "a sealed note is answered 200", tostring(s) .. " " .. tostring(b))
check(fc.read_file(box .. "/inbox/talk-notes/Ann-Lee") == "I will bring a cake.",
    "it is filed as inbox/talk-notes/Ann-Lee: the name made safe, the text as written")
socket.sleep(1.1)
check(select(1, post("note-anon.sealed")) == 200 and
    fc.read_file(box .. "/inbox/talk-notes/a-reader") == "Who else is coming?",
    "a note without a name is filed as a-reader")
socket.sleep(1.1)
check(select(1, post("note-ann2.sealed")) == 200, "a second note under the same name is answered 200")
local second
for name in pairs(inbox_state()) do
    if name:find("^talk%-notes/Ann%-Lee%-") then second = name end
end
check(second and fc.read_file(box .. "/inbox/" .. second) == "And candles.",
    "and kept under a name of its own", second)
socket.sleep(1.1)
check(select(1, post("ok-8k.sealed")) == 200, "a note of exactly 8 KiB is taken")
local st = inbox_state()
local meta = st["talk-notes/Ann-Lee"] or {}
check(meta.from == "url-" .. address:sub(1, 12), "inbox.json says it came from the link's sender", meta.from)
check(meta.name == "Ann Lee" and type(meta.time) == "number", "with the reader's name and when it came",
    json.encode(meta))
local log = fc.read_file(work .. "/daemon.log")
check(log:find("a reader left a note on the link for talk", 1, true), "the log says a reader left a note")
check(not log:find(words, 1, true) and not log:find("maple", 1, true), "the log never holds the code")

print("section an answer")
socket.sleep(1.1)
write(box .. "/outbox/talk-answer", "to: url\nattach: " .. work .. "/files/answer.txt\n\nThanks, see you there.\n\n" ..
    "URL: http://localhost:" .. public_port .. "/#" .. words .. "\n")
local talk
check(mallory:wait_for(40, function()
    local _, sealed = request("GET", "/m/" .. address)
    local plain = sealed and crypto.aes_gcm_decrypt(crypto.sha256("rmail public link key\0" .. words),
        sealed:sub(1, 12), sealed:sub(13))
    talk = plain and json.decode(plain)
    return talk and talk.talk and #talk.talk == 5
end), "the answer joins the conversation once a cycle has seen it", talk and json.encode(talk.talk))
-- an edit of the message keeps it the message: once a cycle has recorded
-- when it first saw the answer, the message is written again, a second
-- later, so the message's file is now the newer of the two
check(mallory:wait_for(40, function()
    local record = json.decode(fc.read_file(box .. "/.state/outbox.json")) or {}
    local r = record["talk-answer"]
    return r and r.recipients and r.recipients.url and r.recipients.url.since ~= nil
end), "the outbox record notes when a cycle first saw the answer")
socket.sleep(1.1)
local msg = fc.read_file(box .. "/outbox/talk")
write(box .. "/outbox/talk", msg)
local s2, sealed = request("GET", "/m/" .. address)
check(s2 == 200, "GET /m/<address> answers 200", s2)
write(work .. "/talk.sealed", sealed or "")
local ps, piece = request("GET", "/m/" .. address .. "/2/0")
check(ps == 200, "the answer's file is piece 0 of file 2", ps)
write(work .. "/answer-piece.sealed", piece or "")
socket.sleep(1.1)
check(select(1, post("note-late.sealed")) == 200, "a note after the answer is taken")

print("section the owner's hand")
os.remove(box .. "/inbox/talk-notes/Ann-Lee")
write(box .. "/inbox/talk-notes/a-reader", "Who else is coming?\nedited by the owner\n")
check(select(1, request("GET", "/m/" .. address)) == 200, "the conversation is still served")
write(work .. "/talk-later.sealed", select(2, request("GET", "/m/" .. address)) or "")

print("section refused")
local count = 0
for _ in pairs(inbox_state()) do count = count + 1 end
local function refused(name, want, what)
    local st_, body = post(name)
    check(st_ == want, what .. " (" .. want .. ")", tostring(st_) .. " " .. tostring(body))
end
refused("bad-key.sealed", 400, "a note sealed under the message's key is refused")
refused("bad-field.sealed", 400, "a note with a field more is refused")
refused("bad-empty.sealed", 400, "an empty note is refused")
refused("bad-long.sealed", 413, "a note over 8 KiB is refused")
check(select(1, request("POST", notes_path, "x", "")) == 400, "a note without a Content-Length is refused (400)")
check(select(1, request("POST", notes_path, nil, "Content-Length: 40000\r\n")) == 413,
    "a request over 32 KiB is refused unread (413)")
check(select(1, request("POST", "/m/" .. address, fc.read_file(work .. "/note-anon.sealed"))) == 405,
    "a POST that is not to /notes is 405")
check(select(1, request("POST", "/m/" .. string.rep("ab", 32) .. "/notes", fc.read_file(work .. "/note-anon.sealed"))) == 404,
    "a note for an address with nothing published is 404")
local after = 0
for _ in pairs(inbox_state()) do after = after + 1 end
check(after == count, "none of these reached the inbox", count .. " then " .. after)
local s3 = post("note-long-name.sealed")
local cut
for _, m in pairs(inbox_state()) do if m.name and m.name:find("^aé") then cut = m.name end end
check(s3 == 200 and cut == "a" .. string.rep("é", 19), "a long name is cut to 40 bytes at a character's edge", cut)

print("section full")
local full_addr = sha_hex("rmail public link address\0" .. fc.read_file(work .. "/full-words"))
local sf, bf = request("POST", "/m/" .. full_addr .. "/notes", fc.read_file(work .. "/note-full.sealed"))
check(sf == 403 and (bf or ""):find("full", 1, true), "a link holding 500 notes takes no more (403)",
    tostring(sf) .. " " .. tostring(bf))
request("POST", "/m/" .. full_addr .. "/notes", fc.read_file(work .. "/note-full.sealed"))
local _, said = fc.read_file(work .. "/daemon.log"):gsub("holds 500 notes and takes no more", "")
check(said == 1, "the log says so once", said)
check(not exists(box .. "/inbox/full-notes/Late"), "the note is not kept")
LUA
lua_status=$?
relay "$WORK/lua.out"
[ "$lua_status" -eq 0 ] || note_fail "the Lua half stopped with status $lua_status"
stop_receiver
# }}}

# {{{ public_url_notes = no
echo ""
echo "with public_url_notes = no"
printf 'public_url_notes = no\n' >> "$BOX/config"
: > "$WORK/daemon.log"
start_receiver
"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$PUBLIC_PORT" > "$WORK/lua2.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box, work = fc.for_test(arg)
local socket, crypto = mallory.socket, mallory.crypto
local words = fc.read_file(work .. "/words")
local address = (crypto.sha256("rmail public link address\0" .. words):gsub(".", function(c) return string.format("%02x", c:byte()) end))
local function check(passed, w, detail)
    if passed then print("ok " .. w) else print("-- " .. w .. (detail and (": " .. tostring(detail)) or "")) end
end
local function request(method, path, body)
    local c = socket.tcp(); c:settimeout(10)
    if not c:connect("127.0.0.1", tonumber(arg[6])) then return nil end
    c:send(method .. " " .. path .. " HTTP/1.1\r\n" .. (body and ("Content-Length: " .. #body .. "\r\n") or "") .. "\r\n" .. (body or ""))
    local a = c:receive("*a") or ""; c:close()
    local h, b = a:match("^(.-)\r\n\r\n(.*)$")
    return h and tonumber(h:match("^HTTP/%d%.%d (%d+)")), b
end
check(mallory:wait_for(40, function() return request("GET", "/m/" .. address) == 200 end), "the link is served")
local s, b = request("POST", "/m/" .. address .. "/notes", fc.read_file(work .. "/note-anon.sealed"))
check(s == 403, "a note is refused (403)", tostring(s) .. " " .. tostring(b))
local f = assert(io.open(work .. "/talk-closed.sealed", "wb"))
f:write(select(2, request("GET", "/m/" .. address)) or ""); f:close()
LUA
lua_status=$?
relay "$WORK/lua2.out"
[ "$lua_status" -eq 0 ] || note_fail "the Lua half stopped with status $lua_status"
stop_receiver
# }}}

"$NODE" "$WORK/page.js" "$DIR/data/public-link-page.html" "$WORK" open > "$WORK/node2.out" 2>&1
[ $? -eq 0 ] || note_fail "the page's program stopped while opening"
relay "$WORK/node2.out"

finish
