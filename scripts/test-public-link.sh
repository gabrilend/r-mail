#!/bin/sh
# test-public-link.sh — check that `to: url` publishes a message as a link a browser opens (#714)
#
# `to: url` in an outbox file publishes the message for someone who has a
# browser and no rmail.  The daemon appends a `URL:` line whose part after
# `#` is a code of hand-alternating words; the code never reaches the
# server.  From it the page works out an address (a hash, which it asks
# the server for) and a key (which opens what the server answers).  The
# daemon serves the page and the sealed message on its own port,
# public_http_port, reading the outbox file afresh at every visit.
#
# Cases, against one throwaway mailbox with a stand-in contact "friend"
# (scripts/lib/fake-recipient.lua) on the same file:
#   the URL line     appended once, at the bottom after a blank line, with
#                    public_url_words words, the first from the right-hand
#                    list and the rest from the left-hand one; the log
#                    names the file but never the code
#   the contact      friend gets the body without the URL line, and the
#                    line's arrival sends friend no edit
#   the page         GET / answers the page with its Content-Security-
#                    Policy, no-store, nosniff and no-referrer
#   the message      GET /m/<address> answers sealed bytes that the
#                    page's own program (run in Node) opens with the code:
#                    the body without the URL line, and the files under
#                    `to: url` with their sizes; a folder and a missing
#                    file are listed with why they are not offered
#   the pieces       each piece opens, says which piece of which file it
#                    is, and the pieces join into the file byte for byte;
#                    a piece checked against the wrong place, a changed
#                    byte, and a wrong code are all refused
#   refused          a wrong address, a piece past the end, a folder's
#                    piece, a path outside /m/ and a `..` path are 404;
#                    POST is 405; a request that is not HTTP is 400
#   an edit          shows at the next visit
#   taken down       removing `to: url` answers 404 from then on, keeps
#                    the file for friend, and drops url from the record
#   no port          without public_http_port nothing listens, the file
#                    is marked NO PUBLIC PORT and gets no URL line
#   the cipher       the page's AES-256-GCM opens what Node's own seals,
#                    at every length around the block size, refuses any
#                    changed byte, its SHA-256 matches Node's, and its
#                    speed is measured (at least 25 MiB/s is required)
#
# Node (`node`, or /opt/node22/bin/node) runs the page's program; without
# it the Node cases are skipped and say so.
#
# Usage:
#   scripts/test-public-link.sh          # use the enclosing checkout
#   scripts/test-public-link.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/public-link"
PORT=59541
PUBLIC_PORT=59542
FRIEND_PORT=59543
FRIEND_TOKEN="public-link-friend-token-not-a-secret"
TEST_NAME="public-link"
. "$SCRIPT_DIR/lib/test-receiver.sh"

NODE=$(command -v node 2>/dev/null)
[ -z "$NODE" ] && [ -x /opt/node22/bin/node ] && NODE=/opt/node22/bin/node

printf 'public_http_port = %s\n' "$PUBLIC_PORT" >> "$BOX/config"
printf '\nfriend.ip = "127.0.0.1"\nfriend.port = %s\nfriend.token = "%s"\n' \
    "$FRIEND_PORT" "$FRIEND_TOKEN" >> "$BOX/contacts"

# the files the message offers: a picture of three pieces (the last one
# short), a small note, a folder and a path with nothing at it
FILES="$WORK/files"
mkdir -p "$FILES/a-folder"
head -c 2500000 /dev/urandom > "$FILES/picture.jpg"
printf 'a small note\n' > "$FILES/note.txt"
printf 'inside\n' > "$FILES/a-folder/inside.txt"
{
    printf 'to: url\n'
    printf 'attach: %s\n' "$FILES/picture.jpg" "$FILES/note.txt" "$FILES/a-folder" "$FILES/not-there.png"
    printf 'to: friend\n\n'
    printf 'Hello from the test.\nSecond line.\n'
} > "$BOX/outbox/for-the-web"

"$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$FRIEND_PORT" "$FRIEND_TOKEN" "$WORK/friend" \
    > "$WORK/friend.log" 2>&1 &
FRIEND_PID=$!
start_receiver

# {{{ the Lua half: the daemon's side, and fetching what Node checks
"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$PUBLIC_PORT" > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box, work = fc.for_test(arg)
local socket, crypto, json = mallory.socket, mallory.crypto, mallory.json
local public_port = tonumber(arg[6])
local outbox_file = box .. "/outbox/for-the-web"

local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. tostring(detail)) or "")) end
end

local function write(path, bytes)
    local f = assert(io.open(path, "wb")); f:write(bytes); f:close()
end

-- {{{ local function get
-- One request on a fresh connection to the public port: status, headers
-- (lower-case names), body.
local function get(path, method, raw)
    local c = socket.tcp()
    c:settimeout(10)
    local okc, err = c:connect("127.0.0.1", public_port)
    if not okc then return nil, err end
    c:send(raw or ((method or "GET") .. " " .. path .. " HTTP/1.1\r\nHost: localhost\r\n\r\n"))
    local answer = c:receive("*a") or ""
    c:close()
    local head, body = answer:match("^(.-)\r\n\r\n(.*)$")
    if not head then return nil, "no answer" end
    local status = tonumber(head:match("^HTTP/%d%.%d (%d+)"))
    local headers = {}
    for name, value in head:gmatch("\n([^:\r\n]+):%s*([^\r\n]*)") do headers[name:lower()] = value end
    return status, headers, body
end
-- }}}

local function sha_hex(s) return (crypto.sha256(s):gsub(".", function(c) return string.format("%02x", c:byte()) end)) end
local function open(key, sealed) return crypto.aes_gcm_decrypt(key, sealed:sub(1, 12), sealed:sub(13)) end

print("section the URL line")
local text
local appeared = mallory:wait_for(40, function()
    text = fc.read_file(outbox_file)
    return text:find("\nURL: ", 1, true) ~= nil
end)
check(appeared, "a URL line is added to the file", text)
local link, words = text:match("\n\nURL: (http://[^\n#]+/#([%a%-]+))\n$")
check(link ~= nil, "it is the last line, after a blank line, a link with the code after #", text:sub(-120))
local _, count = text:gsub("\nURL: ", "")
check(count == 1, "there is one URL line", count)
words = words or ""
local list = {}
for w in words:gmatch("[^-]+") do list[#list + 1] = w end
check(#list == 6, "the code is 6 words by default", words)
local function set_of(name)
    local s = {}
    for w in fc.read_file(arg[1] .. "/data/slug-words-" .. name .. ".txt"):gmatch("[a-z]+") do s[w] = true end
    return s
end
local right, left = set_of("right"), set_of("left")
local hands = right[list[1] or ""] == true
for i = 2, #list do hands = hands and left[list[i]] == true end
check(hands, "the first word is from the right-hand list, the rest from the left-hand one", words)
check(link and link:find(":" .. public_port .. "/#", 1, true), "the link names the public port", link)
local log = fc.read_file(work .. "/daemon.log")
check(log:find("public link added for for-the-web", 1, true), "the log says a link was added")
check(#words > 0 and not log:find(list[2] or "?", 1, true) and not log:find(words, 1, true),
    "the log never holds the code")
check(log:find("public links served on :" .. public_port, 1, true), "the log names the public port")

print("section the contact on the same file")
local friend_body
check(mallory:wait_for(40, function()
    local f = io.open(work .. "/friend/inbox/for-the-web", "rb")
    if f then friend_body = f:read("*a"); f:close() end
    return friend_body ~= nil
end), "friend got the message")
check(friend_body == "Hello from the test.\nSecond line.\n", "friend's copy has no URL line", friend_body)
-- the URL line's write woke a cycle; give it, and one more, time to send an edit if it would
socket.sleep(6)
local events = fc.read_file(work .. "/friend/events")
check(not events:find('"update"', 1, true), "the URL line sent friend no edit", events)

print("section the page")
local status, headers, body = get("/")
check(status == 200, "GET / answers 200", status)
headers = headers or {}
check((headers["content-type"] or ""):find("text/html", 1, true), "as HTML", headers["content-type"])
local csp = headers["content-security-policy"] or ""
check(csp:find("default-src 'none'", 1, true) and csp:find("connect-src 'self'", 1, true)
    and csp:find("form-action 'none'", 1, true), "with a Content-Security-Policy that lets it ask only its own server", csp)
check(headers["cache-control"] == "no-store" and headers["x-content-type-options"] == "nosniff"
    and headers["referrer-policy"] == "no-referrer", "no-store, nosniff, no-referrer")
check(body == fc.read_file(arg[1] .. "/data/public-link-page.html"), "the body is data/public-link-page.html")
check(not body:find("<script src", 1, true) and not body:find("<link", 1, true)
    and not body:find("@import", 1, true), "the page loads nothing from elsewhere")
status = get("/index.html")
check(status == 200, "GET /index.html is the same page", status)

print("section the sealed message")
local address = sha_hex("rmail public link address\0" .. words)
local key = crypto.sha256("rmail public link key\0" .. words)
local sealed
status, headers, sealed = get("/m/" .. address)
check(status == 200 and (headers or {})["content-type"] == "application/octet-stream",
    "GET /m/<address> answers sealed bytes", status)
sealed = sealed or ""
write(work .. "/message.sealed", sealed)
check(not sealed:find("Hello", 1, true), "the message is not readable on the way")
local plain = open(key, sealed)
local message = plain and json.decode(plain)
check(message and message.body == "Hello from the test.\nSecond line.\n", "it opens with the code to the body, without the URL line",
    plain)
local again = select(3, get("/m/" .. address))
check(again ~= sealed, "each answer is sealed afresh (a new nonce)")
check(select(1, get("/m/" .. address:upper())) == 200, "the address is read in either case")

-- the pieces, saved for Node to open
for p = 0, 2 do
    local s, _, b = get("/m/" .. address .. "/1/" .. p)
    check(s == 200, "piece " .. p .. " of the picture answers 200", s)
    write(work .. "/piece-1-" .. p .. ".sealed", b or "")
end
local s2, _, b2 = get("/m/" .. address .. "/2/0")
check(s2 == 200, "the note's one piece answers 200", s2)
write(work .. "/piece-2-0.sealed", b2 or "")
write(work .. "/words", words)

print("section refused")
check(select(1, get("/m/" .. string.rep("ab", 32))) == 404, "a wrong address is 404")
check(select(1, get("/m/" .. address:sub(1, 63))) == 404, "a short address is 404")
check(select(1, get("/m/" .. address .. "/1/3")) == 404, "a piece past the end is 404")
check(select(1, get("/m/" .. address .. "/3/0")) == 404, "a folder's piece is 404")
check(select(1, get("/m/" .. address .. "/4/0")) == 404, "a missing file's piece is 404")
check(select(1, get("/m/" .. address .. "/9/0")) == 404, "a file that is not listed is 404")
check(select(1, get("/../../etc/passwd")) == 404, "a path with .. is 404")
check(select(1, get("/data/public-link-page.html")) == 404, "a path outside / and /m/ is 404")
check(select(1, get("/", "POST")) == 405, "POST is 405")
check(select(1, get("/", "DELETE")) == 405, "DELETE is 405")
check(select(1, get(nil, nil, "hello there\r\n\r\n")) == 400, "a request that is not HTTP is 400")
local before = fc.read_file(outbox_file)
get(nil, nil, "GET /" .. string.rep("a", 20000) .. " HTTP/1.1\r\n\r\n")
check(fc.read_file(outbox_file) == before, "a long request changes nothing")

print("section an edit")
write(outbox_file, (fc.read_file(outbox_file):gsub("Second line%.", "An edited line.")))
local edited
check(mallory:wait_for(10, function()
    local p = open(key, select(3, get("/m/" .. address)) or "")
    edited = p and json.decode(p)
    return edited and edited.body:find("An edited line.", 1, true)
end), "the edit shows at the next visit", edited and edited.body)

print("section taken down")
write(outbox_file, (fc.read_file(outbox_file):gsub("^to: url\n", "")))
local record
check(mallory:wait_for(40, function()
    record = json.decode(fc.read_file(box .. "/.state/outbox.json"))
    local r = record and record["for-the-web"]
    return r and r.recipients and r.recipients.url == nil
end), "url is dropped from the outbox record")
check(record and record["for-the-web"] and record["for-the-web"].recipients.friend ~= nil,
    "friend is still on the record")
check(select(1, get("/m/" .. address)) == 404, "the link answers 404")
check(io.open(outbox_file) ~= nil, "the file stays, for friend")
check(fc.read_file(work .. "/daemon.log"):find("public link for for-the-web taken down", 1, true),
    "the log says it was taken down")
LUA
lua_status=$?
while IFS= read -r line; do
    case "$line" in
        "section "*) echo ""; echo "${line#section }" ;;
        "ok "*)      ok "${line#ok }" ;;
        "-- "*)      note_fail "${line#-- }" ;;
        *)           info "$line" ;;
    esac
done < "$WORK/lua.out"
[ "$lua_status" -eq 0 ] || note_fail "the Lua half stopped with status $lua_status"
# }}}

# {{{ the Node half: the page's own program opens what the daemon sealed
if [ -z "$NODE" ]; then
    echo ""
    info "node is not installed: the page's program was not run (the cases above opened the seals in Lua)"
else
cat > "$WORK/check.js" <<'JS'
"use strict";
const fs = require("fs"), crypto = require("crypto");
const [pagePath, work, picture, note] = process.argv.slice(2);
const html = fs.readFileSync(pagePath, "utf8");
const src = html.slice(html.indexOf("<script>") + 8, html.lastIndexOf("</script>"));
const mod = { exports: null };
new Function("module", "document", src)(mod, undefined);
const L = mod.exports;
const check = (passed, words, detail) =>
  console.log(passed ? "ok " + words : "-- " + words + (detail === undefined ? "" : ": " + detail));
const read = (name) => new Uint8Array(fs.readFileSync(work + "/" + name));

console.log("section the page's program opens it");
const words = fs.readFileSync(work + "/words", "utf8");
const d = L.derive("  " + words.toUpperCase().replace(/-/g, " ") + " ");
check(d.words === words, "a code typed with capitals and spaces is the same code", d.words);
const lit = L.readInput("http://192.0.2.1:8028/index.html#" + words, null);
check(lit.base === "http://192.0.2.1:8028" && lit.words === words, "a pasted link gives its server and its code",
  JSON.stringify(lit));
check(L.readInput(words, "http://h:1").base === "http://h:1", "a typed code asks the server the page came from");
const message = L.open(d.key, read("message.sealed"));
check(message !== null, "the message opens with the code");
const m = message ? JSON.parse(new TextDecoder().decode(message)) : { files: [] };
check(m.body === "Hello from the test.\nSecond line.\n", "the body is the message without its URL line", m.body);
const pic = fs.statSync(picture);
const f = m.files || [];
check(f.length === 4, "four files are listed", f.length);
check(f[0] && f[0].name === "picture.jpg" && f[0].size === pic.size && f[0].pieces === 3,
  "the picture: its name, size and three pieces", JSON.stringify(f[0]));
check(f[1] && f[1].name === "note.txt" && f[1].pieces === 1, "the note: one piece", JSON.stringify(f[1]));
check(f[2] && f[2].name === "a-folder" && /folder/.test(f[2].missing || "") && f[2].size === undefined,
  "the folder is listed with why it is not offered", JSON.stringify(f[2]));
check(f[3] && f[3].name === "not-there.png" && f[3].missing === "not there",
  "the missing file is listed as not there", JSON.stringify(f[3]));
check(m.piece_size === 1048576, "pieces are 1 MiB", m.piece_size);
const wrong = L.derive(words + "-extra");
check(wrong.address !== d.address && L.open(wrong.key, read("message.sealed")) === null, "a wrong code opens nothing");

console.log("section the pieces");
const parts = [];
for (let p = 0; p < 3; p++) {
  const plain = L.open(d.key, read("piece-1-" + p + ".sealed"));
  const bytes = plain && L.pieceBytes(plain, 1, p, f[0].size, f[0].mtime);
  check(bytes !== null && bytes !== undefined, "piece " + p + " opens and says it is piece " + p + " of file 1");
  if (bytes) parts.push(Buffer.from(bytes));
  if (p === 1 && plain) {
    check(L.pieceBytes(plain, 1, 2, f[0].size, f[0].mtime) === null, "the same piece checked as another piece is refused");
    check(L.pieceBytes(plain, 2, 1, f[0].size, f[0].mtime) === null, "or as another file's piece");
    check(L.pieceBytes(plain, 1, 1, f[0].size, f[0].mtime + 1) === null, "or as another version of the file");
  }
}
check(Buffer.compare(Buffer.concat(parts), fs.readFileSync(picture)) === 0, "the pieces join into the picture, byte for byte");
const n = L.open(d.key, read("piece-2-0.sealed"));
const nb = n && L.pieceBytes(n, 2, 0, f[1].size, f[1].mtime);
check(nb && Buffer.from(nb).toString() === fs.readFileSync(note, "utf8"), "the note's piece is the note");
const changed = read("piece-1-0.sealed"); changed[5000] ^= 1;
check(L.open(d.key, changed) === null, "a piece with one byte changed is refused");

console.log("section the cipher");
let agree = true, refused = true;
for (const len of [0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 1000, 4096, 65537]) {
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(12), pt = crypto.randomBytes(len);
  const c = crypto.createCipheriv("aes-256-gcm", key, iv);
  const sealed = new Uint8Array(Buffer.concat([iv, c.update(pt), c.final(), c.getAuthTag()]));
  const out = L.open(new Uint8Array(key), sealed);
  if (!out || Buffer.compare(Buffer.from(out), pt) !== 0) agree = false;
  for (const at of [0, 11, 12, sealed.length - 17, sealed.length - 1]) {
    if (at < 0 || at >= sealed.length) continue;
    const t = sealed.slice(); t[at] ^= 0x80;
    if (L.open(new Uint8Array(key), t) !== null) refused = false;
  }
}
check(agree, "it opens what Node's AES-256-GCM sealed, at every length tried");
check(refused, "a changed byte anywhere (nonce, text or tag) is refused");
let sha = true;
for (const s of ["", "abc", "a".repeat(55), "a".repeat(56), "a".repeat(64), "a".repeat(1000)])
  if (Buffer.from(L.sha256(new TextEncoder().encode(s))).toString("hex") !== crypto.createHash("sha256").update(s).digest("hex")) sha = false;
check(sha, "its SHA-256 matches Node's at the padding edges");
const size = 32 << 20, key = crypto.randomBytes(32), iv = crypto.randomBytes(12);
const c = crypto.createCipheriv("aes-256-gcm", key, iv);
const big = new Uint8Array(Buffer.concat([iv, c.update(Buffer.alloc(size, 7)), c.final(), c.getAuthTag()]));
L.open(new Uint8Array(key), big.subarray(0, 1 << 20));   // warm up
const t0 = process.hrtime.bigint();
const opened = L.open(new Uint8Array(key), big);
const speed = 32 / (Number(process.hrtime.bigint() - t0) / 1e9);
console.log("measured: " + speed.toFixed(1) + " MiB/s");
check(opened !== null && speed >= 25, "it opens 32 MiB at 25 MiB/s or more", speed.toFixed(1));
JS
"$NODE" "$WORK/check.js" "$DIR/data/public-link-page.html" "$WORK" "$FILES/picture.jpg" "$FILES/note.txt" \
    > "$WORK/node.out" 2>&1
node_status=$?
while IFS= read -r line; do
    case "$line" in
        "section "*) echo ""; echo "${line#section }" ;;
        "ok "*)      ok "${line#ok }" ;;
        "-- "*)      note_fail "${line#-- }" ;;
        *)           info "$line" ;;
    esac
done < "$WORK/node.out"
[ "$node_status" -eq 0 ] || note_fail "the Node half stopped with status $node_status"
fi
# }}}

stop_receiver
touch "$WORK/friend/stop"
sleep 1
kill "$FRIEND_PID" 2>/dev/null
wait "$FRIEND_PID" 2>/dev/null

# {{{ no public port: nothing listens, and the author is told why
echo ""
echo "without public_http_port"
grep -v '^public_http_port' "$BOX/config" > "$WORK/config.new" && mv "$WORK/config.new" "$BOX/config"
printf 'to: url\n\nnot published\n' > "$BOX/outbox/no-port"
: > "$WORK/daemon.log"
start_receiver
"$LUA" - "$DIR" "$PORT" "$MALLORY_TOKEN" "$PHONE_TOKEN" "$WORK" "$PUBLIC_PORT" > "$WORK/lua2.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box = fc.for_test(arg)
local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. tostring(detail)) or "")) end
end
local text
check(mallory:wait_for(40, function()
    text = fc.read_file(box .. "/outbox/no-port")
    return text:find("NO PUBLIC PORT", 1, true) ~= nil
end), "the file is marked NO PUBLIC PORT", text)
check(not text:find("\nURL:", 1, true), "it gets no URL line")
local c = mallory.socket.tcp()
c:settimeout(2)
check(c:connect("127.0.0.1", tonumber(arg[6])) == nil, "nothing listens on the public port")
c:close()
LUA
lua_status=$?
while IFS= read -r line; do
    case "$line" in
        "ok "*)      ok "${line#ok }" ;;
        "-- "*)      note_fail "${line#-- }" ;;
        *)           info "$line" ;;
    esac
done < "$WORK/lua2.out"
[ "$lua_status" -eq 0 ] || note_fail "the Lua half stopped with status $lua_status"
stop_receiver
# }}}

finish
