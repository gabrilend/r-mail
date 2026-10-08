#!/bin/sh
# test-frame-in-web-request.sh — check that a message a web page sends, wrapped in the browser's own request, is read like any other
#
# A web page cannot put bare bytes on a connection: the browser always
# writes a request line ("POST / HTTP/1.1") and headers in front of what
# the page sends.  Until 2026-10-08 rmail recognised only "GET " at the
# start of a connection and read anything else as a message length, so
# the letters "POST" became a length of 1,347,375,956 bytes, over the
# 64 MiB limit, and the message was dropped unread.
#
# Now the first byte decides: a real length always starts with 0x00-0x04,
# a web request with a capital letter.  A POST's headers are skipped and
# its body read as one sealed message; GET is still the health answer;
# other methods are refused out loud.
#
# Cases, against one throwaway mailbox named "receiver" whose contact is
# "mallory":
#   bare frames      the ordinary way in still works, and still keeps the
#                    connection open for a second request
#   frame in a POST  answered as a web reply whose body decrypts with
#                    mallory's key; a message sent that way lands in the
#                    inbox under mallory's name
#   wrong key        a POSTed frame no contact's key opens gets nothing
#   wrong length     a POST whose declared length is not its frame's is
#                    refused with 400, and the daemon keeps working
#   health check     a plain GET / is still {"ok":true}
#   other methods    PUT is answered 405, naming GET and POST
#   not a request    capital letters with no request line get silence
#
# Usage:
#   scripts/test-frame-in-web-request.sh          # use the enclosing checkout
#   scripts/test-frame-in-web-request.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/frame-in-web-request"
PORT=59507
TEST_NAME="frame-in-web-request"
. "$SCRIPT_DIR/lib/test-receiver.sh"

start_receiver

run_lua_cases <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, phone, box = fc.for_test(arg)
local stranger = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), "a token no one was given")

-- {{{ local function check
local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. detail) or "")) end
end
-- }}}

print("section bare frames, the ordinary way in")
-- two sealed requests on one connection: the second is only answered
-- if the daemon kept the connection open after the first
do
    local conn = assert(mallory.socket.tcp())
    conn:settimeout(10)
    assert(conn:connect(mallory.host, mallory.port))
    local answered = 0
    for _ = 1, 2 do
        conn:send(mallory:seal("GET", "/"))
        local len_bytes = conn:receive(4)
        if len_bytes then
            local a, b, c, d = len_bytes:byte(1, 4)
            local packet = conn:receive(a * 16777216 + b * 65536 + c * 256 + d)
            local plain = packet and mallory.crypto.aes_gcm_decrypt(
                mallory.key, packet:sub(1, 12), packet:sub(13))
            if plain and plain:match("^HTTP/%S+ 200") then answered = answered + 1 end
        end
    end
    conn:close()
    check(answered == 2, "two requests on one connection, both answered",
        answered .. " of 2 answered")
end

print("section a frame inside a web POST")
local web, inner, body = mallory:web_post("GET", "/")
check(web == 200, "the web reply is 200", tostring(web))
check(inner == 200 and body and body:find('"ok":true', 1, true),
    "its body is a sealed answer that opens with mallory's key",
    tostring(inner) .. " " .. tostring(body))

web, inner, body = mallory:web_post("POST", "/deliver", mallory.json.encode({
    type = "message", subject = "from-a-web-page", body = "sent through a browser's POST\n"}))
check(web == 200 and inner == 200, "a message sent that way is accepted",
    tostring(web) .. " / " .. tostring(inner) .. " " .. tostring(body))
local f = io.open(box .. "/inbox/from-a-web-page")
local text = f and f:read("*a"); if f then f:close() end
check(text and text:find("sent through a browser's POST", 1, true),
    "and lands in the inbox", text and text:sub(1, 80) or "no such file")
local state = fc.read_file(box .. "/.state/inbox.json")
local decoded = mallory.json.decode(state)
local meta = type(decoded) == "table" and decoded["from-a-web-page"]
check(meta and meta.from == "mallory", "recorded as from mallory",
    meta and tostring(meta.from) or "no record")

print("section a POSTed frame no contact's key opens")
web, inner = stranger:web_post("GET", "/")
check(web == nil and inner == nil, "answered with nothing", tostring(web))

print("section a POST whose declared length is not its frame's")
web, inner = mallory:web_post("GET", "/", "", 10)
check(web == 400, "refused with 400", tostring(web))
web, inner = mallory:web_post("GET", "/")
check(web == 200 and inner == 200, "the daemon still answers afterwards",
    tostring(web) .. " / " .. tostring(inner))

print("section the plain health check")
local reply = mallory:raw("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
check(reply:match("^HTTP/1.1 200") and reply:sub(-11) == '{"ok":true}',
    "GET / is still {\"ok\":true}", reply:sub(1, 60))

print("section any other method")
reply = mallory:raw("PUT / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
check(reply:match("^HTTP/1.1 405"), "PUT is answered 405", reply:sub(1, 60))
check(reply:find("\r\nAllow: GET, POST\r\n", 1, true), "naming GET and POST")
reply = mallory:raw("DELETE /x HTTP/1.1\r\n\r\n")
check(reply:match("^HTTP/1.1 405"), "a method longer than four letters too", reply:sub(1, 60))

print("section capital letters that are no request")
reply = mallory:raw("HELLO THERE\r\n\r\n")
check(reply == "", "answered with silence", reply:sub(1, 60))
LUA

if grep -q "refused a web PUT request" "$WORK/daemon.log"; then
    ok "the daemon's log says why PUT was refused"
else
    note_fail "no log line for the refused PUT"
fi
if grep -q "refused a web POST: its body is 10 bytes" "$WORK/daemon.log"; then
    ok "the daemon's log says why the mismatched POST was refused"
else
    note_fail "no log line for the mismatched POST"
fi

stop_receiver
finish
