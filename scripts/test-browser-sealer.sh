#!/bin/sh
# test-browser-sealer.sh — check that the skill's browser-side sealer locks messages correctly and really delivers, even from a page browsers do not trust
#
# The rmail-integration skill (.claude/skills/rmail-integration/) carries
# a small JavaScript file that locks a message inside a web page and sends
# it to a mailbox in an ordinary web POST.  Browsers give their built-in
# lock only to "secure" pages (https, this machine, a local file); a page
# served over plain http from another machine gets none, so the file does
# the arithmetic itself.  Code other websites copy has to be right, so this
# checks it three ways:
#
#   the standards     SHA-256 of "abc" (FIPS 180-4) and AES-256-GCM test
#                     cases 13 and 14 (the GCM specification) give the
#                     published answers
#   a second lock     for lengths around every block edge, the file's
#                     AES-256-GCM output is byte for byte what Node's
#                     built-in cipher gives for the same key and nonce
#   a real daemon     run by Node: a message is answered 200, lands in the
#                     inbox recorded as from the right contact, multi-byte
#                     letters arrive whole, a wrong token gets nothing.
#                     Run by Firefox, on a page served over plain http from
#                     this machine's home-network address -- not a secure
#                     page -- the message lands, and says the page had no
#                     built-in lock
#
# Usage:
#   scripts/test-browser-sealer.sh          # use the enclosing checkout
#   scripts/test-browser-sealer.sh /path    # use some other checkout
#
# Needs Node 18 or later and Firefox.  Exit status is 0 when every case
# passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/browser-sealer"
PORT=59508
PAGE_PORT=59510
TEST_NAME="browser-sealer"
SEALER="$DIR/.claude/skills/rmail-integration/rmail-seal.js"
. "$SCRIPT_DIR/lib/test-receiver.sh"

if ! command -v node > /dev/null; then
    note_fail "node is not installed; the sealer cannot be run"
    finish
fi
if ! command -v firefox > /dev/null; then
    note_fail "firefox is not installed; the insecure-page case cannot be run"
    finish
fi
# this machine's address on the home network: a page served from it is
# not a secure page, the way a page from another machine is not
LAN_IP=$(ip route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
if [ -z "$LAN_IP" ]; then
    note_fail "no home-network address; the insecure-page case cannot be run"
    finish
fi

start_receiver

# The daemon takes a moment to open its port.
waited=0
while [ "$waited" -lt 20 ]; do
    curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/" && break
    sleep 1
    waited=$((waited + 1))
done

# relay_node_lines: print the Node half's verdict lines the usual way
relay_node_lines() {
    while IFS= read -r line; do
        case "$line" in
            "section "*) echo ""; echo "${line#section }" ;;
            "ok "*)      ok "${line#ok }" ;;
            "-- "*)      note_fail "${line#-- }" ;;
            *)           info "$line" ;;
        esac
    done < "$1"
}

node - "$SEALER" "$PORT" "$MALLORY_TOKEN" > "$WORK/node.out" 2>&1 <<'NODE'
const [sealerPath, port, token] = process.argv.slice(2);
const seal = require(sealerPath);
const nodeCrypto = require("crypto");
const url = "http://127.0.0.1:" + port + "/";
const hex = (b) => Buffer.from(b).toString("hex");

// {{{ function check
function check(passed, words, detail) {
    console.log((passed ? "ok " : "-- ") + words + (passed || !detail ? "" : ": " + detail));
}
// }}}

(async () => {
    console.log("section the standards' published answers");
    const abc = hex(seal.sha256(new TextEncoder().encode("abc")));
    check(abc === "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "SHA-256 of \"abc\" (FIPS 180-4)", abc);
    const zeroKey = new Uint8Array(32), zeroNonce = new Uint8Array(12);
    const tc13 = hex(seal.sealGcm(zeroKey, zeroNonce, new Uint8Array(0)));
    check(tc13 === "530f8afbc74536b9a963b4f1c4cb738b", "AES-256-GCM test case 13 (empty message)", tc13);
    const tc14 = hex(seal.sealGcm(zeroKey, zeroNonce, new Uint8Array(16)));
    check(tc14 === "cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919",
        "AES-256-GCM test case 14 (one zero block)", tc14);

    console.log("section the same as Node's built-in cipher");
    const lengths = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 1000, 4097];
    let same = 0;
    for (const n of lengths) {
        const key = nodeCrypto.randomBytes(32), nonce = nodeCrypto.randomBytes(12);
        const plain = nodeCrypto.randomBytes(n);
        const c = nodeCrypto.createCipheriv("aes-256-gcm", key, nonce);
        const theirs = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);
        const ours = Buffer.from(seal.sealGcm(new Uint8Array(key), new Uint8Array(nonce), new Uint8Array(plain)));
        if (ours.equals(theirs)) same++; else console.log("   differs at length " + n);
    }
    check(same === lengths.length, "AES-256-GCM matches for " + same + " of " + lengths.length +
        " lengths (0 to 4097 bytes)");
    const h = nodeCrypto.createHash("sha256").update("a token with ünïcode").digest("hex");
    check(hex(seal.sha256(new TextEncoder().encode("a token with ünïcode"))) === h,
        "SHA-256 of a token with accented letters matches");

    console.log("section delivered to a real daemon");
    let reply = await seal.sendMessage(url, token, "from-the-sealer", "sealed by rmail-seal.js\n", "cors");
    check(reply.status === 200, "the web reply is 200", String(reply.status));
    await reply.arrayBuffer();
    reply = await seal.sendMessage(url, token, "wide-letters", "café, naïve, 🐛 -- every byte counted\n", "cors");
    check(reply.status === 200, "a message with letters wider than one byte is accepted", String(reply.status));
    await reply.arrayBuffer();
    let refused = false;
    try {
        const r = await seal.sendMessage(url, "a token no one was given", "should-not-land", "nothing\n", "cors");
        await r.arrayBuffer();
    } catch (e) {
        refused = true;
    }
    check(refused, "a token nobody was given: the connection closes unanswered");
})().catch((e) => { console.log("-- the Node half stopped: " + e); process.exitCode = 1; });
NODE
node_status=$?
relay_node_lines "$WORK/node.out"
[ "$node_status" -eq 0 ] || note_fail "the Node half stopped with status $node_status"

echo ""
echo "what landed from Node"
if grep -q "sealed by rmail-seal.js" "$BOX/inbox/from-the-sealer" 2>/dev/null; then
    ok "the first message is in the inbox"
else
    note_fail "the first message is not in the inbox"
fi
# the receiver's record, read as JSON (it is written spread over lines)
sender=$(node -e 'const s = require(process.argv[1]); console.log((s["from-the-sealer"] || {}).from)' "$BOX/.state/inbox.json")
if [ "$sender" = "mallory" ]; then
    ok "recorded as from mallory"
else
    note_fail "recorded as from: $sender"
fi
if grep -q "café, naïve, 🐛 -- every byte counted" "$BOX/inbox/wide-letters" 2>/dev/null; then
    ok "the wide letters arrived whole"
else
    note_fail "the wide letters did not arrive whole: $(cat "$BOX/inbox/wide-letters" 2>&1)"
fi
if [ -e "$BOX/inbox/should-not-land" ]; then
    note_fail "the message with the wrong token landed"
else
    ok "nothing landed for the wrong token"
fi

# ---- Firefox, on a page browsers do not count as secure --------------------
#
# A tiny web server (the daemon's own Lua and luasocket) serves a page and
# the sealer from http://<home-network address>:PAGE_PORT/.  The page
# reports, inside the message it seals, whether the browser thought it
# secure and whether the built-in lock was there.
mkdir -p "$WORK/site" "$WORK/firefox-profile"
cp "$SEALER" "$WORK/site/rmail-seal.js"
cat > "$WORK/site/page.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>sealing</title>
<script src="rmail-seal.js"></script>
<script>
var report = "secure page: " + window.isSecureContext + "\n" +
             "built-in lock: " + (window.crypto && window.crypto.subtle ? "present" : "absent") + "\n" +
             "sealed by rmail-seal.js in Firefox\n";
RMAIL_SEAL.sendMessage("http://$LAN_IP:$PORT/", "$MALLORY_TOKEN", "from-firefox", report)
    .then(function () { document.title = "sent"; },
          function (e) { document.title = "failed: " + e; });
</script>
EOF
cat > "$WORK/serve.lua" <<'SERVE'
-- serve.lua — a few files over plain http, for the test only
package.path  = arg[1] .. "/libs/?.lua;" .. package.path
package.cpath = arg[1] .. "/libs/?.so;" .. package.cpath
local socket = require("socket")
local server = assert(socket.bind(arg[2], tonumber(arg[3])))
local types = {html = "text/html; charset=utf-8", js = "text/javascript; charset=utf-8"}
while true do
    local c = server:accept()
    c:settimeout(5)
    local line = c:receive("*l") or ""
    repeat local h = c:receive("*l") until not h or h == ""
    local path = line:match("^GET (/[%w%-_]*%.?%w*) ")
    if path == "/" then path = "/page.html" end
    local f = path and io.open(arg[4] .. path, "rb")
    if f then
        local body = f:read("*a"); f:close()
        c:send("HTTP/1.1 200 OK\r\nContent-Type: " .. (types[path:match("%.(%w+)$")] or "text/plain") ..
               "\r\nContent-Length: " .. #body .. "\r\nConnection: close\r\n\r\n" .. body)
    else
        c:send("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    end
    c:close()
end
SERVE
"$LUA" "$WORK/serve.lua" "$DIR" "$LAN_IP" "$PAGE_PORT" "$WORK/site" > "$WORK/serve.log" 2>&1 &
SERVE_PID=$!
sleep 1
firefox --headless --no-remote --profile "$WORK/firefox-profile" "http://$LAN_IP:$PAGE_PORT/" \
    > "$WORK/firefox.log" 2>&1 &
FIREFOX_PID=$!

waited=0
while [ "$waited" -lt 60 ] && [ ! -f "$BOX/inbox/from-firefox" ]; do
    sleep 1
    waited=$((waited + 1))
done
kill "$FIREFOX_PID" "$SERVE_PID"
wait "$FIREFOX_PID" "$SERVE_PID" 2>/dev/null

echo ""
echo "sealed by Firefox on a page served over plain http from $LAN_IP"
if [ -f "$BOX/inbox/from-firefox" ]; then
    ok "the message landed ($waited s)"
else
    note_fail "no message from Firefox within 60 s"
    info "firefox log: $WORK/firefox.log"
fi
if grep -q "^secure page: false" "$BOX/inbox/from-firefox" 2>/dev/null; then
    ok "Firefox did not count the page as secure"
else
    note_fail "the page was not shown to be insecure: $(head -2 "$BOX/inbox/from-firefox" 2>&1 | tr '\n' ';')"
fi
if grep -q "^built-in lock: absent" "$BOX/inbox/from-firefox" 2>/dev/null; then
    ok "and had no built-in lock, so the file's own arithmetic sealed it"
else
    note_fail "the built-in lock was not absent: $(sed -n 2p "$BOX/inbox/from-firefox" 2>&1)"
fi

stop_receiver
finish
