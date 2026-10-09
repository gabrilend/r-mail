#!/bin/sh
# test-browser-sealer.sh — check that the skill's browser-side sealer really delivers to a real daemon
#
# The rmail-integration skill (.claude/skills/rmail-integration/) carries a
# small JavaScript file that locks a message in a web page, with a token
# the viewer supplies, and sends it inside an ordinary web POST.  Code that
# other projects copy has to work, so this runs that very file under Node
# (which has the same built-in lock, WebCrypto, and the same fetch as a
# browser) against a throwaway mailbox, and checks what landed.
#
# Cases, against one throwaway mailbox named "receiver" whose contact is
# "mallory":
#   delivered       a message sealed with mallory's token is answered 200,
#                   the answer opens with the same key, and the message
#                   is in the inbox, recorded as from mallory
#   byte counts     a body with accented letters and an emoji arrives
#                   whole -- the sealed request counts bytes, not
#                   characters
#   wrong token     a message sealed with a token nobody was given gets
#                   no answer and lands nowhere
#
# Usage:
#   scripts/test-browser-sealer.sh          # use the enclosing checkout
#   scripts/test-browser-sealer.sh /path    # use some other checkout
#
# Needs Node 18 or later.  Exit status is 0 when every case passes, 1
# otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/browser-sealer"
PORT=59508
TEST_NAME="browser-sealer"
SEALER="$DIR/.claude/skills/rmail-integration/rmail-seal.js"
. "$SCRIPT_DIR/lib/test-receiver.sh"

if ! command -v node > /dev/null; then
    note_fail "node is not installed; the sealer cannot be run"
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

node --input-type=module - "$SEALER" "$PORT" "$MALLORY_TOKEN" > "$WORK/node.out" 2>&1 <<'NODE'
const [sealerPath, port, token] = process.argv.slice(2);
const seal = await import("file://" + sealerPath);
const url = "http://127.0.0.1:" + port + "/";

// {{{ function check
function check(passed, words, detail) {
    console.log((passed ? "ok " : "-- ") + words + (passed || !detail ? "" : ": " + detail));
}
// }}}

console.log("section a message sealed in the page");
let { reply, key } = await seal.sendMessage(url, token, "from-the-sealer",
    "sealed by rmail-seal.js\n", "cors");
check(reply.status === 200, "the web reply is 200", String(reply.status));
let inner = await seal.openReply(key, await reply.arrayBuffer());
check(inner.status === 200 && inner.body.includes('"ok":true'),
    "its answer opens with the same key and says ok", inner.status + " " + inner.body);

console.log("section letters wider than one byte");
({ reply, key } = await seal.sendMessage(url, token, "wide-letters",
    "café, naïve, 🐛 -- every byte counted\n", "cors"));
inner = await seal.openReply(key, await reply.arrayBuffer());
check(inner.status === 200, "accepted", inner.status + " " + inner.body);

console.log("section a token nobody was given");
let refused = false;
try {
    const r = await seal.sendMessage(url, "a token no one was given", "should-not-land",
        "nothing\n", "cors");
    await r.reply.arrayBuffer();
} catch (e) {
    refused = true;
}
check(refused, "no answer: the connection closes unanswered");
NODE
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

echo ""
echo "what landed"
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

stop_receiver
finish
