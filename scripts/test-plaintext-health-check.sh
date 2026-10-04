#!/bin/sh
# test-plaintext-health-check.sh — check that the unencrypted "are you there?" answer says nothing about the mailbox
#
# rmail answers a plain web request, `GET /`, without any key, so a person
# can test from outside that their router forwards the port.  Until
# 2026-10-04 (issue #410) that answer carried the mailbox's own name, so
# anyone who could reach the port could learn whose mailbox it was.  The
# name came along by accident when encryption moved from TLS into each
# message; nothing ever read it.
#
# Cases, against one throwaway mailbox named "receiver":
#   the answer        a plain GET / is answered 200 with {"ok":true}
#   no name           the configured name appears nowhere in the reply,
#                     headers included
#   still a test      the router-settings validator's own probe (a GET /
#                     that only needs an answer) still gets one
#
# Usage:
#   scripts/test-plaintext-health-check.sh          # use the enclosing checkout
#   scripts/test-plaintext-health-check.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/plaintext-health-check"
PORT=59496
TEST_NAME="plaintext-health-check"
. "$SCRIPT_DIR/lib/test-receiver.sh"

start_receiver

# The daemon takes a moment to open its port.
waited=0
reply=""
while [ "$waited" -lt 20 ]; do
    reply="$(curl -s -i --max-time 3 "http://127.0.0.1:$PORT/")"
    [ -n "$reply" ] && break
    sleep 1
    waited=$((waited + 1))
done

echo ""
echo "a plain GET /"
case "$reply" in
    "HTTP/1.1 200"*) ok "answered 200" ;;
    *)               note_fail "no 200 answer (got: $(printf '%s' "$reply" | head -1))" ;;
esac
body="$(printf '%s' "$reply" | tail -1)"
if [ "$body" = '{"ok":true}' ]; then
    ok "the body is {\"ok\":true}"
else
    note_fail "the body is: $body"
fi
if printf '%s' "$reply" | grep -q "receiver"; then
    note_fail "the reply names the mailbox"
else
    ok "the reply does not name the mailbox"
fi

echo ""
echo "the router validator's probe"
# validate-router-settings.sh decides "open" from whether curl gets any
# HTTP answer at all; the same call here.
if curl -s -o /dev/null --max-time 3 -w '%{http_code}' "http://127.0.0.1:$PORT/" | grep -q '^200$'; then
    ok "still answered"
else
    note_fail "no answer to the probe"
fi

stop_receiver
finish
