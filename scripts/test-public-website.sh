#!/bin/sh
# test-public-website.sh — check that anyone may fetch a public website, with its key remembered and its words shown (#715b)
#
# Two throwaway mailboxes in RAM: "owner", whose config says
# `website_access = public`, runs as a daemon; "asker" is not its
# contact, and fetches the site with `run-rmail.sh <config>
# --website=127.0.0.1:<port> --yes`, which runs once and exits.  A third,
# "newcomer", has never visited.  A small Lua program, "between", plays
# someone in the middle: it answers askers with a key of its own and
# fetches from the owner with another.
#
# Cases:
#   key        the owner makes its website key on first start (64 hex
#              digits, readable by the owner only) and logs its six words
#   fetched    the asker gets the site, byte for byte, filed at
#              websites/owner-at-127.0.0.1-<port>/ with information pages;
#              it printed the owner's words and remembered the key
#   again      a second fetch says the key is the same, and the first copy
#              goes to RAM, as a contact's does (#715a)
#   guard      a third fetch the same day is refused: twice the site per
#              address a day
#   between    someone in the middle: the asker who remembers the key
#              refuses, loudly; a newcomer is fooled (nothing can tell on
#              a first visit) but is shown words that differ from the
#              owner's; one on the path with no key, who answers one
#              piece with another, is caught
#   changed    the owner's key is replaced: the asker refuses the site
#   asked      no terminal and no --yes: nothing fetched
#   wrong      a GET, a malformed key, an all-zero key, a piece of the
#              wrong version, a piece out of range: each refused
#   private    with website_access unset, /website is answered as before
#              (the health answer, and the frame rules), and nothing is
#              fetched
#
# Usage:
#   scripts/test-public-website.sh          # use the enclosing checkout
#   scripts/test-public-website.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/public-website"
PORT=59591
BETWEEN=59592
SWAPPER=59596
RAM_OLD="/tmp/rmail-progress/old-websites"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# {{{ helpers
# make_mailbox <name> <port> [extra config line]
make_mailbox() {
    mkdir -p "$WORK/$1/inbox" "$WORK/$1/outbox" "$WORK/$1/.state" "$WORK/$1/attachments"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n%s\n' \
        "$1" "$2" "$WORK/$1/pending" "$3" > "$WORK/$1/config"
    : > "$WORK/$1/contacts"
}
start_owner() {
    started=$(grep -c "listening on :$PORT" "$WORK/owner.log" 2>/dev/null)
    "$LAUNCHER" "$WORK/owner/config" >> "$WORK/owner.log" 2>&1 &
    OWNER_PID=$!
    wait_until 10 '[ "$(grep -c "listening on :$PORT" "$WORK/owner.log")" -gt "${started:-0}" ]'
}
stop_owner() { kill "$OWNER_PID" 2>/dev/null; wait "$OWNER_PID" 2>/dev/null; }
# fetch <mailbox> [port] — the one-shot fetch, its output in $WORK/<mailbox>.out
fetch() {
    "$LAUNCHER" "$WORK/$1/config" "--website=127.0.0.1:${2:-$PORT}" --yes > "$WORK/$1.out" 2>&1 < /dev/null
}
wait_until() {
    waited=0
    while [ "$waited" -lt "$(($1 * 10))" ]; do
        eval "$2" && return 0
        sleep 0.1
        waited=$((waited + 1))
    done
    return 1
}
owner_words() { sed -n "s/.*its key's words, for askers to compare: //p" "$WORK/owner.log" | tail -1; }
shown_words() { sed -n "s/^Its key's words: //p" "$WORK/$1.out"; }
same_files() {
    for rel in index.html style.css pictures/me.jpg files/video.mp4; do
        cmp -s "$1/$rel" "$WORK/owner/site/$rel" || { info "differs: $rel"; return 1; }
    done
}
# }}}

echo ""
echo "rmail public-website test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LUA" ]; then note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"; exit 1; fi
rm -rf "$WORK"
mkdir -p "$WORK"

make_mailbox owner $PORT "website = site
website_access = public"
make_mailbox asker 59593
make_mailbox newcomer 59594
SITE="$WORK/owner/site"
mkdir -p "$SITE/pictures" "$SITE/files"
printf '<h1>owner</h1>\n<a href="files/video.mp4.info.html">a video</a>\n' > "$SITE/index.html"
printf 'body { color: teal; }\n' > "$SITE/style.css"
head -c 30000 /dev/urandom > "$SITE/pictures/me.jpg"
head -c 2500000 /dev/urandom > "$SITE/files/video.mp4"
HERE="$WORK/asker/attachments/websites/owner-at-127.0.0.1-$PORT"
RAM_TAG="$(printf '%s' "$WORK/asker" | sed 's|^/||; s|/|-|g')-owner-at-127.0.0.1-$PORT-"
rm -rf "$RAM_OLD/$RAM_TAG"*

# ---------------------------------------------------------------------------
echo ""
echo "the owner's website key"
start_owner
KEYFILE="$WORK/owner/.state/website-key"
if grep -qE '^[0-9a-f]{64}$' "$KEYFILE" 2>/dev/null && [ "$(stat -c %a "$KEYFILE")" = 600 ]; then
    ok "made on first start: 64 hex digits, readable by the owner only"
else
    note_fail "the key file: $(ls -l "$KEYFILE" 2>&1)"
fi
WORDS=$(owner_words)
if [ "$(printf '%s' "$WORDS" | wc -w)" -eq 6 ]; then
    ok "its six words are in the log ($WORDS)"
else
    note_fail "no six words in the log: $WORDS"
fi

# ---------------------------------------------------------------------------
echo ""
echo "an asker who is not a contact fetches it"
if fetch asker && grep -q "^Saved at $HERE\$" "$WORK/asker.out"; then
    ok "fetched and saved at websites/owner-at-127.0.0.1-$PORT/"
else
    note_fail "the fetch: $(cat "$WORK/asker.out")"
fi
if same_files "$HERE"; then ok "every file byte for byte"; else note_fail "the files differ"; fi
if [ -f "$HERE/files/video.mp4.info.html" ] && [ ! -f "$HERE/index.html.info.html" ]; then
    ok "with the information page beside the video, none beside the page"
else
    note_fail "information pages: $(ls "$HERE/files")"
fi
if [ "$(shown_words asker)" = "$WORDS" ] && grep -q "^First visit" "$WORK/asker.out"; then
    ok "it showed the owner's words, and said this key is remembered now"
else
    note_fail "shown: $(shown_words asker); owner's: $WORDS"
fi
if grep -q "It is .* zipped" "$WORK/asker.out" && grep -q "Said the other way round" "$WORK/asker.out"; then
    ok "and the size, both ways round"
else
    note_fail "no size both ways: $(cat "$WORK/asker.out")"
fi
OWNER_PUB=$("$LUA" - "$DIR" "$(head -c 64 "$KEYFILE")" <<'LUA'
package.cpath = arg[1] .. "/libs/?.so;" .. package.cpath
local c = require("rmail_crypto")
local priv = arg[2]:gsub("..", function(x) return string.char(tonumber(x, 16)) end)
io.write((c.x25519_public(priv):gsub(".", function(x) return string.format("%02x", x:byte()) end)))
LUA
)
if [ ${#OWNER_PUB} -eq 64 ] && grep -q "\"127.0.0.1:$PORT\"" "$WORK/asker/.state/website-keys.json" 2>/dev/null \
   && grep -q "$OWNER_PUB" "$WORK/asker/.state/website-keys.json"; then
    ok "the owner's public key is remembered for 127.0.0.1:$PORT"
else
    note_fail "remembered: $(cat "$WORK/asker/.state/website-keys.json" 2>&1)"
fi
if grep -q "website: asked for by a stranger at 127.0.0.1" "$WORK/owner.log"; then
    ok "the owner's log names the ask"
else
    note_fail "no line for the ask in the owner's log"
fi

# ---------------------------------------------------------------------------
echo ""
echo "fetched again"
if fetch asker && grep -q "^The same key as on" "$WORK/asker.out" && same_files "$HERE"; then
    ok "the same key, and the site again"
else
    note_fail "the second fetch: $(cat "$WORK/asker.out")"
fi
if ls -d "$RAM_OLD/$RAM_TAG"* > /dev/null 2>&1 && [ -f "$(ls -d "$RAM_OLD/$RAM_TAG"* | head -1)/index.html" ]; then
    ok "the first copy went to RAM, whole"
else
    note_fail "no earlier copy in $RAM_OLD"
fi

echo ""
echo "the guard: twice the site a day per address"
if fetch asker; then
    note_fail "a third fetch the same day was served"
elif grep -q "twice the website today" "$WORK/asker.out" && grep -q "nothing more until tomorrow" "$WORK/owner.log"; then
    ok "a third fetch is refused, and the owner's log says so once"
else
    note_fail "the third fetch: $(cat "$WORK/asker.out")"
fi
stop_owner
start_owner

# ---------------------------------------------------------------------------
echo ""
echo "someone in the middle"
"$LUA" "$DIR/scripts/lib/website-between.lua" "$DIR" "$BETWEEN" "$PORT" > "$WORK/between.out" 2>&1 &
BETWEEN_PID=$!
sleep 1
# the asker remembers keys per address: as if the owner's address now led
# through the one in the middle, its entry is copied to that address
"$LUA" - "$DIR" "$WORK/asker/.state/website-keys.json" "127.0.0.1:$PORT" "127.0.0.1:$BETWEEN" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
local json = require("dkjson")
local f = io.open(arg[2]); local t = json.decode(f:read("*a")); f:close()
t[arg[4]] = t[arg[3]]
f = io.open(arg[2], "w"); f:write(json.encode(t, {indent = true})); f:close()
LUA
if fetch asker $BETWEEN; then
    note_fail "the asker took a different key for a remembered address"
elif grep -q "^REFUSED: the mailbox at 127.0.0.1:$BETWEEN answers with a different key" "$WORK/asker.out" \
     && grep -q "its words then: $WORDS" "$WORK/asker.out"; then
    ok "the asker who remembers the key refuses, naming the words then and now"
else
    note_fail "the asker's answer: $(cat "$WORK/asker.out")"
fi
NEWHERE="$WORK/newcomer/attachments/websites/owner-at-127.0.0.1-$BETWEEN"
if fetch newcomer $BETWEEN && same_files "$NEWHERE"; then
    if [ "$(shown_words newcomer)" != "$WORDS" ] && [ -n "$(shown_words newcomer)" ]; then
        ok "a newcomer is given the site through it, but shown other words ($(shown_words newcomer))"
    else
        note_fail "the newcomer was shown the owner's own words through someone in the middle"
    fi
else
    note_fail "the in-between program did not pass the site on: $(cat "$WORK/newcomer.out"; cat "$WORK/between.out")"
fi
kill "$BETWEEN_PID" 2>/dev/null; wait "$BETWEEN_PID" 2>/dev/null
"$LUA" "$DIR/scripts/lib/website-between.lua" "$DIR" "$SWAPPER" "$PORT" swap > "$WORK/swap.out" 2>&1 &
BETWEEN_PID=$!
sleep 1
if fetch newcomer $SWAPPER; then
    note_fail "a piece answered in another's place was taken"
elif grep -q "^piece 1 did not open as that piece" "$WORK/newcomer.out" \
     && [ ! -d "$WORK/newcomer/attachments/websites/owner-at-127.0.0.1-$SWAPPER" ]; then
    ok "one on the path with no key, answering one piece with another, is caught, and nothing is kept"
else
    note_fail "with a piece swapped: $(cat "$WORK/newcomer.out")"
fi
kill "$BETWEEN_PID" 2>/dev/null; wait "$BETWEEN_PID" 2>/dev/null

# ---------------------------------------------------------------------------
echo ""
echo "the owner's key replaced"
stop_owner
mv "$KEYFILE" "$KEYFILE.old"
start_owner
rm -rf "$HERE/files"
if fetch asker; then
    note_fail "the asker took the site under a new key"
elif grep -q "^REFUSED" "$WORK/asker.out" && [ ! -d "$HERE/files" ]; then
    ok "the asker refuses it, and keeps nothing"
else
    note_fail "the asker's answer: $(cat "$WORK/asker.out")"
fi
stop_owner
mv "$KEYFILE.old" "$KEYFILE"
printf 'not a key\n' > "$WORK/owner/.state/website-key"
"$LAUNCHER" "$WORK/owner/config" > "$WORK/bad-key.log" 2>&1 &
BAD_PID=$!
if wait_until 10 '! kill -0 $BAD_PID 2>/dev/null' && grep -q "is not a website key" "$WORK/bad-key.log"; then
    ok "a key file that is not a key stops the daemon, rather than making a new key"
else
    kill "$BAD_PID" 2>/dev/null
    note_fail "with a broken key file: $(cat "$WORK/bad-key.log")"
fi
wait "$BAD_PID" 2>/dev/null
mv "$KEYFILE" "$KEYFILE.bad"
start_owner

# ---------------------------------------------------------------------------
echo ""
echo "asked first"
"$LAUNCHER" "$WORK/newcomer/config" "--website=127.0.0.1:$PORT" > "$WORK/asked.out" 2>&1 < /dev/null
status=$?
if [ "$status" -ne 0 ] && grep -q "No terminal to answer on" "$WORK/asked.out" \
   && [ ! -d "$WORK/newcomer/attachments/websites/owner-at-127.0.0.1-$PORT" ]; then
    ok "with no terminal and no --yes, nothing is fetched"
else
    note_fail "without --yes: $(cat "$WORK/asked.out")"
fi

# ---------------------------------------------------------------------------
echo ""
echo "wrong requests"
"$LUA" - "$DIR" "$PORT" "$SITE" > "$WORK/wrong.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
package.cpath = arg[1] .. "/libs/?.so;" .. package.cpath
local socket, json, c = require("socket"), require("dkjson"), require("rmail_crypto")
local port, site = tonumber(arg[2]), arg[3]
local function hex(s) return (s:gsub(".", function(x) return string.format("%02x", x:byte()) end)) end
local function ask(method, path, body)
    local s = socket.tcp(); s:settimeout(10); assert(s:connect("127.0.0.1", port))
    s:send(method .. " " .. path .. " HTTP/1.1\r\nContent-Length: " .. #body .. "\r\n\r\n" .. body)
    local line = s:receive("*l") or ""
    local len = 0
    while true do
        local h = s:receive("*l"); if not h or h == "" then break end
        len = tonumber(h:lower():match("content%-length:%s*(%d+)")) or len
    end
    local data = len > 0 and s:receive(len) or ""
    s:close()
    return tonumber(line:match(" (%d%d%d)")), data
end
local function check(ok, words, detail) print((ok and "ok " or "-- ") .. words .. (ok and "" or (": " .. tostring(detail)))) end
local st = ask("GET", "/website", "")
check(st == 405, "a GET of /website is 405", st)
st = ask("POST", "/website", '{"key":"not hex"}')
check(st == 400, "a key that is not hex is 400", st)
st = ask("POST", "/website", json.encode({key = string.rep("00", 32)}))
check(st == 400, "an all-zero key is 400", st)
st = ask("GET", "/anything-else", "")
check(st == 200, "any other GET is still the health answer", st)
local priv = c.random_bytes(32)
local mine = c.x25519_public(priv)
local st, data = ask("POST", "/website", json.encode({key = hex(mine)}))
local key = c.sha256("rmail public website\0" .. c.x25519(priv, data:sub(1, 32)) .. mine .. data:sub(1, 32))
local offer = json.decode(c.aes_gcm_decrypt(key, data:sub(33, 44), data:sub(45)) or "null")
check(type(offer) == "table" and offer.pieces == 3, "the offer opens with the agreed key: 3 pieces", offer and offer.pieces)
st = ask("POST", "/website/piece", json.encode({key = hex(mine), n = 3, fingerprint = offer.fingerprint}))
check(st == 400, "a piece past the last is 400", st)
st = ask("POST", "/website/piece", json.encode({key = hex(mine), n = 0.5, fingerprint = offer.fingerprint}))
check(st == 400, "a piece that is not a whole number is 400", st)
st, data = ask("POST", "/website/piece", json.encode({key = hex(mine), n = 0, fingerprint = offer.fingerprint}))
local plain = st == 200 and c.aes_gcm_decrypt(key, data:sub(1, 12), data:sub(13))
check(plain and plain:sub(1, 22) == "rmail website piece 0 ", "piece 0 opens, behind the line naming it", st)
local other = c.sha256("someone else's key")
check(c.aes_gcm_decrypt(other, data:sub(1, 12), data:sub(13)) == nil, "and opens with no other key")
local f = io.open(site .. "/style.css", "a"); f:write("/* changed */\n"); f:close()
socket.sleep(6)
st = ask("POST", "/website/piece", json.encode({key = hex(mine), n = 0, fingerprint = offer.fingerprint}))
check(st == 409, "once the site changes, a piece of the old version is 409", st)
LUA
while read -r line; do
    case "$line" in
        "ok "*) ok "${line#ok }" ;;
        "-- "*) note_fail "${line#-- }" ;;
        *) info "$line" ;;
    esac
done < "$WORK/wrong.out"
stop_owner

# ---------------------------------------------------------------------------
echo ""
echo "a private website"
make_mailbox private 59595 "website = site"
mkdir -p "$WORK/private/site"; printf '<h1>private</h1>\n' > "$WORK/private/site/index.html"
"$LAUNCHER" "$WORK/private/config" > "$WORK/private.log" 2>&1 &
PRIVATE_PID=$!
wait_until 10 'grep -q "listening on :59595" "$WORK/private.log"'
"$LAUNCHER" "$WORK/newcomer/config" "--website=127.0.0.1:59595" --yes > "$WORK/private.out" 2>&1 < /dev/null
status=$?
if [ "$status" -ne 0 ] && grep -q "did not offer a website: the body must be exactly one rmail frame" "$WORK/private.out" \
   && [ ! -e "$WORK/private/.state/website-key" ]; then
    ok "nothing offered: /website is read as a frame, as before, and no key is made"
else
    note_fail "the private mailbox: $(cat "$WORK/private.out")"
fi
if [ "$(printf 'GET /website HTTP/1.1\r\n\r\n' | nc -q 2 127.0.0.1 59595 | tail -1)" = '{"ok":true}' ]; then
    ok "a GET of /website is the health answer, as before"
else
    note_fail "a GET of /website on a private mailbox was not the health answer"
fi
kill "$PRIVATE_PID" 2>/dev/null; wait "$PRIVATE_PID" 2>/dev/null

rm -rf "$RAM_OLD/$RAM_TAG"*
echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
info "logs: $WORK/*.log, $WORK/*.out"
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
