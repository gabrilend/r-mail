#!/bin/sh
# test-website-browse.sh — check that a public website can be read page by page, each page kept once fetched (#715c)
#
# Throwaway mailboxes in RAM: "owner", whose config says
# `website_access = public`, runs as a daemon; "reader" runs
# `run-rmail.sh <config> --website=127.0.0.1:<port> --yes --browse=<port>`,
# which serves the site to this computer's own browser at 127.0.0.1 and
# fetches each file from the owner the first time it is asked for.  curl
# plays the browser.  "whole" fetches the whole site first (#715b), then
# browses it.
#
# Cases:
#   pages      the front page, a folder's page (after its slash is added),
#              a file of three pieces, a link inside the site: each byte
#              for byte, each kept under websites/owner-at-127.0.0.1-<port>/
#   info       an information page, as #715a writes them, made when first
#              asked for, with the file's checksum
#   kept       a page opened twice is fetched once; with the owner's
#              computer off, opened pages still open and others do not
#   refused    on the reader's side: .., an encoded .., an encoded slash
#              or backslash, //, a dotfile, a NUL, another Host; on the
#              owner's side: the same paths sent straight to it, a link
#              that leads out of the site, a from past the end
#   changed    a newer version of the site: the kept copy goes to RAM and
#              the new page arrives
#   whole      after a whole fetch, browsing it asks the owner for nothing
#   guard      the owner's daily guard counts pages too
#   private    with website_access unset, /website/page is not answered
#
# Usage:
#   scripts/test-website-browse.sh          # use the enclosing checkout
#   scripts/test-website-browse.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"
WORK="/tmp/rmail/tests/website-browse"
PORT=59601
BROWSE=59603
RAM_OLD="/tmp/rmail-progress/old-websites"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

# {{{ helpers
make_mailbox() {
    mkdir -p "$WORK/$1/inbox" "$WORK/$1/outbox" "$WORK/$1/.state" "$WORK/$1/attachments"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n%s\n' \
        "$1" "$2" "$WORK/$1/pending" "$3" > "$WORK/$1/config"
    : > "$WORK/$1/contacts"
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
start_owner() {
    started=$(grep -c "listening on :$PORT" "$WORK/owner.log" 2>/dev/null)
    "$LAUNCHER" "$WORK/owner/config" >> "$WORK/owner.log" 2>&1 &
    OWNER_PID=$!
    wait_until 10 '[ "$(grep -c "listening on :$PORT" "$WORK/owner.log")" -gt "${started:-0}" ]'
}
stop_owner() { kill "$OWNER_PID" 2>/dev/null; wait "$OWNER_PID" 2>/dev/null; }
# browse <mailbox> — the reader's server, in the background
browse() {
    "$LAUNCHER" "$WORK/$1/config" "--website=127.0.0.1:$PORT" --yes "--browse=$BROWSE" \
        > "$WORK/$1.out" 2> "$WORK/$1.log" < /dev/null &
    BROWSE_PID=$!
    wait_until 10 "grep -q '^Open http://127.0.0.1:$BROWSE/' '$WORK/$1.out'"
}
stop_browse() { kill "$BROWSE_PID" 2>/dev/null; wait "$BROWSE_PID" 2>/dev/null; }
# get <path> [file] — the status code; the body in [file]
get() { curl -s --path-as-is -o "${2:-/dev/null}" -w '%{http_code}' "http://127.0.0.1:$BROWSE$1"; }
fetched() { grep -c ": .* fetched (" "$WORK/$1.log" 2>/dev/null; }
# owner_ask <case lines...> — POST /website/page straight to the owner;
# each argument is "<path>\t<from>", each answer's status on its own line
owner_ask() {
    "$LUA" - "$DIR" "$1" "$2" <<'LUA'
package.path = arg[1] .. "/libs/?.lua;" .. package.path
package.cpath = arg[1] .. "/libs/?.so;" .. package.cpath
local socket, json, c = require("socket"), require("dkjson"), require("rmail_crypto")
local port = tonumber(arg[2])
local function hex(s) return (s:gsub(".", function(x) return string.format("%02x", x:byte()) end)) end
local priv = c.random_bytes(32)
local mine = hex(c.x25519_public(priv))
for line in io.lines(arg[3]) do
    local path, from = line:match("^(.-)\t(%d+)$")
    local body = json.encode({key = mine, path = path, from = tonumber(from)})
    local s = socket.tcp(); s:settimeout(10); assert(s:connect("127.0.0.1", port))
    s:send("POST /website/page HTTP/1.1\r\nContent-Length: " .. #body .. "\r\n\r\n" .. body)
    local status = (s:receive("*l") or ""):match(" (%d%d%d)")
    s:close()
    print(status or "none")
end
LUA
}
# }}}

echo ""
echo "rmail website page-by-page test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ ! -x "$LUA" ]; then note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"; exit 1; fi
command -v curl > /dev/null || { note_fail "curl is needed to play the browser"; exit 1; }
rm -rf "$WORK"
mkdir -p "$WORK"

make_mailbox owner $PORT "website = site
website_access = public"
make_mailbox reader 59602
make_mailbox whole 59604
SITE="$WORK/owner/site"
mkdir -p "$SITE/about"
printf '<h1>owner</h1>\n<a href="about/">about</a> <a href="big.bin.info.html">a file</a>\n' > "$SITE/index.html"
printf 'body { color: teal; }\n' > "$SITE/style.css"
printf '<h1>about</h1>\n' > "$SITE/about/index.html"
head -c 2500000 /dev/urandom > "$SITE/big.bin"
printf 'not published\n' > "$SITE/.secret"
printf 'outside the website\n' > "$WORK/owner/outside.txt"
ln -s ../outside.txt "$SITE/leak.txt"
ln -s .. "$SITE/up"
ln -s index.html "$SITE/alias.html"
HERE="$WORK/reader/attachments/websites/owner-at-127.0.0.1-$PORT"
RAM_TAG="$(printf '%s' "$WORK/reader" | sed 's|^/||; s|/|-|g')-owner-at-127.0.0.1-$PORT-"
rm -rf "$RAM_OLD/$RAM_TAG"*
start_owner

# ---------------------------------------------------------------------------
echo ""
echo "pages, read one at a time"
browse reader
if grep -q "^Page by page: each page you open" "$WORK/reader.out" && grep -q "^Its key's words: " "$WORK/reader.out" \
   && grep -q "Said the other way round" "$WORK/reader.out"; then
    ok "it showed the words, and the cost both ways round"
else
    note_fail "what it showed: $(cat "$WORK/reader.out")"
fi
if [ "$(get / "$WORK/got-index")" = 200 ] && cmp -s "$WORK/got-index" "$SITE/index.html" \
   && cmp -s "$HERE/index.html" "$SITE/index.html"; then
    ok "the front page, byte for byte, and kept at websites/owner-at-127.0.0.1-$PORT/"
else
    note_fail "the front page: $(cat "$WORK/got-index" 2>&1)"
fi
if [ "$(get /about)" = 301 ] && [ "$(get /about/ "$WORK/got-about")" = 200 ] \
   && cmp -s "$WORK/got-about" "$SITE/about/index.html"; then
    ok "a folder: sent to its slash, then its index.html"
else
    note_fail "the about folder: $(cat "$WORK/got-about" 2>&1)"
fi
if [ "$(get /big.bin "$WORK/got-big")" = 200 ] && cmp -s "$WORK/got-big" "$SITE/big.bin"; then
    ok "a file of three pieces, byte for byte"
else
    note_fail "big.bin: $(ls -l "$WORK/got-big" 2>&1)"
fi
if [ "$(get /alias.html "$WORK/got-alias")" = 200 ] && cmp -s "$WORK/got-alias" "$SITE/index.html"; then
    ok "a link that stays inside the site is followed"
else
    note_fail "alias.html: $(cat "$WORK/got-alias" 2>&1)"
fi
SUM=$(sha256sum "$SITE/big.bin" | cut -d' ' -f1)
if [ "$(get /big.bin.info.html "$WORK/got-info")" = 200 ] && grep -q "$SUM" "$WORK/got-info" \
   && [ -f "$HERE/big.bin.info.html" ]; then
    ok "an information page, made when first asked for, with the file's checksum"
else
    note_fail "the information page: $(head -c 300 "$WORK/got-info" 2>&1)"
fi

# ---------------------------------------------------------------------------
echo ""
echo "kept once fetched"
before=$(fetched reader)
get / > /dev/null; get /about/ > /dev/null; get /big.bin > /dev/null
if [ "$(fetched reader)" = "$before" ] && [ "$before" -eq 4 ]; then
    ok "opened again, nothing is fetched again ($before fetches in all)"
else
    note_fail "fetches: $before, then $(fetched reader)"
fi
stop_owner
if [ "$(get / "$WORK/got-off")" = 200 ] && cmp -s "$WORK/got-off" "$SITE/index.html" \
   && [ "$(get /big.bin "$WORK/got-off-big")" = 200 ] && cmp -s "$WORK/got-off-big" "$SITE/big.bin"; then
    ok "with the owner's computer off, opened pages still open"
else
    note_fail "with the owner off: $(cat "$WORK/got-off" 2>&1)"
fi
if [ "$(get /style.css "$WORK/got-never")" = 502 ] && grep -q "did not give this page" "$WORK/got-never"; then
    ok "and a page never opened says the owner's computer did not give it"
else
    note_fail "a page never opened, owner off: $(cat "$WORK/got-never" 2>&1)"
fi
start_owner

# ---------------------------------------------------------------------------
echo ""
echo "paths refused by the reader"
mkdir -p "$WORK/reader/marker"
for case in "/../config|.." "/about/../../config|.. inside" "/%2e%2e/config|an encoded .." \
            "/about%2Findex.html|an encoded slash" "/about%5cindex.html|an encoded backslash" \
            "//etc/passwd|//" "/.secret|a dotfile" "/x%00y|a NUL" "/.rmail-website.json|the copy's own record"; do
    path=${case%%|*}; what=${case#*|}
    code=$(get "$path" "$WORK/got-refused")
    if [ "$code" = 400 ]; then ok "$what: 400"; else note_fail "$what ($path): $code"; fi
done
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Host: elsewhere.example:$BROWSE" "http://127.0.0.1:$BROWSE/")
if [ "$code" = 403 ]; then ok "another Host (a renamed page elsewhere): 403"; else note_fail "another Host: $code"; fi
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://127.0.0.1:$BROWSE/")
if [ "$code" = 405 ]; then ok "a POST: 405"; else note_fail "a POST: $code"; fi
if [ -z "$(find "$HERE" -name 'config' -o -name 'passwd' -o -name '.secret' | head -1)" ] \
   && ! grep -q "secret" "$WORK/owner.log"; then
    ok "nothing refused was kept, or asked of the owner"
else
    note_fail "something refused was kept: $(find "$HERE")"
fi

# ---------------------------------------------------------------------------
echo ""
echo "paths refused by the owner"
printf '../config\t0\n/etc/passwd\t0\nabout\\index.html\t0\nabout%%2Findex.html\t0\n.secret\t0\nabout//index.html\t0\nleak.txt\t0\nup/config\t0\nup/outside.txt\t0\nindex.html\t999999\nindex.html\t0\nnone.html\t0\n' \
    > "$WORK/owner-paths"
owner_ask "$PORT" "$WORK/owner-paths" > "$WORK/owner-answers" 2>&1
expect="400 400 400 400 400 400 403 403 403 400 200 404"
got=$(tr '\n' ' ' < "$WORK/owner-answers" | sed 's/ $//')
if [ "$got" = "$expect" ]; then
    ok "..; absolute; backslash; %; dotfile; //: 400.  Links out of the site: 403.  Past the end: 400"
    ok "and a page that is there is 200, one that is not 404"
else
    note_fail "the owner answered: $got (wanted $expect)"
fi
if grep -q "refused: a link that leads outside the website" "$WORK/owner.log"; then
    ok "the owner logs a refused path"
else
    note_fail "no refusal in the owner's log"
fi

# ---------------------------------------------------------------------------
echo ""
echo "a newer version of the site"
sleep 1.1
printf '<h1>owner, again</h1>\n' > "$SITE/index.html"
sleep 5.5
before=$(fetched reader)
if [ "$(get /style.css "$WORK/got-css")" = 200 ] && cmp -s "$WORK/got-css" "$SITE/style.css" \
   && ls -d "$RAM_OLD/$RAM_TAG"* > /dev/null 2>&1 && [ ! -e "$HERE/big.bin" ] \
   && grep -q "changed since it was last read" "$WORK/reader.log"; then
    ok "the kept copy went to RAM, and the new version's page arrived"
else
    note_fail "after the change: $(ls "$HERE" 2>&1); RAM: $(ls "$RAM_OLD" 2>&1)"
fi
if [ "$(get / "$WORK/got-new")" = 200 ] && cmp -s "$WORK/got-new" "$SITE/index.html"; then
    ok "and the front page is the new one"
else
    note_fail "the front page after the change: $(cat "$WORK/got-new" 2>&1)"
fi
stop_browse

# ---------------------------------------------------------------------------
echo ""
echo "browsing a whole copy"
"$LAUNCHER" "$WORK/whole/config" "--website=127.0.0.1:$PORT" --yes > "$WORK/whole-fetch.out" 2>&1 < /dev/null
WHOLE="$WORK/whole/attachments/websites/owner-at-127.0.0.1-$PORT"
if grep -q "To read it page by page instead, add --browse" "$WORK/whole-fetch.out" \
   && grep -q '"whole":true' "$WHOLE/.rmail-website.json" 2>/dev/null; then
    ok "a whole fetch names --browse, and records its version"
else
    note_fail "the whole fetch: $(cat "$WORK/whole-fetch.out")"
fi
browse whole
if [ "$(get /big.bin "$WORK/got-whole")" = 200 ] && cmp -s "$WORK/got-whole" "$SITE/big.bin" \
   && [ "$(get /about/ > /dev/null; fetched whole)" = 0 ]; then
    ok "browsing it then asks the owner for nothing"
else
    note_fail "browsing the whole copy: $(fetched whole) fetches"
fi
stop_browse

# ---------------------------------------------------------------------------
echo ""
echo "the owner's daily guard"
stop_owner; start_owner
: > "$WORK/guard-paths"
for i in 1 2 3 4 5 6 7 8 9; do printf 'big.bin\t0\n' >> "$WORK/guard-paths"; done
owner_ask "$PORT" "$WORK/guard-paths" > "$WORK/guard-answers" 2>&1
# the site is a little over 2.5 MB, so the day's allowance is a little
# over 6 MB: five pieces of 1 MiB fit, the sixth does not
if [ "$(sed -n 5p "$WORK/guard-answers")" = 200 ] && [ "$(sed -n 6p "$WORK/guard-answers")" = 429 ]; then
    ok "pages count against twice the site a day: the sixth 1 MiB is 429"
else
    note_fail "the guard: $(tr '\n' ' ' < "$WORK/guard-answers")"
fi
stop_owner

# ---------------------------------------------------------------------------
echo ""
echo "a private website"
make_mailbox private 59605 "website = site"
mkdir -p "$WORK/private/site"; printf '<h1>private</h1>\n' > "$WORK/private/site/index.html"
"$LAUNCHER" "$WORK/private/config" > "$WORK/private.log" 2>&1 &
PRIVATE_PID=$!
wait_until 10 'grep -q "listening on :59605" "$WORK/private.log"'
answer=$(curl -s -X POST --data "{\"key\":\"$(printf '%064d' 7)\",\"path\":\"index.html\"}" \
    "http://127.0.0.1:59605/website/page")
if printf '%s' "$answer" | grep -q "exactly one rmail frame" && ! grep -q "page by page\|asked for" "$WORK/private.log"; then
    ok "/website/page is read as a frame, as before, and not answered as a page"
else
    note_fail "the private mailbox answered: $answer"
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
