#!/bin/sh
# test-thin-client-viewer.sh — check the terminal viewer in clients/shared/ (#711)
#
# The viewer is driven two ways.  Most cases hand it a pretend terminal
# (a fixed size, keys from a list, writes kept) and read what its screen
# holds; that needs no terminal and checks exactly what was drawn.  The
# last case runs it for real inside `script`, which gives it a terminal,
# and types keys at it.
#
# Cases:
#   wrap        a writer's newline always breaks; a wrap point is worked
#               out from the width; a word too long is broken inside;
#               wide characters count two cells
#   keys        arrow keys in both spellings, Escape alone, a UTF-8
#               character, Enter and Tab come out as names
#   renderer    a second flush with nothing changed writes nothing; a
#               changed cell writes only that run; update_tag restyles
#               every tagged cell; a wide character is not halved at the
#               edge
#   list        newest first, hidden files left out, folders marked, the
#               selection drawn by its tag; counts in the status bar
#   read        a message opens; its header lines are styled; its body
#               wraps to the width and reflows on a resize; a binary file
#               is described, not dumped
#   navigate    Tab to the outbox, into a folder and back up, q at the
#               top quits, and mail that arrives shows at the next key
#   terminal    run for real: it draws, opens a message, quits on q and
#               gives the terminal back as it found it
#
# Usage:
#   scripts/test-thin-client-viewer.sh          # use the enclosing checkout
#   scripts/test-thin-client-viewer.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/thin-client-viewer"
SHARED="$DIR/clients/shared"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

LUA=""
for l in "$DIR/deps/lua/bin/lua" lua5.4 luajit lua5.3 lua5.1 lua; do
    if command -v "$l" >/dev/null 2>&1 || [ -x "$l" ]; then LUA="$l"; break; fi
done

echo ""
echo "rmail thin-client viewer test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ -z "$LUA" ]; then
    note_fail "no Lua interpreter"
    exit 1
fi

rm -rf "$WORK"
BOX="$WORK/mailbox-1"
mkdir -p "$BOX/inbox/alice" "$BOX/outbox"
printf 'old\n' > "$BOX/inbox/alice/older-note"
touch -d '2026-01-01 00:00' "$BOX/inbox/alice/older-note" "$BOX/inbox/alice"
printf 'from: bob\nsubject: lunch\n\nAre you free for lunch on Thursday at the usual place by the river?\nBring the map.\n' \
    > "$BOX/inbox/bob-lunch"
touch -d '2026-01-02 00:00' "$BOX/inbox/bob-lunch"
printf '\0\1\2binary' > "$BOX/inbox/photo.jpg"
touch -d '2026-01-03 00:00' "$BOX/inbox/photo.jpg"
printf 'bookkeeping\n' > "$BOX/inbox/.hidden-state"
printf 'to: carol\n\nhello\n' > "$BOX/outbox/to-carol"
printf '{}\n' > "$BOX/sync-state.json"

cat > "$WORK/checks.lua" <<'LUA'
local shared, box = arg[1], arg[2]
package.path = shared .. "/?.lua;" .. package.path
local wrap = require("wrap")
local term = require("term")
local Renderer = require("renderer")
local Viewer = require("viewer")

local function say(case, good, what, got)
    print(case .. "\t" .. (good and "ok" or "--") .. "\t" .. what
        .. (good and "" or ("\t" .. tostring(got):gsub("\27", "^["):gsub("\n", "|"))))
end
local function texts(lines)
    local t = {}
    for _, l in ipairs(lines) do t[#t + 1] = l.text end
    return table.concat(t, "|")
end

-- wrap
local w = wrap.wrap("the quick brown fox jumps\nover", 10)
say("wrap", texts(w) == "the quick|brown fox|jumps|over" and not w[2].ends_paragraph
    and w[3].ends_paragraph, "a newline breaks; wrap points come from the width", texts(w))
say("wrap", texts(wrap.wrap("abcdefghij", 4)) == "abcd|efgh|ij", "a word too long is broken inside it",
    texts(wrap.wrap("abcdefghij", 4)))
say("wrap", texts(wrap.wrap("日本語の", 5)) == "日本|語の" and wrap.text_width("😀a") == 3,
    "wide characters take two cells", texts(wrap.wrap("日本語の", 5)))

-- keys
local function keys_of(bytes)
    local i, out = 1, {}
    local function rd() if i > #bytes then return nil end local b = bytes:sub(i, i); i = i + 1; return b end
    while i <= #bytes do out[#out + 1] = term.parse(rd) end
    return table.concat(out, " ")
end
local k = keys_of("\27[A\27OB\27[5~\r\tq\195\169")
say("keys", k == "up down pageup enter tab q é", "escape sequences, Enter, Tab and a UTF-8 character", k)
say("keys", keys_of("\27") == "escape", "Escape on its own", keys_of("\27"))

-- renderer
local r = Renderer.new(3, 10)
r:line(1, "hello", "")
local first = r:flush()
local second = r:flush()
say("renderer", first:find("hello", 1, true) and second == "", "nothing changed, nothing written", second)
r:put(1, 2, "a", "")
local third = r:flush()
say("renderer", third == "\27[1;2Ha", "one changed cell writes only that cell", third)
r:line(2, "abc", "", { selection = true })
local n = r:update_tag("selection", { ansi_on = "\27[7m" })
say("renderer", n == 10 and r.back[2][1].ansi_on == "\27[7m" and r.back[1][1].ansi_on == "",
    "update_tag restyles every tagged cell and no other", n)
r:line(3, "123456789日", "")
say("renderer", r:text():match("[^\n]*$") == "123456789", "a wide character is not halved at the edge",
    r:text():match("[^\n]*$"))
r:line(3, "日本", "")
say("renderer", r.back[3][2].char == "" and r.back[3][3].char == "本", "its second cell is a continuation",
    r.back[3][2].char)

-- a viewer with a pretend terminal: draw, then the screen as text
local function screen(v) v:draw(); return v.screen:text() end
local v = Viewer.new(box, 8, 30)
local s = screen(v)
local rows = {}
for line in (s .. "\n"):gmatch("(.-)\n") do rows[#rows + 1] = line end
say("list", rows[2] == "  photo.jpg" and rows[3] == "  bob-lunch" and rows[4] == "  alice/",
    "newest first, folders marked", s)
say("list", not s:find("hidden", 1, true), "hidden files are not listed", s)
local wide_status = Viewer.new(box, 8, 60)
local status = screen(wide_status):match("^[^\n]*")
say("list", status:find("mailbox-1   inbox 3  outbox 1   synced just now", 1, true) ~= nil,
    "the status bar names the mailbox, counts both folders, and says when it synced", status)
say("list", v.screen.back[2][3].ansi_on == "\27[7m" and v.screen.back[3][3].ansi_on == "",
    "the selection is drawn by its tag", v.screen.back[2][3].ansi_on)
v:handle("down")
screen(v)
say("list", v.screen.back[3][3].ansi_on == "\27[7m" and v.screen.back[2][3].ansi_on == "",
    "and moves with it", v.screen.back[3][3].ansi_on)

-- read
v:handle("enter")
s = screen(v)
rows = {}
for line in (s .. "\n"):gmatch("(.-)\n") do rows[#rows + 1] = line end
say("read", rows[2] == "from: bob" and rows[3] == "subject: lunch" and rows[4] == ""
    and rows[5] == "Are you free for lunch on",
    "a message opens, wrapped to the width", s)
say("read", v.screen.back[2][1].ansi_on == "\27[32m" and v.screen.back[5][1].ansi_on == "",
    "its header lines are styled and its body is not", v.screen.back[2][1].ansi_on)
local narrow = #v:read_lines()
v.screen:resize(8, 60)
screen(v)
local wide = #v:read_lines()
say("read", wide < narrow and v.body:find("Thursday at the usual", 1, true),
    "a resize reflows the text; the text itself is unchanged", narrow .. " then " .. wide)
v:handle("q")
v:handle("up")
v:handle("enter")
s = screen(v)
say("read", s:find("photo.jpg is not text: 9 bytes", 1, true) ~= nil, "a binary file is described, not dumped", s)
v:handle("q")

-- navigate
v:handle("end")
v:handle("enter")
s = screen(v)
say("navigate", s:find("older-note", 1, true) and s:find("left up", 1, true),
    "into a folder, with a way back up", s)
say("navigate", v:handle("q") == nil and #v.path == 0, "q in a folder goes up rather than quitting", #v.path)
v:handle("tab")
s = screen(v)
say("navigate", s:find("to-carol", 1, true) and not s:find("bob-lunch", 1, true), "Tab shows the outbox", s)
v:handle("tab")
screen(v)
local f = io.open(box .. "/inbox/zz-new-arrival", "w"); f:write("new\n"); f:close()
s = screen(v)
say("navigate", s:find("zz-new-arrival", 1, true) ~= nil and s:find("inbox 4", 1, true) ~= nil,
    "mail that arrives shows at the next frame", s)
os.remove(box .. "/inbox/zz-new-arrival")
say("navigate", v:handle("q") == "quit", "q at the top quits", "")

-- run() with a pretend terminal: the keys, in order, then the end
local fed = { "down", "enter", "q", "q" }
local writes = {}
local fake = {
    size = function() return 8, 30 end,
    read_key = function() return table.remove(fed, 1) end,
    write = function(s) writes[#writes + 1] = s end,
}
Viewer.new(box, 8, 30):run(fake)
local all = table.concat(writes)
say("navigate", #fed == 0 and #writes == 4 and all:find("Thursday", 1, true) ~= nil,
    "run() draws a frame per key and stops on q", #fed .. " keys left, " .. #writes .. " frames")
LUA

"$LUA" "$WORK/checks.lua" "$SHARED" "$BOX" > "$WORK/checks.out" 2>&1
last=""
while IFS='	' read -r case result what got; do
    if [ "$case" != "$last" ]; then echo ""; echo "$case"; last="$case"; fi
    if [ "$result" = "ok" ]; then ok "$what"; else note_fail "$what: $got"; fi
done < "$WORK/checks.out"
if ! grep -q "	" "$WORK/checks.out" || grep -qv "	" "$WORK/checks.out"; then
    note_fail "the checks did not run cleanly: $(grep -v "	" "$WORK/checks.out" | head -3 | tr '\n' ' ')"
fi

echo ""
echo "terminal"
if command -v script >/dev/null 2>&1; then
    # keys typed with pauses, so each is read as a key of its own
    ( sleep 1; printf '\033[B'; sleep 0.5; printf '\r'; sleep 0.5; printf 'q'; sleep 0.5; printf 'q'; sleep 1 ) \
        | script -qec "stty rows 10 cols 40; '$LUA' '$SHARED/rmail-view.lua' '$BOX'; echo \"exit=\$?\"; stty -a" \
          /dev/null > "$WORK/tty.out" 2>&1
    # only what changed is written, so the words of a line arrive as
    # separate runs; these two land where the list left blank rows
    grep -q "Thursday" "$WORK/tty.out" && grep -q "river?" "$WORK/tty.out" \
        && ok "in a real terminal it draws the list and opens a message" \
        || note_fail "the message never showed: $(tail -c 300 "$WORK/tty.out" | tr -d '\033' | tr '\n' ' ')"
    grep -q "exit=0" "$WORK/tty.out" \
        && ok "q quits, with status 0" || note_fail "it did not quit cleanly: $(tail -c 200 "$WORK/tty.out" | tr -d '\033')"
    if grep -q "exit=0" "$WORK/tty.out" && sed -n '/exit=0/,$p' "$WORK/tty.out" | grep -q " echo " \
       && sed -n '/exit=0/,$p' "$WORK/tty.out" | grep -q " icanon "; then
        ok "and gives the terminal back: echo and line editing are on again"
    else
        note_fail "the terminal was left in raw mode: $(sed -n '/exit=/,$p' "$WORK/tty.out" | head -5 | tr '\n' ' ')"
    fi
else
    info "skipped: no 'script' command to give the viewer a terminal"
fi

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
info "checks output: $WORK/checks.out"
exit 1
