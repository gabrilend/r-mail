#!/bin/sh
# test-thin-client-editor.sh — check the terminal viewer's edit mode (#711)
#
# Edit mode writes one outbox file when told to save, and nothing else.
# Like test-thin-client-viewer.sh, the viewer is handed a pretend terminal
# (a fixed size, keys as names) and what it drew and wrote is read back;
# no real terminal is needed.
#
# Cases:
#   buffer      the gap buffer: typing, Backspace and Delete at the cursor,
#               moving across characters of several bytes, a line cut
#               with its newline, and undo taking back a run of typing
#               as one step
#   rows        rows break at a writer's newline and at the last space
#               that fits; a word too long is broken inside; a resize
#               moves the wrap points and never the text; the cursor is
#               found in its row and column, and up and down keep the
#               column they started from
#   keys        Ctrl-S, Ctrl-X and the other control keys come out as
#               ctrl- and their letter
#   new         n opens a new message with the cursor after "to: "; typed
#               text, Enter and the arrows build it; Ctrl-S asks for a
#               name; a name that is taken, holds a slash or starts with a
#               dot is refused; the file is written whole, with no hidden
#               file left beside it
#   edit        e on an outbox file opens it; a change on disk since it
#               was opened is not saved over until a second Ctrl-S; Ctrl-K
#               and Ctrl-U move a line; Ctrl-X with unsaved changes warns,
#               and a second Ctrl-X leaves the file as it was
#   inbox       e does nothing in the inbox, and the inbox is unchanged
#   cursor      in edit mode the terminal's cursor is shown where the
#               text's cursor is drawn, and hidden again in the list
#
# Usage:
#   scripts/test-thin-client-editor.sh          # use the enclosing checkout
#   scripts/test-thin-client-editor.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/thin-client-editor"
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
echo "rmail thin-client editor test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"

if [ -z "$LUA" ]; then
    note_fail "no Lua interpreter"
    exit 1
fi

rm -rf "$WORK"
BOX="$WORK/mailbox-1"
mkdir -p "$BOX/inbox" "$BOX/outbox"
printf 'from: bob\n\nAre you free for lunch?\n' > "$BOX/inbox/bob-lunch"
printf 'to: carol\n\nfirst line\nsecond line\n' > "$BOX/outbox/to-carol"
printf 'to: dave\n\nhello\n' > "$BOX/outbox/taken"
cp "$BOX/inbox/bob-lunch" "$WORK/bob-lunch.before"

cat > "$WORK/checks.lua" <<'LUA'
local shared, box = arg[1], arg[2]
package.path = shared .. "/?.lua;" .. package.path
local EditBuf = require("editbuf")
local term = require("term")
local Viewer = require("viewer")

local function say(case, good, what, got)
    print(case .. "\t" .. (good and "ok" or "--") .. "\t" .. what
        .. (good and "" or ("\t" .. tostring(got):gsub("\27", "^["):gsub("\n", "|"))))
end
local function read(path)
    local f = io.open(path, "rb"); if not f then return nil end
    local s = f:read("*a"); f:close(); return s
end
local function write(path, s) local f = assert(io.open(path, "wb")); f:write(s); f:close() end
local function press(v, ...) for _, k in ipairs({ ... }) do v:handle(k) end end
local function type_text(v, s) for ch in s:gmatch("[%z\1-\127\194-\244][\128-\191]*") do v:handle(ch) end end

-- buffer
local b = EditBuf.new("héllo")
b:move_to(2)
b:insert("X")
say("buffer", b:text() == "héXllo" and b:offset() == 3, "typing goes in at the cursor, between characters of two bytes", b:text())
b:backspace(); b:delete()
say("buffer", b:text() == "hélo" and b:offset() == 2, "Backspace takes the character before, Delete the one after", b:text())
b:left(); b:left(); b:left()
say("buffer", b:offset() == 0, "the cursor stops at the start", b:offset())
local c = EditBuf.new("one\ntwo\nthree")
c:move_to(5)
local cut = c:cut_line()
say("buffer", cut == "two\n" and c:text() == "one\nthree" and c:offset() == 4,
    "a cut line takes its newline, and the cursor stays where it was", c:text())
local u = EditBuf.new("ab")
u:move_to(2)
u:insert("c"); u:insert("d"); u:insert("e")
u:backspace()
say("buffer", u:text() == "abcd", "(typed, then one Backspace)", u:text())
u:undo_last()
say("buffer", u:text() == "abcde", "undo takes back the deleting", u:text())
u:undo_last()
say("buffer", u:text() == "ab" and u:offset() == 2, "and then the run of typing, as one step", u:text())
say("buffer", u:undo_last() == false, "with nothing left, undo says so", "")

-- rows
local function shown(buf, width)
    local out = {}
    for _, r in ipairs(buf:rows(width)) do
        local t = {}
        for i = r.first, r.last do t[#t + 1] = buf:at(i) end
        out[#out + 1] = (table.concat(t):gsub("\n", "$"))
    end
    return table.concat(out, "|")
end
local w = EditBuf.new("the quick brown fox\nover")
say("rows", shown(w, 10) == "the quick |brown fox$|over", "rows break at the last space that fits and at a newline",
    shown(w, 10))
say("rows", shown(w, 6) == "the |quick |brown |fox$|over" and w:text() == "the quick brown fox\nover",
    "a resize moves the wrap points and not the text", shown(w, 6))
say("rows", shown(EditBuf.new("abcdefghij"), 4) == "abcd|efgh|ij", "a word too long is broken inside it",
    shown(EditBuf.new("abcdefghij"), 4))
local rows = w:rows(10)
w:move_to(12)  -- after "the quick br"
local r, col = w:locate(rows)
say("rows", r == 2 and col == 3, "the cursor is found in its row and column", r .. "," .. col)
w:to_row(rows, 1, col)
say("rows", w:offset() == 2, "up keeps the column", w:offset())
w:to_row(rows, 3, col)
say("rows", w:offset() == 22, "down to a shorter row stops at its end, or the column", w:offset())

-- keys
local function keys_of(bytes)
    local i, out = 1, {}
    local function rd() if i > #bytes then return nil end local x = bytes:sub(i, i); i = i + 1; return x end
    while i <= #bytes do out[#out + 1] = term.parse(rd) end
    return table.concat(out, " ")
end
local k = keys_of("\19\24\11\21\26\3\12\t\r")
say("keys", k == "ctrl-s ctrl-x ctrl-k ctrl-u ctrl-z ctrl-c ctrl-l tab enter",
    "control keys come out as ctrl- and their letter, Tab and Enter as before", k)

-- new
local v = Viewer.new(box, 10, 40)
v:draw()
press(v, "tab")
v:draw()
press(v, "n")
say("new", v.mode == "edit" and v.edit.buf:text() == "to: \n\n" and v.edit.buf:offset() == 4,
    "n opens a new message with the cursor after \"to: \"", v.edit and v.edit.buf:text())
type_text(v, "dave")
press(v, "down", "down")
type_text(v, "Lunch at noon?")
press(v, "enter")
type_text(v, "— me")
v:draw()
local hint = v.screen:text():match("[^\n]*$")
say("new", hint:find("new message *", 1, true) and hint:find("^S save", 1, true),
    "the hint bar says the message is new and unsaved, and the keys", hint)
press(v, "ctrl-s")
say("new", v.edit.prompt ~= nil, "Ctrl-S asks for a name", "")
type_text(v, "taken"); press(v, "enter")
say("new", v.edit.prompt and v.edit.message:find("taken; choose another", 1, true) and read(box .. "/outbox/taken") == "to: dave\n\nhello\n",
    "a name already in the folder is refused, and that file is untouched", v.edit.message)
for _ = 1, 5 do press(v, "backspace") end
type_text(v, "a/b"); press(v, "enter")
say("new", v.edit.prompt and v.edit.message:find("no /", 1, true), "a name with a slash is refused", v.edit.message)
for _ = 1, 3 do press(v, "backspace") end
type_text(v, ".hidden"); press(v, "enter")
say("new", v.edit.prompt and v.edit.message:find("dot", 1, true), "a name starting with a dot is refused", v.edit.message)
for _ = 1, 7 do press(v, "backspace") end
type_text(v, "lunch-for-dave"); press(v, "enter")
say("new", read(box .. "/outbox/lunch-for-dave") == "to: dave\n\nLunch at noon?\n— me",
    "the message is written whole, under its name", read(box .. "/outbox/lunch-for-dave"))
local leftovers = io.popen("ls -A " .. box .. "/outbox"):read("*a")
say("new", not leftovers:find("rmail-view", 1, true), "no hidden file is left beside it", leftovers)
press(v, "ctrl-x")
say("new", v.mode == "list" and v.selected_name == "lunch-for-dave", "Ctrl-X leaves a saved message at once, with it selected",
    v.mode)

-- edit
v:draw()
for i, e in ipairs(v.entries) do if e.name == "to-carol" then v.selected = i end end
press(v, "e")
say("edit", v.mode == "edit" and v.edit.name == "to-carol" and v.edit.buf:offset() == 0, "e opens an outbox file", v.mode)
press(v, "down", "down")
press(v, "ctrl-k")
press(v, "down")
press(v, "ctrl-u")
say("edit", v.edit.buf:text() == "to: carol\n\nsecond line\nfirst line\n", "Ctrl-K cuts a line and Ctrl-U puts it back elsewhere",
    v.edit.buf:text())
-- the daemon marks the file while it is open
write(box .. "/outbox/to-carol", "to: carol\n\nfirst line\nsecond line\n\nCANNOT REACH carol\n")
press(v, "ctrl-s")
say("edit", read(box .. "/outbox/to-carol"):find("CANNOT REACH", 1, true) and v.edit.message:find("changed on disk", 1, true),
    "a file changed on disk since it was opened is not saved over", v.edit.message)
press(v, "ctrl-s")
say("edit", read(box .. "/outbox/to-carol") == "to: carol\n\nsecond line\nfirst line\n",
    "a second Ctrl-S saves over it", read(box .. "/outbox/to-carol"))
type_text(v, "x")
press(v, "ctrl-x")
say("edit", v.mode == "edit" and v.edit.message:find("not saved", 1, true), "Ctrl-X with unsaved changes warns", v.mode)
press(v, "ctrl-x")
say("edit", v.mode == "list" and read(box .. "/outbox/to-carol") == "to: carol\n\nsecond line\nfirst line\n",
    "a second Ctrl-X leaves without saving", read(box .. "/outbox/to-carol"))
press(v, "e")
press(v, "ctrl-z")
say("edit", v.edit.message == "nothing to undo", "undo starts empty for a file just opened", v.edit.message)
press(v, "ctrl-x")

-- inbox
press(v, "tab")
v:draw()
press(v, "e")
say("inbox", v.mode == "list", "e does nothing in the inbox", v.mode)
press(v, "enter")
press(v, "e")
say("inbox", v.mode == "read", "nor on a message read from the inbox", v.mode)
press(v, "q")

-- cursor
local pretend = { out = {} }
local keys = { "tab", "n", "h", "i", "ctrl-x", "ctrl-x", "q" }
local shown_at, hidden_after = nil, nil
function pretend.size() return 10, 40 end
function pretend.write(s) pretend.out[#pretend.out + 1] = s end
function pretend.read_key()
    local key = table.remove(keys, 1)
    return key
end
local v2 = Viewer.new(box, 10, 40)
v2:run(pretend)
for i, s in ipairs(pretend.out) do
    if s:find("\27%[2;7H\27%[%?25h$") then shown_at = shown_at or i end
    if shown_at and i > shown_at and s:find("\27%[%?25l$") then hidden_after = i end
end
say("cursor", shown_at ~= nil, "in edit mode the cursor is shown after \"to: hi\" (row 2, column 7)",
    table.concat(pretend.out, "\n"):sub(-300))
say("cursor", hidden_after ~= nil, "and hidden again back in the list", "")
LUA

"$LUA" "$WORK/checks.lua" "$SHARED" "$BOX" > "$WORK/checks.out" 2>&1
lua_status=$?
last=""
while IFS="	" read -r case verdict what got; do
    if [ "$case" != "$last" ]; then echo ""; echo "$case"; last="$case"; fi
    if [ "$verdict" = "ok" ]; then ok "$what"; else note_fail "$what${got:+: $got}"; fi
done < "$WORK/checks.out"
[ "$lua_status" -eq 0 ] || note_fail "the checks stopped with status $lua_status: $(tail -3 "$WORK/checks.out" | tr '\n' ' ')"

echo ""
cmp -s "$BOX/inbox/bob-lunch" "$WORK/bob-lunch.before" \
    && ok "the inbox is as it was" || note_fail "the inbox changed"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n\n"
    exit 0
fi
printf "  \033[31m%s case(s) failed\033[0m\n\n" "$FAILURES"
exit 1
