#!/bin/sh
# test-contact-folders.sh — a folder in the outbox named after a contact sends what is put in it, and the receiver keeps its folders safely (#214)
#
# Two throwaway mailboxes, "sender" and "receiver", run on this machine.
# The sender's outbox holds a folder named "receiver", with files and
# folders in it, and the cases follow what happens to them:
#
#   quick-note            no to: line: sent to the folder's contact
#   projects/2026/q2-plan the folders below the contact folder are kept
#                         on the receiver's side
#   dup                   a to: line naming the folder's contact again:
#                         sent once
#   both                  a to: line naming the sender itself: the
#                         receiver gets it, and so does the sender's inbox
#   hello                 beside a plain outbox file also called hello:
#                         two separate messages
#   photo.bin             bytes that are not text: the file on disk is
#                         never changed
#   .secret, .hidden/x    hidden: not sent
#   bad<newline>dir/x     a path the receiver would refuse: not sent
#   drafts/x              a folder named after no contact: not sent
#
# then edits quick-note (the edit reaches the receiver), moves q2-plan
# (gone from its old place, delivered at its new one), deletes quick-note
# (deleted on the receiver), and has the receiver delete "both" (the
# sender keeps the file for its other recipient and sends it to the
# receiver no more) and "dup" (the sender's file goes).
#
# A stand-in contact ("mallory", scripts/lib/fake-contact.lua) then sends
# the receiving daemon subjects no honest daemon sends: an absolute path,
# "..", empty names, NUL and control bytes, hidden names, too deep, too
# long, and a folder that is a symbolic link out of the inbox.  Each must
# be refused with nothing written; then a fuzz pass sends random subjects
# and checks every answer against the rule, written again here, and that
# nothing appeared outside the inbox.
#
# Usage:
#   scripts/test-contact-folders.sh          # use the enclosing checkout
#   scripts/test-contact-folders.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

LAUNCHER="$DIR/run-rmail.sh"
LUA="$DIR/deps/lua/bin/lua"

# RAM-backed scratch space, per project convention.
WORK="/tmp/rmail/tests/contact-folders"
RAM_FILES="/tmp/rmail-progress/*-tmp-rmail-tests-contact-folders-*"

SENDER_PORT=59550
RECEIVER_PORT=59551
TOKEN="contact-folders-test-token-not-a-real-secret"
MALLORY_TOKEN="contact-folders-mallory-token-not-a-secret"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }

FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail contact folders test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

if [ ! -x "$LAUNCHER" ]; then note_fail "no launcher at $LAUNCHER"; exit 1; fi
if [ ! -x "$LUA" ]; then note_fail "no bundled Lua at $LUA (scripts/install.sh builds it)"; exit 1; fi

rm -rf "$WORK"
mkdir -p "$WORK"
rm -f $RAM_FILES

# make_mailbox <dir> <name> <port>
make_mailbox() {
    mkdir -p "$1/inbox" "$1/outbox" "$1/.state" "$1/attachments"
    printf 'name = %s\nport = %s\nattachment_pending_dir = %s\n' "$2" "$3" "$1/pending" > "$1/config"
}
make_mailbox "$WORK/sender"   sender   "$SENDER_PORT"
make_mailbox "$WORK/receiver" receiver "$RECEIVER_PORT"

printf 'receiver.ip    = "127.0.0.1"\nreceiver.port  = %s\nreceiver.token = "%s"\n' \
    "$RECEIVER_PORT" "$TOKEN" > "$WORK/sender/contacts"
printf 'sender.ip    = "127.0.0.1"\nsender.port  = %s\nsender.token = "%s"\n\nmallory.token = "%s"\n' \
    "$SENDER_PORT" "$TOKEN" "$MALLORY_TOKEN" > "$WORK/receiver/contacts"

OUT="$WORK/sender/outbox"
R_INBOX="$WORK/receiver/inbox"
S_INBOX="$WORK/sender/inbox"

# The contact folder is put together beside the outbox and moved in whole,
# so the daemon's first look at it sees every file.
F="$WORK/folder-being-made"
mkdir -p "$F/projects/2026" "$F/.hidden" "$F/bad
dir"
printf 'a quick note\n' > "$F/quick-note"
printf 'the q2 plan\n' > "$F/projects/2026/q2-plan"
printf 'to: receiver\n\nsaid twice\n' > "$F/dup"
printf 'to: sender\n\nfor both of us\n' > "$F/both"
printf 'hello from the folder\n' > "$F/hello"
printf '\000\001\002binary\377\376 not text\n' > "$F/photo.bin"
printf 'hidden\n' > "$F/.secret"
printf 'hidden too\n' > "$F/.hidden/x"
printf 'a refused path\n' > "$F/bad
dir/x"
PHOTO_SUM="$(sha256sum "$F/photo.bin" | cut -d' ' -f1)"
mkdir -p "$OUT/drafts"
printf 'not for anyone\n' > "$OUT/drafts/x"
printf 'to: receiver\n\nhello from the outbox\n' > "$OUT/hello"
mv "$F" "$OUT/receiver"

"$LAUNCHER" "$WORK/receiver/config" > "$WORK/receiver.log" 2>&1 &
RECEIVER_PID=$!
"$LAUNCHER" "$WORK/sender/config" > "$WORK/sender.log" 2>&1 &
SENDER_PID=$!

# wake <seconds> <condition...>: nudge the sender's outbox watcher (a hidden
# file it ignores; files below a contact folder are otherwise found on the
# next timed sync), then wait for the condition
wait_for() {
    limit="$1"; shift
    n=0
    while [ "$n" -lt "$limit" ]; do
        touch "$OUT/.wake"
        if "$@"; then return 0; fi
        sleep 1
        n=$((n + 1))
    done
    return 1
}

# inbox_holds <inbox> <body>: some file in that inbox (any depth) is exactly <body>
inbox_holds() {
    find "$1" -type f | while IFS= read -r f; do
        [ "$(cat "$f")" = "$2" ] && echo yes && break
    done | grep -q yes
}

first_deliveries() {
    [ -f "$R_INBOX/quick-note" ] && [ -f "$R_INBOX/projects/2026/q2-plan" ] \
        && [ -f "$R_INBOX/dup" ] && [ -f "$R_INBOX/both" ] && [ -f "$S_INBOX/both" ] \
        && inbox_holds "$R_INBOX" "hello from the folder" && inbox_holds "$R_INBOX" "hello from the outbox"
}

echo "the first deliveries"
if wait_for 90 first_deliveries; then
    ok "quick-note, projects/2026/q2-plan, dup, both and both hellos arrived"
else
    note_fail "not everything arrived: $(cd "$R_INBOX" && find . -type f | tr '\n' ' ')"
fi
[ "$(cat "$R_INBOX/quick-note" 2>/dev/null)" = "a quick note" ] \
    && ok "a file with no to: line went to the folder's contact, as written" \
    || note_fail "quick-note's body: $(cat "$R_INBOX/quick-note" 2>/dev/null)"
[ "$(cat "$R_INBOX/projects/2026/q2-plan" 2>/dev/null)" = "the q2 plan" ] \
    && ok "folders below the contact folder are kept: inbox/projects/2026/q2-plan" \
    || note_fail "no inbox/projects/2026/q2-plan"
[ "$(cat "$R_INBOX/dup" 2>/dev/null)" = "said twice" ] && [ "$(find "$R_INBOX" -name 'dup*' | wc -l)" -eq 1 ] \
    && ok "a to: line naming the folder's contact again sends it once" \
    || note_fail "dup arrived $(find "$R_INBOX" -name 'dup*' | wc -l) times"
[ "$(cat "$S_INBOX/both" 2>/dev/null)" = "for both of us" ] \
    && ok "a to: line inside the file adds a recipient (the sender itself)" \
    || note_fail "the sender's own copy of both is missing"
[ -f "$OUT/receiver/quick-note" ] && [ "$(cat "$OUT/receiver/quick-note")" = "a quick note" ] \
    && ok "the sender's file stays where it was, unchanged" \
    || note_fail "the sender's quick-note was moved or changed"
[ "$(sha256sum "$OUT/receiver/photo.bin" | cut -d' ' -f1)" = "$PHOTO_SUM" ] \
    && ok "photo.bin (not text) is unchanged on the sender's disk" \
    || note_fail "photo.bin was changed on disk"
if find "$R_INBOX" | grep -q 'secret\|hidden\|bad\|drafts'; then
    note_fail "a hidden file, a refused path or a non-contact folder was sent"
else
    ok "hidden files, the refused path and drafts/ were not sent"
fi
grep -q "not sending receiver/bad" "$WORK/sender.log" \
    && ok "the refused path is named in the sender's log" \
    || note_fail "the sender did not say why bad/x is not sent"
grep -q "directory .*outbox/drafts in outbox" "$WORK/sender.log" \
    && ok "drafts/ (no such contact) is ignored as before, with the usual warning" \
    || note_fail "no warning about drafts/"
if grep -q "directory .*outbox/receiver in outbox" "$WORK/sender.log"; then
    note_fail "the contact folder was warned about as a stray folder"
else
    ok "the contact folder is not warned about"
fi

echo ""
echo "edit, move and delete on the sender's side"
printf 'a quick note, edited\n' > "$OUT/receiver/quick-note"
wait_for 90 sh -c "[ \"\$(cat '$R_INBOX/quick-note' 2>/dev/null)\" = 'a quick note, edited' ]" \
    && ok "an edit reaches the receiver" || note_fail "the edit did not arrive"
mv "$OUT/receiver/projects/2026/q2-plan" "$OUT/receiver/moved-plan"
wait_for 90 sh -c "[ -f '$R_INBOX/moved-plan' ] && [ ! -e '$R_INBOX/projects/2026/q2-plan' ]" \
    && ok "a move is a delete at the old place and a delivery at the new one" \
    || note_fail "after the move: $(cd "$R_INBOX" && find . -type f | tr '\n' ' ')"
rm "$OUT/receiver/quick-note"
wait_for 90 sh -c "[ ! -e '$R_INBOX/quick-note' ]" \
    && ok "deleting the file deletes the receiver's copy" || note_fail "the receiver still has quick-note"

echo ""
echo "the receiver deletes"
rm "$R_INBOX/both" "$R_INBOX/dup"
wait_for 90 sh -c "[ ! -e '$OUT/receiver/dup' ] && grep -q 'removed recipient receiver from receiver/both' '$WORK/sender.log'" \
    && ok "the receiver's deletes reached the sender" || note_fail "the sender never heard of the deletes"
[ ! -e "$OUT/receiver/dup" ] && ok "dup (for the folder's contact only) is gone from the sender's folder" \
    || note_fail "dup is still in the sender's folder"
[ -f "$OUT/receiver/both" ] && ok "both is kept: its to: line still names the sender" \
    || note_fail "both was removed though another recipient remains"
# two more passes, to be sure the folder's contact is not sent it again
touch "$OUT/.wake"; sleep 4; touch "$OUT/.wake"; sleep 4
[ ! -e "$R_INBOX/both" ] && ! ls "$R_INBOX" | grep -q '^both' \
    && ok "both is not sent to the receiver again" || note_fail "both came back to the receiver"

echo ""
echo "subjects no honest daemon sends (a stand-in contact)"
mkdir -p "$WORK/outside"
ln -s "$WORK/outside" "$R_INBOX/link"
printf 'the owner made this\n' > "$R_INBOX/plainfile"
"$LUA" - "$DIR" "$RECEIVER_PORT" "$MALLORY_TOKEN" "$WORK" > "$WORK/lua.out" 2>&1 <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory = fc.new(arg[1], "127.0.0.1", tonumber(arg[2]), arg[3])
local work = arg[4]
local inbox = work .. "/receiver/inbox"
local json = mallory.json

local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail and (": " .. detail) or "")) end
end

-- every file and folder under a folder, as a sorted list
local function tree(dir)
    local h = io.popen("cd '" .. dir .. "' && find . -mindepth 1 | sort")
    local out = h:read("*a"); h:close()
    return out
end

local n = 0
local function send(subject)
    n = n + 1
    return mallory:post_json("/deliver", {type = "message", subject = subject,
        message_id = "subject-test-" .. n, body = "body " .. n .. "\n"})
end

-- the rule, written again from #214's decisions, without rmail's code
local function acceptable(subject)
    if not subject:find("/", 1, true) then return true end
    if #subject > 1024 or subject:sub(1, 1) == "/" then return false end
    for i = 1, #subject do
        local b = subject:byte(i)
        if b < 32 or b == 127 then return false end
    end
    local parts = 0
    for name in (subject .. "/"):gmatch("([^/]*)/") do
        parts = parts + 1
        if name == "" or name:sub(1, 1) == "." or #name > 255 then return false end
    end
    return parts <= 16
end

local before_box = tree(work .. "/receiver"):gsub("[^\n]*inbox[^\n]*\n", ""):gsub("[^\n]*%.state[^\n]*\n", "")
local before_work = tree(work):gsub("[^\n]*/receiver/[^\n]*\n", ""):gsub("[^\n]*/sender/[^\n]*\n", "")

-- {subject, what it is, the reason the answer must give}: each refusal is
-- checked for its own reason, so that a later check catching what an
-- earlier one should have (the folder check catches ".." too) still fails
local refusals = {
    {"/etc/rmail-test-absolute", "an absolute path", "an absolute path"},
    {"../escape", "\"..\" first", "a \"..\""},
    {"a/../../escape", "\"..\" inside", "a \"..\""},
    {"a/./b", "\".\" inside", "a \".\""},
    {"a//b", "an empty name", "an empty name"},
    {"a/", "a trailing slash", "an empty name"},
    {"a/b\0c", "a NUL byte", "a control character"},
    {"a/b\nc", "a line break", "a control character"},
    {"a/b\127c", "a DEL byte", "a control character"},
    {".ssh/authorized_keys", "a hidden folder", "a hidden name"},
    {"a/.b", "a hidden file", "a hidden name"},
    {string.rep("d/", 16) .. "x", "17 levels", "more than 16 levels"},
    {"a/" .. string.rep("n", 256), "a 256-byte name", "a name over 255 bytes"},
    {string.rep("abcdefghi/", 103) .. "x", "over 1024 bytes", "a path over 1024 bytes"},
    {"link/x", "a folder that is a symbolic link out of the inbox", "a folder on the way that is a symbolic link"},
}
local before = tree(inbox)
for _, r in ipairs(refusals) do
    local status, answer = send(r[1])
    local said = tostring(answer.error or answer.filename)
    check(status == 400 and said:sub(-#r[3]) == r[3], "refused: " .. r[2] .. " (" .. r[3] .. ")",
        tostring(status) .. " " .. said)
end
check(tree(inbox) == before, "nothing was written in the inbox for any of them")
check(tree(work .. "/outside") == "", "nothing was written through the link")

-- where the last message sent was saved, read from the inbox itself: the
-- answer no longer names the file (#206: the sender is not told the name)
local function saved_at()
    local h = io.popen("cd '" .. inbox .. "' && grep -rlxF -- 'body " .. n .. "' . 2>/dev/null")
    local found = h:read("*a"); h:close()
    return (found:gsub("^%./", ""):gsub("\n$", ""))
end

local status, answer = send(string.rep("d/", 15) .. "x")
check(status == 200 and saved_at() == string.rep("d/", 15) .. "x", "16 levels are accepted", saved_at())
status, answer = send("-rf/--help")
check(status == 200 and fc.read_file(inbox .. "/-rf/--help") == "body " .. n .. "\n",
    "names starting with a dash are folders and files, not options", saved_at())
status, answer = send("my folder/my file")
check(status == 200 and saved_at() == "my-folder/my-file", "spaces become dashes in each name", saved_at())
status, answer = send("plainfile/note")
check(status == 200 and saved_at() == "note" and fc.read_file(inbox .. "/plainfile") == "the owner made this\n",
    "a file holding a folder's name: kept, and the message saved beside it", saved_at())
status, answer = send("a\\b")
check(status == 200 and saved_at() == "b", "a subject with no \"/\" is named as before", saved_at())
check(answer.filename == nil, "the answer does not name the file it was saved as (#206)", tostring(answer.filename))

print("section a fuzz pass over random subjects")
math.randomseed(214)
local pieces = {"a", "b", "q2", ".", "..", "/", "/", "/", "\0", "\n", "\t", " ", "\\", "-", "~", "$x",
                "*", "\195\169", "\127", "%2e", "link", "plainfile", ".x", "con", "\255"}
local tried, wrong, worst = 0, 0, nil
for _ = 1, 600 do
    local parts = {}
    for i = 1, math.random(1, 10) do parts[i] = pieces[math.random(#pieces)] end
    local subject = table.concat(parts)
    local st, ans = send(subject)
    tried = tried + 1
    local expected = acceptable(subject) and 200 or 400
    -- one exception: a path through the link is refused though the rule allows it
    if expected == 200 and (subject:match("^link/") or subject:match("^link$")) and subject:find("/") then expected = 400 end
    if st ~= expected then
        wrong = wrong + 1
        worst = worst or string.format("%q: %d, expected %d (%s)", subject, st, expected, tostring(ans.error))
    elseif st == 200 then
        -- the name it was saved under is inside the inbox
        local fname, bad = saved_at(), false
        if fname == "" or fname:sub(1, 1) == "/" then bad = true end
        for name in (fname .. "/"):gmatch("([^/]*)/") do
            if name == "" or name == "." or name == ".." then bad = true end
        end
        if bad then
            wrong = wrong + 1
            worst = worst or ("saved as " .. fname)
        end
    end
end
check(wrong == 0, tried .. " random subjects answered as the rule says", worst)
local h = io.popen("cd '" .. inbox .. "' && find . -mindepth 1 \\( -type l ! -name link \\) -print")
local links = h:read("*a"); h:close()
check(links == "", "no symbolic link was made in the inbox", links)
h = io.popen("cd '" .. inbox .. "' && top=$(pwd -P) && find . -mindepth 1 -type d ! -name link | while IFS= read -r d; do " ..
    "case \"$(cd \"$d\" && pwd -P)/\" in \"$top\"/?*) ;; *) echo \"$d\";; esac; done")
local outside = h:read("*a"); h:close()
check(outside == "", "every folder in the inbox resolves inside it", outside)
local after_box = tree(work .. "/receiver"):gsub("[^\n]*inbox[^\n]*\n", ""):gsub("[^\n]*%.state[^\n]*\n", "")
local after_work = tree(work):gsub("[^\n]*/receiver/[^\n]*\n", ""):gsub("[^\n]*/sender/[^\n]*\n", "")
check(after_box == before_box, "nothing new in the receiver's mailbox outside its inbox", after_box)
check(after_work == before_work and tree(work .. "/outside") == "", "nothing new beside the mailboxes", after_work)
check(pcall(function() mallory:request("GET", "/") end), "the receiving daemon still answers")
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
[ "$lua_status" -eq 0 ] || note_fail "the stand-in contact stopped with status $lua_status"

kill "$RECEIVER_PID" "$SENDER_PID"
wait "$RECEIVER_PID" "$SENDER_PID" 2>/dev/null

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "all cases passed"
    rm -rf "$WORK"
    rm -f $RAM_FILES
    exit 0
fi
echo "$FAILURES case(s) failed; logs kept in $WORK"
exit 1
