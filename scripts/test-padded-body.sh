#!/bin/sh
# test-padded-body.sh — check the recipe that sends a message's words as a padded attachment (#902)
#
# helpers/rpad.sh writes the words into a file padded with random bytes to
# whole attachment pieces (less 4 KiB for the zip's headers), behind a fixed
# marker, and an outbox file with a fixed short body that attaches it.
# helpers/runpad.sh, called from an on_package hook, puts the words back
# into the message.  The hooks are taken from the encryption guide itself,
# so the guide's recipe is what is tested.
#
# The daemon under test, "receiver", has attachment_chunk_size = 65536 and
# the guide's on_consent and on_package hooks.  "mallory"
# (scripts/lib/fake-contact.lua) sends it a padded message; it sends padded
# messages to "alice" (scripts/lib/fake-recipient.lua).
#
# Cases:
#   rpad             the outbox file keeps the draft's to: lines, attaches
#                    padded/<name>/message.padded-body and has the fixed
#                    body; 10 and 3000 bytes of words make files of the
#                    same size (one piece less 4 KiB), 70000 bytes two
#                    pieces less 4 KiB; refuses a draft with no to: line and
#                    a name already in the outbox
#   runpad           the words come back byte for byte: with no last
#                    newline, with bytes that are not text, and quoting the
#                    marker itself; a file with no marker, or a marker
#                    that has lost its dashes, changes nothing; with no
#                    inbox file the words go beside the padded file
#   received         mallory's padded file is accepted by the hook with no
#                    one at the machine, and once it arrives the message
#                    holds the words and the padded file is gone; one
#                    offered at over 64 MiB waits for the owner
#   sent             two messages of 10 and 3000 bytes go to alice: the
#                    message, the offer and the piece are each the same
#                    size on the wire for both, and what alice gets unpacks
#                    and unpads to the words
#
# Usage:
#   scripts/test-padded-body.sh          # use the enclosing checkout
#   scripts/test-padded-body.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
WORK="/tmp/rmail/tests/padded-body"
PORT=59572
TEST_NAME="padded-body"
. "$SCRIPT_DIR/lib/test-receiver.sh"

ALICE_PORT=59573
ALICE_TOKEN="padded-body-alice-token-not-a-secret"
export ALICE_PORT ALICE_TOKEN
printf '\nalice.ip = "127.0.0.1"\nalice.port = %s\nalice.token = "%s"\n' \
    "$ALICE_PORT" "$ALICE_TOKEN" >> "$BOX/contacts"
printf 'attachment_chunk_size = 65536\non_consent = ./hooks/on_consent.sh\non_package = ./hooks/on_package.sh\n' \
    >> "$BOX/config"

# the guide's two hooks, with the install path it is written for replaced
# by this checkout's
GUIDE="$DIR/docs/.templates/encryption.md"
mkdir -p "$BOX/hooks"
for hook in on_consent on_package; do
    awk -v first="# $hook hook (#902)" '
        /^```/ { if (keep) exit; inside = !inside; next }
        inside && index($0, first) == 1 { keep = 1; print "#!/bin/sh" }
        keep { print }
    ' "$GUIDE" | sed "s|/home/you/programs/email|$DIR|g" > "$BOX/hooks/$hook.sh"
    chmod +x "$BOX/hooks/$hook.sh"
    if [ "$(wc -l < "$BOX/hooks/$hook.sh")" -lt 3 ]; then
        note_fail "no $hook hook for #902 in the encryption guide"
    fi
done

mkdir -p "$WORK/alice"
"$LUA" "$DIR/scripts/lib/fake-recipient.lua" "$DIR" "$ALICE_PORT" "$ALICE_TOKEN" "$WORK/alice" \
    > "$WORK/alice.log" 2>&1 &
ALICE_PID=$!

start_receiver

cat > "$WORK/cases.lua" <<'LUA'
package.path = arg[1] .. "/scripts/lib/?.lua;" .. arg[1] .. "/libs/?.lua;" .. package.path
local fc = require("fake-contact")
local mallory, _, box, work = fc.for_test(arg)
local zip, reader = require("zip-writer"), require("zip-reader")
local json, dir = mallory.json, arg[1]
local alice_dir = work .. "/alice"
local CHUNK = 65536
local MARK = "\n" .. string.rep("-", 79) .. "\n" ..
    "    end of encrypted message. what follows is random data with no meaning.\n" ..
    string.rep("-", 79) .. "\n"

local function check(passed, words, detail)
    if passed then print("ok " .. words)
    else print("-- " .. words .. (detail ~= nil and (": " .. tostring(detail)) or "")) end
end
local function read(path) local f = io.open(path, "rb"); if not f then return nil end; local s = f:read("*a"); f:close(); return s end
local function write(path, s) local f = assert(io.open(path, "wb")); f:write(s); f:close() end
local function q(s) return "'" .. s:gsub("'", "'\\''") .. "'" end
local function sh(cmd) local ok = os.execute(cmd .. " > " .. q(work .. "/sh.out") .. " 2>&1"); return ok == true or ok == 0 end
local function words(n) return (string.rep("The quick brown fox. ", math.ceil(n / 21))):sub(1, n) end
local function events()
    local list = {}
    for line in (read(alice_dir .. "/events") or ""):gmatch("[^\n]+") do list[#list + 1] = json.decode(line) end
    return list
end
local function event(kind, test)
    for _, e in ipairs(events()) do if e.kind == kind and test(e) then return e end end
end

-- a scratch mailbox for rpad alone, with the same piece size
local pad_box = work .. "/pad-box"
os.execute("mkdir -p " .. q(pad_box .. "/outbox"))
write(pad_box .. "/config", "name = scratch\nattachment_chunk_size = " .. CHUNK .. "\n")
local function rpad(mailbox, draft_name, body, head)
    local draft = work .. "/" .. draft_name
    write(draft, (head or "to: alice\n\n") .. body)
    return sh(q(dir .. "/helpers/rpad.sh") .. " " .. q(mailbox) .. " " .. q(draft))
end
local function padded(mailbox, name) return mailbox .. "/padded/" .. name .. "/message.padded-body" end

print("section rpad")
check(rpad(pad_box, "ten", words(10), "to: alice\nto: bob\nattach: /etc/hostname\n\n"), "rpad writes a padded message", read(work .. "/sh.out"))
local out = read(pad_box .. "/outbox/ten") or ""
check(out:find("^to: alice\nto: bob\nattach: /etc/hostname\nattach: " .. padded(pad_box, "ten"):gsub("%p", "%%%0") .. "\n\nThis message was sent padded"),
    "the outbox file keeps the to: and attach: lines, attaches the padded file, then the fixed body", out:sub(1, 300))
local size_10 = #(read(padded(pad_box, "ten")) or "")
check(size_10 == CHUNK - 4096, "10 bytes of words: one piece less 4 KiB", size_10)
check((read(padded(pad_box, "ten")) or ""):sub(1, 10 + #MARK) == words(10) .. MARK, "the words, then the marker")
rpad(pad_box, "three-thousand", words(3000))
check(#(read(padded(pad_box, "three-thousand")) or "") == size_10, "3000 bytes of words: the same size")
local stub_10 = (read(pad_box .. "/outbox/ten") or ""):match("\n\n(.*)$")
local stub_3000 = (read(pad_box .. "/outbox/three-thousand") or ""):match("\n\n(.*)$")
check(stub_10 and stub_10 == stub_3000, "and the same body in the outbox")
rpad(pad_box, "seventy-thousand", words(70000))
check(#(read(padded(pad_box, "seventy-thousand")) or "") == 2 * CHUNK - 4096, "70000 bytes: two pieces less 4 KiB")
check(not rpad(pad_box, "no-to", "hello\n", "") and not io.open(pad_box .. "/outbox/no-to"),
    "a draft with no to: line is refused")
check(not rpad(pad_box, "ten", "again\n"), "a name already in the outbox is refused")

print("section runpad")
local function round_trip(label, body)
    local file = work .. "/rt.padded-body"
    write(file, body .. MARK .. string.rep("\0\255", 300))
    write(work .. "/rt-inbox", "the short body\n")
    local ran = sh(q(dir .. "/helpers/runpad.sh") .. " " .. q(file) .. " " .. q(work .. "/rt-inbox"))
    check(ran and read(work .. "/rt-inbox") == body and not io.open(file), label, read(work .. "/sh.out"))
end
round_trip("words with no last newline come back byte for byte", "no newline at the end")
round_trip("bytes that are not text too", "\0\1\2binary\255\254\n\0")
round_trip("a message quoting the marker keeps every word", "here is the marker:" .. MARK .. "and after it\n")
round_trip("an empty message", "")
write(work .. "/plain.txt", "just a file\n")
write(work .. "/rt-inbox", "the short body\n")
check(not sh(q(dir .. "/helpers/runpad.sh") .. " " .. q(work .. "/plain.txt") .. " " .. q(work .. "/rt-inbox"))
    and read(work .. "/plain.txt") == "just a file\n" and read(work .. "/rt-inbox") == "the short body\n",
    "a file with no marker changes nothing")
write(work .. "/broken.padded-body", string.rep("words ", 40) .. "\n    end of encrypted message. what follows is random data with no meaning.\nnoise")
write(work .. "/rt-inbox", "the short body\n")
check(not sh(q(dir .. "/helpers/runpad.sh") .. " " .. q(work .. "/broken.padded-body") .. " " .. q(work .. "/rt-inbox"))
    and read(work .. "/rt-inbox") == "the short body\n", "nor does one whose marker has lost its dashes")
write(work .. "/orphan.padded-body", "orphaned words\n" .. MARK .. "noise")
check(sh(q(dir .. "/helpers/runpad.sh") .. " " .. q(work .. "/orphan.padded-body") .. " ''")
    and read(work .. "/orphan.padded-body.txt") == "orphaned words\n", "with no inbox file the words go beside it")

print("section received")
local mallory_box = work .. "/mallory-box"
os.execute("mkdir -p " .. q(mallory_box .. "/outbox"))
write(mallory_box .. "/config", "attachment_chunk_size = " .. CHUNK .. "\n")
local body = words(5000) .. "\n"
rpad(mallory_box, "padded-in", body, "to: receiver\n\n")
local stub = (read(mallory_box .. "/outbox/padded-in") or ""):match("\n\n(.*)$")
local att_id = "9ad00001"
local status = mallory:request("POST", "/deliver", json.encode({type = "message", subject = "padded-in",
    message_id = "test-" .. att_id, body = stub}))
check(status == 200 and read(box .. "/inbox/padded-in") == stub, "the message arrives with its short body", status)
local packed = work .. "/padded-in.zip"
local made = zip.pack(padded(mallory_box, "padded-in"), packed)
local bytes = read(packed)
status = mallory:post_json("/deliver", {type = "attachment_request", attachment_id = att_id,
    filename = "message.padded-body", expected_size = made.size, message_id = "test-" .. att_id})
check(status == 200, "the padded file is offered", status)
check(mallory:wait_for(30, function()
    mallory:request("GET", "/")
    local r = mallory:consent_record(box, att_id)
    return r ~= nil and r.status == "accepted"
end), "the on_consent hook accepts it, with no one at the machine")
local all_ok = true
for i = 0, math.ceil(#bytes / CHUNK) - 1 do
    local s
    for _ = 1, 20 do
        s = mallory:send_chunk(att_id, bytes, i, CHUNK)
        if s ~= 503 then break end
        mallory.socket.sleep(0.5)
    end
    if s ~= 200 then all_ok = false; print("   piece " .. i .. ": " .. tostring(s)) end
end
check(all_ok, "its pieces arrive")
check(mallory:wait_for(30, function() return read(box .. "/inbox/padded-in") == body end),
    "the on_package hook puts the words in the message, byte for byte", (read(box .. "/inbox/padded-in") or ""):sub(1, 80))
check(not io.open(box .. "/attachments/message.padded-body"), "and the padded file is gone")

local big_id = "9ad00002"
mallory:request("POST", "/deliver", json.encode({type = "message", subject = "too-big",
    message_id = "test-" .. big_id, body = stub}))
mallory:post_json("/deliver", {type = "attachment_request", attachment_id = big_id,
    filename = "message.padded-body", expected_size = 100 * 1024 * 1024, message_id = "test-" .. big_id})
local waited = mallory:wait_for(6, function()
    mallory:request("GET", "/")
    local r = mallory:consent_record(box, big_id)
    return r ~= nil and r.status ~= "pending"
end)
local big = mallory:consent_record(box, big_id)
check(not waited and big and big.status == "pending", "one over 64 MiB waits for the owner",
    big and big.status)

print("section sent")
local alice = fc.new(dir, "127.0.0.1", tonumber(arg[2]), os.getenv("ALICE_TOKEN"))
local sent = {["pad-one"] = words(10), ["pad-two"] = words(3000)}
for name, text in pairs(sent) do rpad(box, name, text) end
local offers = {}
check(mallory:wait_for(60, function()
    for name in pairs(sent) do
        offers[name] = offers[name] or event("request", function(e) return e.filename == "message.padded-body"
            and (event("message", function(m) return m.subject == name and m.message_id == e.message_id end)) end)
    end
    return offers["pad-one"] and offers["pad-two"]
end), "both messages and their offers reach alice")
for name in pairs(sent) do
    if offers[name] then
        -- 503 while the daemon is sending to her: said again until heard
        for _ = 1, 40 do
            local s = alice:post_json("/deliver", {type = "attachment_response", attachment_id = offers[name].id, consent = true})
            if s ~= 503 then break end
            alice.socket.sleep(0.5)
        end
    end
end
local done = {}
check(mallory:wait_for(90, function()
    for name in pairs(sent) do
        done[name] = done[name] or (offers[name] and event("complete", function(e) return e.id == offers[name].id end))
    end
    return done["pad-one"] and done["pad-two"]
end), "alice accepts, and both padded files arrive")
local m1 = event("message", function(e) return e.subject == "pad-one" end) or {}
local m2 = event("message", function(e) return e.subject == "pad-two" end) or {}
check(m1.frame and m1.frame == m2.frame, "the two messages are the same size on the wire",
    tostring(m1.frame) .. " " .. tostring(m2.frame))
check(offers["pad-one"] and offers["pad-one"].frame == (offers["pad-two"] or {}).frame, "so are the two offers")
check(done["pad-one"] and done["pad-one"].frame == (done["pad-two"] or {}).frame, "and the two pieces",
    tostring((done["pad-one"] or {}).frame) .. " " .. tostring((done["pad-two"] or {}).frame))
local unpadded_all = true
for name, text in pairs(sent) do
    local into = work .. "/unpacked-" .. name
    os.execute("rm -rf " .. q(into) .. " && mkdir -p " .. q(into))
    local ok = offers[name] and pcall(reader.extract, alice_dir .. "/received/" .. offers[name].id .. ".zip", into, {size = 1e9, exact = false, now = os.time()})
    write(work .. "/alice-inbox-" .. name, "the short body\n")
    local got = ok and sh(q(dir .. "/helpers/runpad.sh") .. " " .. q(into .. "/message.padded-body") .. " " ..
        q(work .. "/alice-inbox-" .. name)) and read(work .. "/alice-inbox-" .. name)
    if got ~= text then unpadded_all = false; print("   " .. name .. ": " .. tostring(ok) .. " " .. read(work .. "/sh.out")) end
end
check(unpadded_all, "what alice gets unpacks and unpads to the words")
LUA

run_lua_cases < "$WORK/cases.lua"

stop_receiver
touch "$WORK/alice/stop"
wait "$ALICE_PID" 2>/dev/null
finish
