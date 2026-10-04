-- fake-recipient.lua — a stand-in recipient that a real rmail daemon sends to
--
-- fake-contact.lua plays a contact *talking to* a daemon.  This plays one
-- the daemon *talks to*: it listens on a port, answers every request at
-- once, and never dials anyone.  Two real daemons on one machine cannot be
-- relied on to talk both ways: a daemon answers no one while its own sync
-- waits on a reply (the open "blocking sync cycle stalls inbound" issue),
-- so two that have something to say to each other at the same moment both
-- stall, and on one machine they always do.  With this in the recipient's
-- place, the daemon under test sends, this answers, and the test speaks
-- for the recipient through fake-contact.lua (a consent answer, a cancel).
--
-- Run as a program, in the background, with the same Lua as the daemon:
--
--   lua scripts/lib/fake-recipient.lua <checkout> <port> <token> <folder>
--
-- What it keeps, under <folder> (made if missing):
--
--   inbox/<subject>         each message's body, overwritten by updates
--   events                  one JSON object per line, in arrival order:
--                           {kind = "message"|"update"|"request"|"cancel"|
--                            "delete"|"address"|"complete", ...fields}
--   pieces/<id>/<n>         attachment pieces as they arrive
--   received/<id>.zip       a whole attachment, once every piece is held
--
-- How it answers (the shapes the real receiver uses):
--
--   message, update           200 {ok}
--   attachment_request        200 {ok}
--   attachment_chunk          checksum checked; 200 {ok, missing = the next
--                             64 pieces still owed, held = how many held};
--                             a bad checksum is dropped and still owed
--   attachment_cancel         200 for an id it was offered, else 404
--   /delete, /update-address  200 {ok}
--   anything else             404
--
-- It stops when <folder>/stop appears.  A file <folder>/hold holding a
-- number makes it wait that many seconds before its next answer (once).

local DIR, PORT, TOKEN, FOLDER = arg[1], tonumber(arg[2]), arg[3], arg[4]
package.path  = DIR .. "/libs/?.lua;" .. package.path
package.cpath = DIR .. "/libs/?.so;" .. package.cpath
local socket = require("socket")
local crypto = require("rmail_crypto")
local json   = require("dkjson")
local mime   = require("mime")
local KEY    = crypto.sha256(TOKEN)

os.execute("mkdir -p '" .. FOLDER .. "/inbox' '" .. FOLDER .. "/pieces' '" .. FOLDER .. "/received'")

-- {{{ local function hex
local function hex(bytes)
    return (bytes:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
-- }}}

-- {{{ local function write
local function write(path, text)
    local f = assert(io.open(path, "wb"))
    f:write(text); f:close()
end
-- }}}

local frame_bytes = 0 -- size on the wire of the request being handled

-- {{{ local function event
-- Every event also says how big the request's frame was on the wire
-- (`frame`, bytes): what someone watching the network sees.
local function event(t)
    t.frame = frame_bytes
    local f = assert(io.open(FOLDER .. "/events", "a"))
    f:write(json.encode(t), "\n"); f:close()
end
-- }}}

-- {{{ local function u32
local function u32(n)
    return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
                       math.floor(n / 256) % 256, n % 256)
end
-- }}}

local offered = {}   -- attachment id -> true, for cancels
local shapes  = {}   -- attachment id -> {total = n}

-- {{{ local function owed
-- The next pieces still owed for an attachment, at most 64, and how many
-- are held.
local function owed(id)
    local total = shapes[id].total
    local missing, held = {}, 0
    for n = 0, total - 1 do
        local f = io.open(FOLDER .. "/pieces/" .. id .. "/" .. n, "rb")
        if f then f:close(); held = held + 1
        elseif #missing < 64 then missing[#missing + 1] = n end
    end
    return missing, held
end
-- }}}

-- {{{ local function chunk
local function chunk(d)
    local id = d.attachment_id
    local raw = mime.unb64(d.data or "") or ""
    shapes[id] = shapes[id] or {total = d.total_chunks}
    os.execute("mkdir -p '" .. FOLDER .. "/pieces/" .. id .. "'")
    if hex(crypto.sha256(raw)) == d.chunk_checksum then
        write(FOLDER .. "/pieces/" .. id .. "/" .. d.chunk_index, raw)
    end
    local missing, held = owed(id)
    if #missing == 0 and not shapes[id].done then
        shapes[id].done = true
        local parts = {}
        for n = 0, shapes[id].total - 1 do
            local f = assert(io.open(FOLDER .. "/pieces/" .. id .. "/" .. n, "rb"))
            parts[#parts + 1] = f:read("*a"); f:close()
        end
        write(FOLDER .. "/received/" .. id .. ".zip", table.concat(parts))
        event({kind = "complete", id = id})
    end
    return 200, {ok = true, missing = missing, held = held}
end
-- }}}

-- {{{ local function handle
-- One decrypted request -> status, answer table.
local function handle(method, path, body)
    local d = json.decode(body or "") or {}
    if method == "POST" and path == "/deliver" then
        if d.type == "message" then
            write(FOLDER .. "/inbox/" .. (d.subject or "untitled"), d.body or "")
            event({kind = "message", subject = d.subject, message_id = d.message_id,
                   mtime = d.mtime, body_bytes = #(d.body or "")})
            return 200, {ok = true}
        elseif d.type == "update" then
            write(FOLDER .. "/inbox/" .. (d.subject or "untitled"), d.body or "")
            event({kind = "update", subject = d.subject, message_id = d.message_id,
                   mtime = d.mtime, body_bytes = #(d.body or "")})
            return 200, {ok = true}
        elseif d.type == "attachment_request" then
            offered[d.attachment_id] = true
            event({kind = "request", id = d.attachment_id, filename = d.filename,
                   message_id = d.message_id})
            return 200, {ok = true}
        elseif d.type == "attachment_chunk" then
            return chunk(d)
        elseif d.type == "attachment_cancel" then
            event({kind = "cancel", id = d.attachment_id, known = offered[d.attachment_id] or false})
            if offered[d.attachment_id] then return 200, {ok = true} end
            return 404, {error = "no such attachment transfer"}
        end
    elseif method == "POST" and path == "/delete" then
        event({kind = "delete", message_id = d.message_id})
        return 200, {ok = true}
    elseif method == "POST" and path == "/update-address" then
        event({kind = "address"})
        return 200, {ok = true}
    end
    return 404, {error = "not found"}
end
-- }}}

-- {{{ local function serve
-- One connection: frames until the peer closes.
local function serve(conn)
    conn:settimeout(5)
    while true do
        local len_bytes = conn:receive(4)
        if not len_bytes or #len_bytes ~= 4 then return end
        if len_bytes == "GET " then return end
        local a, b, c, e = len_bytes:byte(1, 4)
        local packet = conn:receive(a * 16777216 + b * 65536 + c * 256 + e)
        if not packet then return end
        frame_bytes = 4 + #packet
        local plain = crypto.aes_gcm_decrypt(KEY, packet:sub(1, 12), packet:sub(13))
        if not plain then return end
        local method, path = plain:match("^(%S+) (%S+)")
        local head_end = plain:find("\r\n\r\n", 1, true)
        local body = head_end and plain:sub(head_end + 4) or ""
        -- <folder>/hold holding a number: wait that many seconds before
        -- answering, after writing <folder>/holding -- so a test can catch
        -- the daemon in the middle of waiting on us
        local hold = io.open(FOLDER .. "/hold")
        if hold then
            local seconds = tonumber(hold:read("*a")) or 0
            hold:close()
            write(FOLDER .. "/holding", "")
            socket.sleep(seconds)
            os.remove(FOLDER .. "/hold")
        end
        local status, answer = handle(method, path, body)
        local out = json.encode(answer)
        local text = "HTTP/1.1 " .. status .. " X\r\nContent-Type: application/json\r\n" ..
                     "Content-Length: " .. #out .. "\r\n\r\n" .. out
        local nonce = crypto.random_bytes(12)
        local sealed = crypto.aes_gcm_encrypt(KEY, nonce, text)
        conn:send(u32(#nonce + #sealed) .. nonce .. sealed)
    end
end
-- }}}

local server = assert(socket.bind("127.0.0.1", PORT))
server:settimeout(0.5)
while true do
    local stop = io.open(FOLDER .. "/stop")
    if stop then stop:close(); break end
    local conn = server:accept()
    if conn then
        pcall(serve, conn)
        conn:close()
    end
end
