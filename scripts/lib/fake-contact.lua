-- fake-contact.lua — a stand-in contact (or phone) that talks to a real rmail daemon
--
-- The security tests need to send a daemon things no honest daemon ever
-- would: chunks without checksums, zips holding symbolic links, a phone
-- upload of two files at once.  A real sending daemon cannot be made to do
-- that, so this library speaks rmail's wire format directly.
--
-- The wire format, as the daemon reads it (handle_request in rmail.lua):
--
--   [4-byte big-endian length][12-byte random nonce][AES-256-GCM ciphertext + 16-byte tag]
--
-- The key is the SHA-256 of the contact's shared token (derive_key).  The
-- plaintext is a small HTTP/1.1 request ("POST /deliver ...", headers,
-- blank line, body), and the answer comes back in the same framing with
-- the same key.  Whichever contact's key decrypts the request is who the
-- daemon believes sent it; a contact marked `own = true` is the owner's
-- phone and may use the /api/ paths.
--
-- Usage from a test (run with the same Lua as the daemon, so the bundled
-- rmail_crypto.so and luasocket load):
--
--   package.path  = DIR .. "/scripts/lib/?.lua;" .. package.path
--   local fake = require("fake-contact").new(DIR, "127.0.0.1", port, token)
--   local status, answer = fake:post_json("/deliver", {type = "attachment_request", ...})
--   local status, body   = fake:request("GET", "/api/attachments/x")

local M = {}

-- {{{ local function load_libraries
-- Load the daemon's own copies of luasocket, the crypto module and the
-- JSON library from <checkout>/libs, so the test uses exactly what the
-- daemon uses.
local function load_libraries(dir)
    package.path  = dir .. "/libs/?.lua;" .. package.path
    package.cpath = dir .. "/libs/?.so;" .. package.cpath
    return require("socket"), require("rmail_crypto"), require("dkjson"), require("mime")
end
-- }}}

-- {{{ local function uint32_be
local function uint32_be(n)
    return string.char(math.floor(n / 16777216) % 256, math.floor(n / 65536) % 256,
                       math.floor(n / 256) % 256, n % 256)
end
-- }}}

-- {{{ function M.new
-- A handle on one daemon, as one contact.  `token` is the shared secret
-- written into the daemon's contacts file for that contact.
function M.new(dir, host, port, token)
    local socket, crypto, json, mime = load_libraries(dir)
    local self = {socket = socket, crypto = crypto, json = json, mime = mime,
                  host = host, port = port, key = crypto.sha256(token)}
    return setmetatable(self, {__index = M})
end
-- }}}

-- {{{ function M:request
-- Send one request on a fresh connection and return (status, body).
-- Errors, rather than returning nil, when the daemon cannot be reached or
-- its answer cannot be decrypted: every caller is a test, and a test that
-- silently got nothing would pass for the wrong reason.
function M:request(method, path, body)
    body = body or ""
    local text = method .. " " .. path .. " HTTP/1.1\r\n" ..
                 "Content-Length: " .. #body .. "\r\n\r\n" .. body
    local nonce = self.crypto.random_bytes(12)
    local sealed = self.crypto.aes_gcm_encrypt(self.key, nonce, text)
    local conn = assert(self.socket.tcp())
    conn:settimeout(30)
    assert(conn:connect(self.host, self.port))
    assert(conn:send(uint32_be(#nonce + #sealed) .. nonce .. sealed))
    local len_bytes = assert(conn:receive(4))
    local a, b, c, d = len_bytes:byte(1, 4)
    local packet = assert(conn:receive(a * 16777216 + b * 65536 + c * 256 + d))
    conn:close()
    local plain = self.crypto.aes_gcm_decrypt(self.key, packet:sub(1, 12), packet:sub(13))
    if not plain then error("fake-contact: the daemon's answer did not decrypt") end
    local status = tonumber(plain:match("^HTTP/%S+ (%d+)"))
    local head_end = plain:find("\r\n\r\n", 1, true)
    if not status or not head_end then error("fake-contact: unreadable answer: " .. plain:sub(1, 80)) end
    return status, plain:sub(head_end + 4)
end
-- }}}

-- {{{ function M:post_json
-- POST a table as JSON and return (status, decoded answer table).  A body
-- that is not JSON comes back as {raw = body} so the test can print it.
function M:post_json(path, tbl)
    local status, body = self:request("POST", path, self.json.encode(tbl))
    local decoded = self.json.decode(body)
    if type(decoded) ~= "table" then decoded = {raw = body} end
    return status, decoded
end
-- }}}

-- {{{ function M:sha256_hex
-- Hex SHA-256 of a byte string, the form every rmail checksum field takes.
function M:sha256_hex(bytes)
    return (self.crypto.sha256(bytes):gsub(".", function(ch)
        return string.format("%02x", ch:byte())
    end))
end
-- }}}

-- {{{ function M:send_chunk
-- Send one attachment chunk the way send_next_chunks does, with every
-- field overridable so a test can leave one out or lie in it.  `fields`
-- is merged over the honest values; set a field to false to omit it.
function M:send_chunk(att_id, zip_bytes, index, chunk_size, fields)
    local total = math.max(1, math.ceil(#zip_bytes / chunk_size))
    local piece = zip_bytes:sub(index * chunk_size + 1, (index + 1) * chunk_size)
    local msg = {
        type = "attachment_chunk", attachment_id = att_id,
        chunk_index = index, total_chunks = total,
        data = self.mime.b64(piece),
        chunk_checksum = self:sha256_hex(piece),
        total_checksum = self:sha256_hex(zip_bytes),
    }
    for k, v in pairs(fields or {}) do
        if v == false then msg[k] = nil else msg[k] = v end
    end
    return self:post_json("/deliver", msg)
end
-- }}}

-- {{{ function M:consent_record
-- The receiving daemon's consent record for one attachment id, read from
-- <mailbox>/.state/consent-pending.json, or nil when there is none.
function M:consent_record(mailbox, att_id)
    local f = io.open(mailbox .. "/.state/consent-pending.json", "r")
    if not f then return nil end
    local all = self.json.decode(f:read("*a")); f:close()
    return type(all) == "table" and all[att_id] or nil
end
-- }}}

-- {{{ function M:ask_and_accept
-- Ask to send an attachment, then answer the consent form the way the
-- owner would at the machine: delete the "deny" line.  The daemon reads
-- forms during a sync cycle; any request from a contact makes that
-- contact due, so a plain "GET /" is sent to bring the cycle round.
-- Returns true once the record says "accepted", false after `seconds`.
function M:ask_and_accept(mailbox, att_id, filename, expected_size, seconds)
    local status, answer = self:post_json("/deliver", {
        type = "attachment_request", attachment_id = att_id,
        filename = filename, expected_size = expected_size,
        message_id = "test-" .. att_id,
    })
    if status ~= 200 then
        error("fake-contact: request refused: " .. status .. " " .. self.json.encode(answer))
    end
    local record = self:consent_record(mailbox, att_id)
    if not record then error("fake-contact: no consent record after the request") end
    local form = mailbox .. "/inbox/" .. record.inbox_file
    local text = M.read_file(form)
    local f = assert(io.open(form, "w"))
    f:write((text:gsub("\ndeny\n?$", "\n")))
    f:close()
    return self:wait_for(seconds, function()
        self:request("GET", "/")
        local r = self:consent_record(mailbox, att_id)
        return r ~= nil and r.status == "accepted"
    end)
end
-- }}}

-- {{{ function M.for_test
-- The usual start of a test's Lua half (see scripts/lib/test-receiver.sh,
-- which passes DIR PORT MALLORY_TOKEN PHONE_TOKEN WORK as arguments):
-- returns the contact "mallory", the owner's phone, and the mailbox folder,
-- once the daemon answers.  Exits the script when it never does.
function M.for_test(args)
    local dir, port, work = args[1], tonumber(args[2]), args[5]
    local mallory = M.new(dir, "127.0.0.1", port, args[3])
    local phone   = M.new(dir, "127.0.0.1", port, args[4])
    local up = mallory:wait_for(30, function()
        return (pcall(function() mallory:request("GET", "/") end))
    end)
    if not up then print("-- the daemon never answered"); os.exit(1) end
    return mallory, phone, work .. "/box", work
end
-- }}}

-- {{{ function M:send_whole
-- Ask to send `bytes` (a zip) as `filename` declaring `expected_size`,
-- accept on the owner's behalf, and send it as one chunk.  Returns the
-- chunk answer (status, table), or nil when consent was never recorded.
function M:send_whole(box, att_id, filename, bytes, expected_size)
    if not self:ask_and_accept(box, att_id, filename, expected_size, 30) then
        print("-- " .. filename .. ": consent never recorded")
        return nil
    end
    return self:send_chunk(att_id, bytes, 0, math.max(1, #bytes))
end
-- }}}

-- {{{ function M.read_file
function M.read_file(path)
    local f = assert(io.open(path, "rb"))
    local s = f:read("*a"); f:close()
    return s
end
-- }}}

-- {{{ function M.wait_for
-- Poll `check` every 0.2 s until it returns true or `seconds` pass.
-- Returns whether it became true; a caller reports a timeout as a failure,
-- never as a pass.
function M:wait_for(seconds, check)
    local deadline = self.socket.gettime() + seconds
    while self.socket.gettime() < deadline do
        if check() then return true end
        self.socket.sleep(0.2)
    end
    return check()
end
-- }}}

return M
