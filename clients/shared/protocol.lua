-- protocol.lua — rmail wire protocol client
--
-- AES-256-GCM over raw TCP. Reuses rmail_crypto.so and luasocket.
--
-- Wire format (both directions):
--   [4-byte big-endian length][12-byte nonce][ciphertext + 16-byte GCM tag]
--
-- Content inside the encrypted frame is HTTP-style:
--   METHOD /path HTTP/1.0\r\nContent-Length: N\r\n\r\nbody

local socket = require("socket")
local crypto = require("rmail_crypto")
local json   = require("dkjson")

local protocol = {}

-- ── Key derivation ─────────────────────────────────────────────────────

function protocol.key_from_token(token)
    return crypto.sha256(token)
end

-- ── Frame encoding / decoding ──────────────────────────────────────────

function protocol.encrypt_frame(plaintext, key)
    local nonce = crypto.random_bytes(12)
    local ciphertext = crypto.aes_gcm_encrypt(key, nonce, plaintext)
    local len = #nonce + #ciphertext
    local len_bytes = string.char(
        math.floor(len / 16777216) % 256,
        math.floor(len / 65536) % 256,
        math.floor(len / 256) % 256,
        len % 256)
    return len_bytes .. nonce .. ciphertext
end

function protocol.decrypt_frame(sock, key)
    -- Read 4-byte length prefix
    local len_bytes, err = protocol.recv_exact(sock, 4)
    if not len_bytes then return nil, "read length: " .. (err or "closed") end
    local b1, b2, b3, b4 = len_bytes:byte(1, 4)
    local frame_len = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
    if frame_len < 28 or frame_len > 10485760 then
        return nil, "bad frame length: " .. frame_len
    end

    -- Read nonce + ciphertext
    local frame, ferr = protocol.recv_exact(sock, frame_len)
    if not frame then return nil, "read frame: " .. (ferr or "closed") end
    local nonce = frame:sub(1, 12)
    local ciphertext = frame:sub(13)
    local plaintext = crypto.aes_gcm_decrypt(key, nonce, ciphertext)
    if not plaintext then return nil, "decryption failed" end
    return plaintext
end

-- Read exactly n bytes from a socket
function protocol.recv_exact(sock, n)
    local parts = {}
    local total = 0
    while total < n do
        local chunk, err, partial = sock:receive(n - total)
        if not chunk then
            if partial and #partial > 0 then
                parts[#parts + 1] = partial
                total = total + #partial
            else
                return nil, err
            end
        else
            parts[#parts + 1] = chunk
            total = total + #chunk
        end
    end
    return table.concat(parts)
end

-- ── HTTP-style request/response ────────────────────────────────────────

function protocol.build_request(method, path, body, content_type)
    local header = method .. " " .. path .. " HTTP/1.0\r\n"
    if body and #body > 0 then
        if content_type then
            header = header .. "Content-Type: " .. content_type .. "\r\n"
        end
        header = header .. "Content-Length: " .. #body .. "\r\n"
    end
    header = header .. "\r\n"
    if body and #body > 0 then
        return header .. body
    end
    return header
end

function protocol.parse_response(plaintext)
    local sep = plaintext:find("\r\n\r\n")
    if not sep then return nil, nil, "no header/body separator" end

    local header = plaintext:sub(1, sep - 1)
    local body = plaintext:sub(sep + 4)

    local status_line = header:match("^([^\r\n]+)")
    local status = tonumber(status_line:match("%s(%d+)%s"))
    if not status then return nil, nil, "bad status line: " .. status_line end

    return status, body
end

-- ── Client object ──────────────────────────────────────────────────────

local Client = {}
Client.__index = Client

function protocol.new(host, port, token)
    local self = setmetatable({}, Client)
    self.host = host
    self.port = port
    self.key = protocol.key_from_token(token)
    self.sock = nil
    return self
end

function Client:connect()
    if self.sock then return true end
    local sock, err = socket.tcp()
    if not sock then return nil, err end
    sock:settimeout(5)
    local ok, cerr = sock:connect(self.host, self.port)
    if not ok then sock:close(); return nil, cerr end
    sock:settimeout(10)
    self.sock = sock
    return true
end

function Client:close()
    if self.sock then
        pcall(function() self.sock:close() end)
        self.sock = nil
    end
end

-- Send one request, return (status, body) or (nil, error).
-- Reuses connection, reconnects once on failure.
function Client:request(method, path, body, content_type)
    local req = protocol.build_request(method, path, body, content_type)
    for attempt = 1, 2 do
        local ok, err = self:connect()
        if not ok then
            if attempt == 2 then return nil, err end
            self:close()
        else
            -- Send encrypted request
            local frame = protocol.encrypt_frame(req, self.key)
            local sent, serr = self.sock:send(frame)
            if not sent then
                self:close()
                if attempt == 2 then return nil, serr end
            else
                -- Read encrypted response
                local plaintext, derr = protocol.decrypt_frame(self.sock, self.key)
                if not plaintext then
                    self:close()
                    if attempt == 2 then return nil, derr end
                else
                    return protocol.parse_response(plaintext)
                end
            end
        end
    end
    return nil, "request failed after 2 attempts"
end

-- Convenience methods
function Client:get(path)
    return self:request("GET", path)
end

function Client:post(path, body, content_type)
    content_type = content_type or "application/json"
    return self:request("POST", path, body, content_type)
end

function Client:post_json(path, data)
    local body = json.encode(data)
    return self:post(path, body, "application/json")
end

function Client:put(path, body)
    return self:request("PUT", path, body, "application/octet-stream")
end

function Client:delete(path)
    return self:request("DELETE", path)
end

-- ── API methods ────────────────────────────────────────────────────────

function Client:sync(req)
    local status, body = self:post_json("/api/sync", req)
    if not status then return nil, body end
    if status ~= 200 then return nil, "sync failed: HTTP " .. status end
    return json.decode(body)
end

function Client:download_file(type, filename)
    local status, body = self:get("/api/file/" .. type .. "/" .. filename)
    if not status then return nil, body end
    if status ~= 200 then return nil, type .. "/" .. filename .. ": HTTP " .. status end
    return body
end

function Client:upload_outbox_file(filename, content)
    local status, body = self:request("POST", "/api/file/outbox/" .. filename,
                                       content, "application/octet-stream")
    if not status then return nil, body end
    return status == 200
end

function Client:get_contacts()
    local status, body = self:get("/api/contacts")
    if not status then return nil, body end
    if status ~= 200 then return nil, "HTTP " .. status end
    return body
end

function Client:post_contacts(content)
    local status = self:request("POST", "/api/contacts",
                                 content, "application/octet-stream")
    return status == 200
end

function Client:list_attachments()
    local status, body = self:get("/api/attachments")
    if not status then return nil, body end
    if status ~= 200 then return nil, "HTTP " .. status end
    return json.decode(body)
end

function Client:download_attachment(filename)
    local status, body = self:get("/api/attachments/" .. filename)
    if not status then return nil, body end
    if status ~= 200 then return nil, "HTTP " .. status end
    return body
end

function Client:delete_attachment(filename)
    local status = self:delete("/api/attachments/" .. filename)
    return status == 200
end

function Client:get_my_address()
    local status, body = self:get("/api/myaddress")
    if not status then return nil end
    if status ~= 200 then return nil end
    return json.decode(body)
end

return protocol
