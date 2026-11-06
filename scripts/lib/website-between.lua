-- website-between.lua — someone in the middle of a public website fetch (#715b), for tests
--
-- Listens on a port and plays the mailbox to whoever asks there, while
-- fetching from the real mailbox on another port as an asker of its own.
-- It answers with a website key of its own, opens what the real mailbox
-- sealed for it, and seals it again for the asker: what an attacker
-- between the two would do.  scripts/test-public-website.sh checks that
-- an asker who remembers the real key refuses it, and that a first-time
-- asker, who cannot tell, is at least shown different words.
--
-- With "swap" as a fourth argument it holds no key at all: it passes
-- everything on untouched, except that the second piece asked for is
-- answered with the first piece's sealed bytes, which open with the
-- asker's key -- the most a stranger on the path without the key can do.
--
--   lua scripts/lib/website-between.lua <checkout> <listen port> <mailbox port> [swap]
--
-- One request per connection, POST /website and /website/piece only.
-- Runs until killed.

local DIR, LISTEN, REAL, SWAP = arg[1], tonumber(arg[2]), tonumber(arg[3]), arg[4] == "swap"
package.path  = DIR .. "/libs/?.lua;" .. package.path
package.cpath = DIR .. "/libs/?.so;" .. package.cpath
local socket = require("socket")
local json   = require("dkjson")
local c      = require("rmail_crypto")

local function hex(s) return (s:gsub(".", function(x) return string.format("%02x", x:byte()) end)) end
local function unhex(h) return (h:gsub("..", function(x) return string.char(tonumber(x, 16)) end)) end
local function session(shared, asker, owner)
    return c.sha256("rmail public website\0" .. shared .. asker .. owner)
end
local function seal(key, plain)
    local nonce = c.random_bytes(12)
    return nonce .. c.aes_gcm_encrypt(key, nonce, plain)
end
local function open(key, sealed) return c.aes_gcm_decrypt(key, sealed:sub(1, 12), sealed:sub(13)) end

-- its own website key, shown to askers, and its own asking key, shown to the mailbox
local own_priv = c.random_bytes(32)
local own_pub = c.x25519_public(own_priv)
local ask_priv = c.random_bytes(32)
local ask_pub = c.x25519_public(ask_priv)
local real_key -- the key it shares with the real mailbox, once known
local first_piece -- in swap mode: piece 0 as the mailbox sealed it

-- {{{ local function post
local function post(path, tbl)
    local body = json.encode(tbl)
    local s = socket.tcp(); s:settimeout(30)
    assert(s:connect("127.0.0.1", REAL))
    s:send("POST " .. path .. " HTTP/1.1\r\nContent-Length: " .. #body .. "\r\n\r\n" .. body)
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
-- }}}

local server = assert(socket.bind("127.0.0.1", LISTEN))
while true do
    local client = server:accept()
    client:settimeout(30)
    local line = client:receive("*l") or ""
    local path = line:match("^POST (%S+) ")
    local len = 0
    while true do
        local h = client:receive("*l"); if not h or h == "" then break end
        len = tonumber(h:lower():match("content%-length:%s*(%d+)")) or len
    end
    local req = json.decode(len > 0 and client:receive(len) or "") or {}
    local theirs = type(req.key) == "string" and #req.key == 64 and unhex(req.key)
    local answer
    if SWAP and theirs then
        local status, data = post(path, req)
        if status == 200 and path == "/website/piece" and req.n == 0 then first_piece = data end
        if status == 200 then
            answer = (path == "/website/piece" and req.n == 1 and first_piece) or data
        end
    elseif theirs and (path == "/website" or path == "/website/piece") then
        local to_asker = session(c.x25519(own_priv, theirs), theirs, own_pub)
        local fwd = {key = hex(ask_pub), n = req.n, fingerprint = req.fingerprint}
        local status, data = post(path, fwd)
        if status == 200 and path == "/website" then
            local owner_pub = data:sub(1, 32)
            real_key = session(c.x25519(ask_priv, owner_pub), ask_pub, owner_pub)
            answer = own_pub .. seal(to_asker, open(real_key, data:sub(33)))
        elseif status == 200 and real_key then
            answer = seal(to_asker, open(real_key, data))
        end
    end
    if answer then
        client:send("HTTP/1.1 200 OK\r\nContent-Length: " .. #answer .. "\r\nConnection: close\r\n\r\n" .. answer)
    else
        client:send("HTTP/1.1 400 Bad Request\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
    end
    client:close()
end
