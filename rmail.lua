#!/usr/bin/env lua
-- rmail - file-based messaging daemon

-- find our own directory for lib/ imports
local script_dir = arg[0]:match("(.*/)") or "./"
package.path = script_dir .. "lib/?.lua;" .. package.path

local ok, json = pcall(require, "dkjson")
if not ok then
    io.stderr:write("error: dkjson.lua not found.\n")
    io.stderr:write("       place it at: " .. script_dir .. "lib/dkjson.lua\n")
    os.exit(1)
end

local ok2, socket = pcall(require, "socket")
if not ok2 then
    io.stderr:write("error: luasocket not found.\n")
    io.stderr:write("       install it with your package manager or luarocks:\n")
    io.stderr:write("         luarocks install luasocket\n")
    os.exit(1)
end

-- ============================================================
-- Paths & file helpers
-- ============================================================

local HOME = os.getenv("HOME")
local MAIL = HOME .. "/mail"
local INBOX = MAIL .. "/inbox"
local OUTBOX = MAIL .. "/outbox"
local STATE = MAIL .. "/.state"

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    return content
end

local function write_file(path, content)
    local f = io.open(path, "w")
    if not f then return false end
    f:write(content)
    f:close()
    return true
end

local function file_exists(path)
    local f = io.open(path, "r")
    if f then f:close(); return true end
    return false
end

local function list_files(dir)
    local files = {}
    local handle = io.popen('ls -1 "' .. dir .. '" 2>/dev/null')
    if handle then
        for name in handle:lines() do
            if name:sub(1, 1) ~= '.' then
                files[#files + 1] = name
            end
        end
        handle:close()
    end
    return files
end

local function uuid()
    local f = io.open("/dev/urandom", "rb")
    if not f then
        math.randomseed(socket.gettime() * 1000)
        return string.format("%08x-%04x-4%03x-%04x-%012x",
            math.random(0, 0xFFFFFFFF), math.random(0, 0xFFFF),
            math.random(0, 0xFFF), math.random(0x8000, 0xBFFF),
            math.random(0, 0xFFFFFFFFFFFF))
    end
    local bytes = {f:read(16):byte(1, 16)}
    f:close()
    bytes[7] = (bytes[7] % 16) + 64   -- version 4
    bytes[9] = (bytes[9] % 64) + 128  -- variant 1
    return string.format(
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
        bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
        bytes[13], bytes[14], bytes[15], bytes[16])
end

-- ============================================================
-- Config & state
-- ============================================================

local function log(fmt, ...)
    io.stderr:write(os.date("%Y-%m-%d %H:%M:%S ") .. string.format(fmt, ...) .. "\n")
    io.stderr:flush()
end

local function load_config()
    local cfg = {}
    local text = read_file(MAIL .. "/config")
    if not text then return cfg end
    for line in text:gmatch("[^\n]+") do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and line:sub(1, 1) ~= "#" then
            local k, v = line:match("^(%S+):%s*(.+)$")
            if k then cfg[k] = v end
        end
    end
    return cfg
end

local function load_contacts()
    local contacts = {}
    local text = read_file(MAIL .. "/contacts")
    if not text then return contacts end
    for line in text:gmatch("[^\n]+") do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and line:sub(1, 1) ~= "#" then
            local name, host, port, token = line:match("^(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
            if name then
                contacts[name] = {host = host, port = tonumber(port), token = token}
            end
        end
    end
    return contacts
end

local function load_state(name)
    local text = read_file(STATE .. "/" .. name)
    if not text or text == "" then return {} end
    return json.decode(text)
end

local function save_state(name, data)
    write_file(STATE .. "/" .. name, json.encode(data, {indent = true}) .. "\n")
end

-- ============================================================
-- HTTP server (raw TCP via luasocket)
-- ============================================================

local function parse_request(client)
    client:settimeout(5)
    local request_line = client:receive("*l")
    if not request_line then return nil end
    local method, path = request_line:match("^(%S+)%s+(%S+)")

    local headers = {}
    while true do
        local line = client:receive("*l")
        if not line or line == "" then break end
        local k, v = line:match("^(.-):%s*(.+)$")
        if k then headers[k:lower()] = v end
    end

    local body = ""
    local length = tonumber(headers["content-length"] or 0)
    if length > 0 then
        body = client:receive(length)
    end

    return method, path, headers, body
end

local function send_response(client, status, data)
    local body = json.encode(data)
    local text = ({[200]="OK", [403]="Forbidden", [404]="Not Found"})[status] or "Error"
    client:send(
        "HTTP/1.1 " .. status .. " " .. text .. "\r\n" ..
        "Content-Type: application/json\r\n" ..
        "Content-Length: " .. #body .. "\r\n" ..
        "Connection: close\r\n\r\n" ..
        body)
end

local function auth_check(data)
    local sender = data["from"] or ""
    local token = data.token or ""
    local contacts = load_contacts()
    if not contacts[sender] then return false end
    return contacts[sender].token == token
end

local function handle_deliver(data)
    local sender = data["from"]
    local subject = data.subject or "untitled"
    local message_id = data.message_id or uuid()
    local body = data.body or ""

    local filename = subject
    local target = INBOX .. "/" .. filename
    if file_exists(target) then
        local inbox_state = load_state("inbox.json")
        local existing = inbox_state[filename]
        if existing and existing["from"] ~= sender then
            filename = subject .. "-from-" .. sender
            target = INBOX .. "/" .. filename
        end
    end

    write_file(target, body)
    log("delivered: %s from %s -> %s", message_id, sender, filename)

    local inbox_state = load_state("inbox.json")
    inbox_state[filename] = {
        ["from"] = sender,
        message_id = message_id,
        subject = subject,
    }
    save_state("inbox.json", inbox_state)
    return 200, {ok = true, filename = filename}
end

local function handle_delete(data)
    local sender = data["from"]
    local message_id = data.message_id or ""

    -- sender asking us to delete from our inbox
    local inbox_state = load_state("inbox.json")
    for filename, meta in pairs(inbox_state) do
        if meta.message_id == message_id and meta["from"] == sender then
            if file_exists(INBOX .. "/" .. filename) then
                os.remove(INBOX .. "/" .. filename)
                log("deleted from inbox: %s (by sender %s)", filename, sender)
            end
            inbox_state[filename] = nil
            save_state("inbox.json", inbox_state)
            return 200, {ok = true}
        end
    end

    -- recipient telling us they deleted something we sent
    local outbox_state = load_state("outbox.json")
    for filename, meta in pairs(outbox_state) do
        if meta.message_id == message_id then
            meta.remote_deleted = true
            if file_exists(OUTBOX .. "/" .. filename) then
                os.remove(OUTBOX .. "/" .. filename)
                log("deleted from outbox: %s (recipient %s deleted)", filename, sender)
            end
            save_state("outbox.json", outbox_state)
            return 200, {ok = true}
        end
    end

    return 404, {error = "message not found"}
end

-- ============================================================
-- Sync (outgoing)
-- ============================================================

local function http_post(host, port, path, data, my_name, token)
    data["from"] = my_name
    data.token = token
    local payload = json.encode(data)

    local conn = socket.tcp()
    conn:settimeout(10)
    local ok, err = conn:connect(host, port)
    if not ok then
        log("connect failed %s:%d: %s", host, port, err)
        conn:close()
        return false, {}
    end

    conn:send(
        "POST " .. path .. " HTTP/1.1\r\n" ..
        "Host: " .. host .. ":" .. port .. "\r\n" ..
        "Content-Type: application/json\r\n" ..
        "Content-Length: " .. #payload .. "\r\n" ..
        "Connection: close\r\n\r\n" ..
        payload)

    local status_line = conn:receive("*l")
    if not status_line then conn:close(); return false, {} end
    local status = tonumber(status_line:match("(%d+)"))

    local resp_headers = {}
    while true do
        local line = conn:receive("*l")
        if not line or line == "" then break end
        local k, v = line:match("^(.-):%s*(.+)$")
        if k then resp_headers[k:lower()] = v end
    end

    local resp_body = ""
    local length = tonumber(resp_headers["content-length"] or 0)
    if length > 0 then
        resp_body = conn:receive(length) or ""
    end
    conn:close()

    local resp_data = {}
    if resp_body ~= "" then
        local ok2, decoded = pcall(json.decode, resp_body)
        if ok2 then resp_data = decoded or {} end
    end

    return status == 200, resp_data
end

local function parse_outbox_file(path)
    local text = read_file(path)
    if not text then return nil, nil end
    local first_line, rest = text:match("^([^\n]*)\n?(.*)")
    if not first_line or not first_line:lower():match("^to:") then
        return nil, nil
    end
    local recipient = first_line:match("^[Tt][Oo]:%s*(.-)%s*$")
    return recipient, rest or ""
end

local function sync_outbox(my_name)
    local contacts = load_contacts()
    local state = load_state("outbox.json")
    local did_work = false

    local current = {}
    for _, name in ipairs(list_files(OUTBOX)) do current[name] = true end

    -- new files
    for name in pairs(current) do
        if not state[name] then
            local recipient, body = parse_outbox_file(OUTBOX .. "/" .. name)
            if not recipient then
                log("skipping %s: missing 'to:' header", name)
            elseif not contacts[recipient] then
                log("skipping %s: unknown contact '%s'", name, recipient)
            else
                local contact = contacts[recipient]
                local mid = uuid()
                local ok = http_post(contact.host, contact.port, "/deliver",
                    {subject = name, message_id = mid, body = body},
                    my_name, contact.token)
                if ok then
                    state[name] = {to = recipient, message_id = mid, sent = true}
                    log("sent: %s -> %s", name, recipient)
                    did_work = true
                else
                    log("failed to send %s to %s", name, recipient)
                end
            end
        end
    end

    -- deleted files
    for name, meta in pairs(state) do
        if not current[name] then
            if meta.remote_deleted then
                state[name] = nil
                did_work = true
            else
                local recipient = meta.to or ""
                if contacts[recipient] then
                    local contact = contacts[recipient]
                    http_post(contact.host, contact.port, "/delete",
                        {message_id = meta.message_id},
                        my_name, contact.token)
                    log("notified %s of deletion: %s", recipient, name)
                end
                state[name] = nil
                did_work = true
            end
        end
    end

    save_state("outbox.json", state)
    return did_work
end

local function sync_inbox(my_name)
    local contacts = load_contacts()
    local state = load_state("inbox.json")
    local did_work = false

    local current = {}
    for _, name in ipairs(list_files(INBOX)) do current[name] = true end

    for name, meta in pairs(state) do
        if not current[name] then
            local sender = meta["from"] or ""
            if contacts[sender] then
                local contact = contacts[sender]
                http_post(contact.host, contact.port, "/delete",
                    {message_id = meta.message_id},
                    my_name, contact.token)
                log("notified %s of inbox deletion: %s", sender, name)
            end
            state[name] = nil
            did_work = true
        end
    end

    save_state("inbox.json", state)
    return did_work
end

-- ============================================================
-- Main
-- ============================================================

local function main()
    os.execute('mkdir -p "' .. INBOX .. '" "' .. OUTBOX .. '" "' .. STATE .. '"')

    local cfg = load_config()
    local my_name = cfg.name or "user"
    local port = tonumber(cfg.port or "8025")

    log("rmail starting: name=%s port=%d", my_name, port)
    log("mail dir: %s", MAIL)

    local server = assert(socket.bind("0.0.0.0", port))
    server:settimeout(1)
    log("listening on :%d", port)

    local interval = 300
    local MIN_INTERVAL = 60
    local last_sync = socket.gettime()

    while true do
        local client = server:accept()
        if client then
            local ok, err = pcall(function()
                local method, path, headers, body = parse_request(client)
                if method == "POST" and body and body ~= "" then
                    local data = json.decode(body)
                    if not auth_check(data) then
                        send_response(client, 403, {error = "forbidden"})
                    elseif path == "/deliver" then
                        local s, r = handle_deliver(data)
                        send_response(client, s, r)
                    elseif path == "/delete" then
                        local s, r = handle_delete(data)
                        send_response(client, s, r)
                    else
                        send_response(client, 404, {error = "not found"})
                    end
                else
                    send_response(client, 404, {error = "not found"})
                end
            end)
            if not ok then log("request error: %s", tostring(err)) end
            client:close()
        end

        local now = socket.gettime()
        if now - last_sync >= interval then
            local ok, err = pcall(function()
                local w1 = sync_outbox(my_name)
                local w2 = sync_inbox(my_name)
                if w1 or w2 then
                    interval = math.max(MIN_INTERVAL, interval - 240)
                    log("had work, interval -> %ds", interval)
                else
                    interval = interval + 360
                    log("idle, interval -> %ds", interval)
                end
            end)
            if not ok then log("sync error: %s", tostring(err)) end
            last_sync = now
        end
    end
end

main()
