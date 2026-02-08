#!/usr/bin/env lua
-- rmail - file-based messaging daemon

-- ============================================================
-- Configuration (edit these)
-- ============================================================

local MAIL   = "/home/ritz/mail"
local INBOX  = MAIL .. "/inbox"
local OUTBOX = MAIL .. "/outbox"
local STATE  = MAIL .. "/.state"

local LIBS   = nil    -- extra libs path (e.g. "/home/you/lua-libs")
                      -- if set, searched before the bundled libs/ directory

local NOTIFY_IP_CHANGE = true   -- drop a message in contacts' inboxes when IP changes
                                -- (IP detection and contact updates always happen)

-- ============================================================

-- find our own directory for libs/ imports
local script_dir = arg[0]:match("(.*/)") or "./"
if LIBS then
    package.path = LIBS .. "/?.lua;" .. script_dir .. "libs/?.lua;" .. package.path
else
    package.path = script_dir .. "libs/?.lua;" .. package.path
end

local ok, json = pcall(require, "dkjson")
if not ok then
    io.stderr:write("error: dkjson.lua not found.\n")
    io.stderr:write("       place it at: " .. script_dir .. "libs/dkjson.lua\n")
    io.stderr:write("       or set LIBS at the top of rmail.lua to a directory containing it\n")
    os.exit(1)
end

local ok2, socket = pcall(require, "socket")
if not ok2 then
    io.stderr:write("error: luasocket not found.\n")
    io.stderr:write("       install it with your package manager or luarocks:\n")
    io.stderr:write("         luarocks install luasocket\n")
    io.stderr:write("       or set LIBS at the top of rmail.lua to a directory containing it\n")
    os.exit(1)
end

-- ============================================================
-- Paths & file helpers
-- ============================================================


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

local function load_contacts()
    local text = read_file(MAIL .. "/contacts")
    if not text or text == "" then return {} end
    return json.decode(text) or {}
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
        if meta.recipients then
            for recipient, rmeta in pairs(meta.recipients) do
                if rmeta.message_id == message_id and recipient == sender then
                    meta.recipients[recipient] = nil
                    local remaining = remove_recipient_from_file(OUTBOX .. "/" .. filename, recipient)
                    log("removed recipient %s from %s (they deleted)", recipient, filename)
                    if not next(meta.recipients) then
                        outbox_state[filename] = nil
                    end
                    save_state("outbox.json", outbox_state)
                    return 200, {ok = true}
                end
            end
        end
    end

    return 404, {error = "message not found"}
end

local function handle_update_address(data)
    local sender = data["from"]
    local new_host = data.host or ""
    local new_port = data.port

    local text = read_file(MAIL .. "/contacts")
    if not text or text == "" then
        return 404, {error = "sender not in contacts"}
    end
    local contacts = json.decode(text) or {}
    if not contacts[sender] then
        return 404, {error = "sender not in contacts"}
    end

    contacts[sender].host = new_host
    if new_port then contacts[sender].port = new_port end
    write_file(MAIL .. "/contacts", json.encode(contacts, {indent = true}) .. "\n")

    log("updated address for %s: %s:%s", sender, new_host, tostring(new_port))

    -- drop a notification in inbox if the sender requested it
    if data.notify ~= false then
        local filename = "address-update-" .. sender
        local body = sender .. "'s address has changed to " .. new_host .. ":" .. tostring(new_port) ..
            ".\nYour contacts file has been updated automatically."
        write_file(INBOX .. "/" .. filename, body)
    end
    return 200, {ok = true}
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
    local recipients = {}
    local pos = 1
    while pos <= #text do
        local line_end = text:find("\n", pos) or #text + 1
        local line = text:sub(pos, line_end - 1)
        if line:lower():match("^to:") then
            local r = line:match("^[Tt][Oo]:%s*(.-)%s*$")
            if r and r ~= "" then
                recipients[#recipients + 1] = r
            end
            pos = line_end + 1
        else
            break
        end
    end
    if #recipients == 0 then return nil, nil end
    return recipients, text:sub(pos)
end

local function remove_recipient_from_file(filepath, recipient)
    local text = read_file(filepath)
    if not text then return 0 end
    local recipients = {}
    local pos = 1
    while pos <= #text do
        local line_end = text:find("\n", pos) or #text + 1
        local line = text:sub(pos, line_end - 1)
        if line:lower():match("^to:") then
            local r = line:match("^[Tt][Oo]:%s*(.-)%s*$")
            if r and r ~= recipient then
                recipients[#recipients + 1] = r
            end
            pos = line_end + 1
        else
            break
        end
    end
    local body = text:sub(pos)
    if #recipients == 0 then
        os.remove(filepath)
        return 0
    end
    local header = ""
    for _, r in ipairs(recipients) do
        header = header .. "to: " .. r .. "\n"
    end
    write_file(filepath, header .. body)
    return #recipients
end

local function sync_outbox(my_name)
    local contacts = load_contacts()
    local state = load_state("outbox.json")
    local did_work = false

    local current = {}
    for _, name in ipairs(list_files(OUTBOX)) do current[name] = true end

    -- sync existing and new files
    for name in pairs(current) do
        local recipients, body = parse_outbox_file(OUTBOX .. "/" .. name)

        -- build set of current to: lines
        local current_set = {}
        if recipients then
            for _, r in ipairs(recipients) do current_set[r] = true end
        end

        if not recipients and not state[name] then
            log("skipping %s: missing 'to:' header", name)
        else
            if not state[name] then state[name] = {recipients = {}} end

            -- detect removed recipients (sender deleted a to: line)
            for recipient, rmeta in pairs(state[name].recipients) do
                if not current_set[recipient] then
                    if contacts[recipient] then
                        local contact = contacts[recipient]
                        http_post(contact.host, contact.port, "/delete",
                            {message_id = rmeta.message_id},
                            my_name, contact.token)
                        log("notified %s of removal: %s", recipient, name)
                    end
                    state[name].recipients[recipient] = nil
                    did_work = true
                end
            end

            -- send to new recipients
            if recipients then
                for _, recipient in ipairs(recipients) do
                    if not state[name].recipients[recipient] then
                        if not contacts[recipient] then
                            log("skipping %s: unknown contact '%s'", name, recipient)
                        else
                            local contact = contacts[recipient]
                            local mid = uuid()
                            local ok = http_post(contact.host, contact.port, "/deliver",
                                {subject = name, message_id = mid, body = body},
                                my_name, contact.token)
                            if ok then
                                state[name].recipients[recipient] = {message_id = mid}
                                log("sent: %s -> %s", name, recipient)
                                did_work = true
                            else
                                log("failed to send %s to %s", name, recipient)
                            end
                        end
                    end
                end
            end

            -- clean up if no recipients left
            if not next(state[name].recipients) then
                os.remove(OUTBOX .. "/" .. name)
                log("cleaned up %s: no recipients left", name)
                state[name] = nil
                did_work = true
            end
        end
    end

    -- deleted files
    for name, meta in pairs(state) do
        if not current[name] then
            if meta.recipients then
                for recipient, rmeta in pairs(meta.recipients) do
                    if contacts[recipient] then
                        local contact = contacts[recipient]
                        http_post(contact.host, contact.port, "/delete",
                            {message_id = rmeta.message_id},
                            my_name, contact.token)
                        log("notified %s of deletion: %s", recipient, name)
                    end
                end
            end
            state[name] = nil
            did_work = true
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

local IP_SERVICES = {
    {host = "ifconfig.me",            path = "/"},
    {host = "icanhazip.com",          path = "/"},
    {host = "api.ipify.org",          path = "/"},
    {host = "checkip.amazonaws.com",  path = "/"},
}

local function fetch_public_ip(service)
    local conn = socket.tcp()
    conn:settimeout(5)
    local ok, err = conn:connect(service.host, 80)
    if not ok then conn:close(); return nil end
    conn:send("GET " .. service.path .. " HTTP/1.1\r\n" ..
        "Host: " .. service.host .. "\r\nConnection: close\r\n\r\n")

    local status_line = conn:receive("*l")
    if not status_line then conn:close(); return nil end

    while true do
        local line = conn:receive("*l")
        if not line or line == "" then break end
    end

    local ip = conn:receive("*l")
    conn:close()
    if ip then ip = ip:match("^%s*(.-)%s*$") end
    return ip
end

local function check_public_ip()
    for _, service in ipairs(IP_SERVICES) do
        local ip = fetch_public_ip(service)
        if ip then return ip, service end
    end
    return nil
end

local function verify_ip_change(new_ip, used_service)
    for _, service in ipairs(IP_SERVICES) do
        if service.host ~= used_service.host then
            local ip = fetch_public_ip(service)
            if ip then return ip == new_ip end
        end
    end
    return false
end

local function sync_address(my_name, port)
    local new_ip, service = check_public_ip()
    if not new_ip then return end

    local stored_ip = read_file(STATE .. "/public_ip")
    if stored_ip then stored_ip = stored_ip:match("^%s*(.-)%s*$") end

    if stored_ip == new_ip then return end

    -- first run: just save it
    if not stored_ip then
        log("public IP recorded: %s", new_ip)
        write_file(STATE .. "/public_ip", new_ip)
        return
    end

    -- verify with a second service before notifying
    if not verify_ip_change(new_ip, service) then
        log("public IP change not confirmed (%s reported %s)", service.host, new_ip)
        return
    end

    log("public IP changed: %s -> %s (confirmed)", stored_ip, new_ip)
    write_file(STATE .. "/public_ip", new_ip)

    local contacts = load_contacts()
    for name, contact in pairs(contacts) do
        if name ~= "me" and contact.host then
            http_post(contact.host, contact.port, "/update-address",
                {host = new_ip, port = port, notify = NOTIFY_IP_CHANGE},
                my_name, contact.token)
            log("notified %s of address change", name)
        end
    end
end

-- ============================================================
-- Main
-- ============================================================

local function main()
    os.execute('mkdir -p "' .. INBOX .. '" "' .. OUTBOX .. '" "' .. STATE .. '"')

    local contacts = load_contacts()
    local me = contacts["me"] or {}
    local my_name = me.name or "user"
    local port = tonumber(me.port or 8025)

    log("rmail starting: name=%s port=%d", my_name, port)
    log("mail dir: %s", MAIL)

    local server = assert(socket.bind("0.0.0.0", port))
    server:settimeout(1)
    log("listening on :%d", port)

    -- check for IP change on startup
    pcall(sync_address, my_name, port)

    local interval = 300
    local MIN_INTERVAL = 60
    local last_sync = socket.gettime()

    while true do
        local client = server:accept()
        if client then
            local ok, err = pcall(function()
                local method, path, headers, body = parse_request(client)
                if method == "GET" and path == "/" then
                    send_response(client, 200, {ok = true, name = my_name})
                elseif method == "POST" and body and body ~= "" then
                    local data = json.decode(body)
                    if not auth_check(data) then
                        send_response(client, 403, {error = "forbidden"})
                    elseif path == "/deliver" then
                        local s, r = handle_deliver(data)
                        send_response(client, s, r)
                    elseif path == "/delete" then
                        local s, r = handle_delete(data)
                        send_response(client, s, r)
                    elseif path == "/update-address" then
                        local s, r = handle_update_address(data)
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
