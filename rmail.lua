#!/usr/bin/env lua
-- rmail - file-based messaging daemon

-- ============================================================
-- Configuration (loaded from ~/.config/rmail/config)
-- ============================================================

local CONFIG_PATH = (os.getenv("HOME") or "/tmp") .. "/.config/rmail/config"


local function load_config()
    local f = io.open(CONFIG_PATH, "r")
    if not f then return {} end
    local cfg = {}
    for line in f:lines() do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and line:sub(1, 1) ~= "#" then
            local key, value = line:match("^(%S+)%s*=%s*(.+)$")
            if key and value then
                value = value:match("^(.-)%s*$")
                if value == "true" then value = true
                elseif value == "false" then value = false
                end
                cfg[key] = value
            end
        end
    end
    f:close()
    return cfg
end

local config = load_config()

local MAIL     = config.mail or (os.getenv("HOME") .. "/mail")
local INBOX    = MAIL .. "/inbox"
local OUTBOX   = MAIL .. "/outbox"
local STATE    = MAIL .. "/.state"
local CONTACTS = MAIL .. "/contacts"
local ATTACHMENTS = MAIL .. "/attachments"

local LIBS             = config.libs
local NOTIFY_IP_CHANGE = config.notify_ip_change ~= false
local ON_RECEIVE_RAW   = config.on_receive_raw
local ON_RECEIVE       = config.on_receive
local ON_PACKAGE       = config.on_package
local ON_SEND          = config.on_send
local ON_DELETE        = config.on_delete
local AUTO_PORT_FORWARD  = config.auto_port_forward == true

-- ============================================================

local DEPS_REGISTRY = {
    lua       = {min = "5.1",   max = "5.4.7", default = "5.4.7", required = true,
                 description = "Lua interpreter and headers"},
    luasocket = {min = "3.0.0", max = "3.1.0", default = "3.1.0", required = true,
                 description = "TCP networking for Lua"},
    luasec    = {min = "1.3.2", max = "1.3.2", default = "1.3.2", required = true,
                 description = "TLS-PSK encryption (must compile with -DLSEC_ENABLE_PSK)"},
    openssl   = {min = "1.1.1", max = "3.2.1", default = "3.2.1", required = true,
                 description = "SSL/TLS library (must support PSK ciphers)"},
    dkjson    = {min = "2.5",   max = "2.8",   default = "2.8",   required = true,
                 description = "JSON encoding/decoding"},
    miniupnpc = {min = "2.0",   max = "2.3.3", default = "2.3.3", required = false,
                 description = "UPnP port forwarding (optional)"},
    libnatpmp = {min = "0.0.1", max = "latest", default = "latest", required = false,
                 description = "NAT-PMP port forwarding (optional)"},
}

-- find our own directory for libs/ imports
local script_dir = arg[0]:match("(.*/)") or "./"
if LIBS then
    package.path = LIBS .. "/?.lua;" .. script_dir .. "libs/?.lua;" .. package.path
    package.cpath = LIBS .. "/?.so;" .. script_dir .. "libs/?.so;" .. package.cpath
else
    package.path = script_dir .. "libs/?.lua;" .. package.path
    package.cpath = script_dir .. "libs/?.so;" .. package.cpath
end

local ok, json = pcall(require, "dkjson")
if not ok then
    io.stderr:write("error: dkjson.lua not found.\n")
    io.stderr:write("       place it at: " .. script_dir .. "libs/dkjson.lua\n")
    io.stderr:write("       or set libs in ~/.config/rmail/config to a directory containing it\n")
    os.exit(1)
end

local ok2, socket = pcall(require, "socket")
if not ok2 then
    io.stderr:write("error: luasocket not found.\n")
    io.stderr:write("       install it with your package manager or luarocks:\n")
    io.stderr:write("         luarocks install luasocket\n")
    io.stderr:write("       or set libs in ~/.config/rmail/config to a directory containing it\n")
    os.exit(1)
end

local mime = require("mime")  -- base64 encoding (part of luasocket)

local ok3, ssl = pcall(require, "ssl")
if not ok3 then
    io.stderr:write("error: luasec not found\n")
    io.stderr:write("       run: scripts/install-deps.sh\n")
    os.exit(1)
end
if not ssl.config or not ssl.config.capabilities or not ssl.config.capabilities.psk then
    io.stderr:write("error: luasec was not compiled with PSK support\n")
    io.stderr:write("       run: scripts/install-deps.sh\n")
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

local function read_file_binary(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    return content
end

local function write_file_binary(path, content)
    local f = io.open(path, "wb")
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

local function shell_quote(s)
    return "'" .. s:gsub("'", "'\\''") .. "'"
end

local function run_hook(script, data, ...)
    local args = shell_quote(data)
    for _, extra in ipairs({...}) do
        args = args .. " " .. shell_quote(extra)
    end
    local handle = io.popen(script .. " " .. args)
    if not handle then return nil end
    local output = handle:read("*a")
    handle:close()
    return output
end

local function sanitize_filename(name)
    if not name or name == "" then return "untitled" end
    -- extract basename (strip directory components)
    name = name:match("([^/\\]+)$") or name
    -- remove leading dots (prevent hidden files / .. traversal)
    name = name:gsub("^%.+", "")
    -- replace control characters and problematic chars with underscores
    name = name:gsub("[%c/%\\%z]", "_")
    if name == "" then return "untitled" end
    return name
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
    local text = read_file(CONTACTS)
    if not text or text == "" then return {} end
    local lines = {}
    for line in text:gmatch("[^\n]*\n?") do
        if not line:match("^%s*//") then
            lines[#lines + 1] = line
        end
    end
    return json.decode(table.concat(lines)) or {}
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
-- NAT traversal (automatic port forwarding)
-- ============================================================

-- resolve NAT tool paths: check deps/bin/ first, then system PATH
local function nat_find_tool(name)
    local local_path = script_dir .. "deps/bin/" .. name
    if file_exists(local_path) then return local_path end
    local handle = io.popen('command -v ' .. shell_quote(name) .. ' 2>/dev/null')
    if not handle then return nil end
    local result = handle:read("*a")
    handle:close()
    local path = result and result:match("^%s*(.-)%s*$")
    if path and path ~= "" then return path end
    return nil
end

local UPNPC   = nat_find_tool("upnpc")
local NATPMPC = nat_find_tool("natpmpc")

local function nat_get_local_ip()
    local handle = io.popen("ip route get 1.1.1.1 2>/dev/null")
    if not handle then return nil end
    local output = handle:read("*a")
    handle:close()
    if output then
        local ip = output:match("src%s+(%d+%.%d+%.%d+%.%d+)")
        if ip then return ip end
    end
    -- fallback: first non-loopback inet address
    handle = io.popen("ip -4 addr show 2>/dev/null")
    if not handle then return nil end
    output = handle:read("*a")
    handle:close()
    if output then
        return output:match("inet%s+(%d+%.%d+%.%d+%.%d+).*scope global")
    end
    return nil
end

local function nat_try_upnp_probe()
    if not UPNPC then return false end
    local handle = io.popen(shell_quote(UPNPC) .. " -s 2>/dev/null")
    if not handle then return false end
    local output = handle:read("*a")
    handle:close()
    return output and output:match("Found valid IGD") ~= nil
end

local function nat_try_upnp_add(local_ip, port)
    local cmd = string.format(
        "%s -e %s -a %s %d %d TCP 2>&1",
        shell_quote(UPNPC), shell_quote("rmail"), local_ip, port, port)
    local handle = io.popen(cmd)
    if not handle then return false end
    local output = handle:read("*a")
    handle:close()
    return output and (output:match("is redirected to") ~= nil
        or output:match("successfully") ~= nil)
end

local function nat_try_upnp_delete(port)
    os.execute(string.format("%s -d %d TCP 2>/dev/null", shell_quote(UPNPC), port))
end

local function nat_try_natpmp_probe()
    if not NATPMPC then return false end
    local handle = io.popen(shell_quote(NATPMPC) .. " 2>/dev/null")
    if not handle then return false end
    local output = handle:read("*a")
    handle:close()
    return output and output:match("Public IP") ~= nil
end

local function nat_try_natpmp_add(port, lifetime)
    local cmd = string.format("%s -a %d %d tcp %d 2>&1", shell_quote(NATPMPC), port, port, lifetime)
    local handle = io.popen(cmd)
    if not handle then return false end
    local output = handle:read("*a")
    handle:close()
    return output and output:match("Mapped public port") ~= nil
end

local function nat_try_natpmp_delete(port)
    os.execute(string.format("%s -a %d %d tcp 0 2>/dev/null", shell_quote(NATPMPC), port, port))
end

local function nat_delete_mapping(port, protocol)
    if protocol == "upnp" then
        nat_try_upnp_delete(port)
    elseif protocol == "natpmp" then
        nat_try_natpmp_delete(port)
    end
end

local function nat_cleanup_old_mapping()
    local old = load_state("nat_mapping.json")
    if old and old.protocol and old.port then
        log("cleaning up previous NAT mapping (%s port %d)", old.protocol, old.port)
        nat_delete_mapping(old.port, old.protocol)
    end
end

local function nat_create_mapping(port)
    local local_ip = nat_get_local_ip()

    -- try UPnP first
    if UPNPC and local_ip then
        if nat_try_upnp_add(local_ip, port) then
            local mapping = {protocol = "upnp", port = port, created_at = os.time()}
            save_state("nat_mapping.json", mapping)
            return mapping
        end
    end

    -- try NAT-PMP
    if NATPMPC then
        local lifetime = 3600
        if nat_try_natpmp_add(port, lifetime) then
            local mapping = {protocol = "natpmp", port = port, lifetime = lifetime, created_at = os.time()}
            save_state("nat_mapping.json", mapping)
            return mapping
        end
    end

    return nil
end

local function nat_security_check(my_name)
    -- only warn once
    local warned = read_file(STATE .. "/nat_security_warned")
    if warned and warned ~= "" then return end

    local vulnerabilities = {}

    -- probe UPnP
    if nat_try_upnp_probe() then
        -- confirm by creating and immediately deleting a test mapping
        local test_port = 60000 + (os.time() % 4000)
        local local_ip = nat_get_local_ip()
        if local_ip and nat_try_upnp_add(local_ip, test_port) then
            nat_try_upnp_delete(test_port)
            vulnerabilities[#vulnerabilities + 1] = "UPnP"
        end
    end

    -- probe NAT-PMP
    if nat_try_natpmp_probe() then
        vulnerabilities[#vulnerabilities + 1] = "NAT-PMP"
    end

    if #vulnerabilities == 0 then return end

    local proto_list = table.concat(vulnerabilities, " and ")
    log("WARNING: router has %s enabled -- this is a security risk", proto_list)
    log("WARNING: any device on your network can open ports without authentication")
    log("WARNING: disable %s in your router settings", proto_list)

    -- send warning to all contacts
    local contacts = load_contacts()
    local recipients = {}
    for name, _ in pairs(contacts) do
        if name ~= my_name then
            recipients[#recipients + 1] = name
        end
    end

    if #recipients > 0 then
        local header = ""
        for _, name in ipairs(recipients) do
            header = header .. "to: " .. name .. "\n"
        end
        local body = "WARNING: My router has " .. proto_list .. " enabled. " ..
            "These protocols allow any device on my network to open ports on " ..
            "my router without authentication. This is a known security risk " ..
            "-- malware commonly exploits this to bypass firewalls.\n\n" ..
            "Until I disable these protocols on my router, treat my connection " ..
            "as potentially compromised. Please do not send me sensitive or " ..
            "private information through this system.\n\n" ..
            "Please remind me to fix this.\n\n" ..
            "This is an automated message from rmail's security check."
        write_file(OUTBOX .. "/SECURITY-WARNING-insecure-nat", header .. "\n" .. body)
        log("security warning sent to %d contact(s)", #recipients)
    end

    write_file(STATE .. "/nat_security_warned", os.date("%Y-%m-%d %H:%M:%S") .. "\n")
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
    local max_body = 50 * 1024 * 1024  -- 50 MB
    if length > max_body then
        return method, path, headers, nil
    end
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

local function send_raw_response(client, status, content_type, body, extra_headers)
    local text = ({[200]="OK", [403]="Forbidden", [404]="Not Found"})[status] or "Error"
    local header = "HTTP/1.1 " .. status .. " " .. text .. "\r\n" ..
        "Content-Type: " .. content_type .. "\r\n" ..
        "Content-Length: " .. #body .. "\r\n"
    if extra_headers then
        for k, v in pairs(extra_headers) do
            header = header .. k .. ": " .. v .. "\r\n"
        end
    end
    header = header .. "Connection: close\r\n\r\n"
    client:send(header .. body)
end

local function auth_check(data)
    local sender = data["from"] or ""
    local token = data.token or ""
    local contacts = load_contacts()
    if not contacts[sender] then return false end
    return contacts[sender].token == token
end

local function save_attachments(attachments, sender, inbox_meta)
    if not attachments or #attachments == 0 then return end
    if not inbox_meta.attachments then inbox_meta.attachments = {} end
    for _, att in ipairs(attachments) do
        local att_filename = sanitize_filename(att.filename)
        local target = ATTACHMENTS .. "/" .. att_filename
        if file_exists(target) and not inbox_meta.attachments[att_filename] then
            att_filename = sanitize_filename(att.filename .. "-from-" .. sender)
            target = ATTACHMENTS .. "/" .. att_filename
        end
        local raw = mime.unb64(att.data)
        write_file_binary(target, raw)
        inbox_meta.attachments[att_filename] = {
            attachment_id = att.attachment_id,
            path = target,
        }
        log("attachment saved: %s from %s", att_filename, sender)
        if ON_PACKAGE then
            os.execute(ON_PACKAGE .. " " .. shell_quote(target) .. " &")
        end
    end
end

local function handle_deliver(data, raw_request)
    local sender = data["from"]
    local subject = data.subject or "untitled"
    local message_id = data.message_id or uuid()
    local body = data.body
    local attachments = data.attachments

    local inbox_state = load_state("inbox.json")

    -- check if adding attachments to an existing message
    for filename, meta in pairs(inbox_state) do
        if meta.message_id == message_id and meta["from"] == sender then
            save_attachments(attachments, sender, meta)
            save_state("inbox.json", inbox_state)
            return 200, {ok = true}
        end
    end

    -- new message
    if not body then body = "" end
    local filename = sanitize_filename(subject)
    local target = INBOX .. "/" .. filename
    if file_exists(target) then
        local existing = inbox_state[filename]
        if existing and existing["from"] ~= sender then
            filename = sanitize_filename(subject .. "-from-" .. sender)
            target = INBOX .. "/" .. filename
        end
    end

    if ON_RECEIVE_RAW then
        local transformed = run_hook(ON_RECEIVE_RAW, raw_request)
        if transformed and transformed ~= "" then body = transformed end
    end

    write_file(target, body)
    log("delivered: %s from %s -> %s", message_id, sender, filename)

    if ON_RECEIVE then
        os.execute(ON_RECEIVE .. " " .. shell_quote(target) .. " &")
    end

    inbox_state[filename] = {
        ["from"] = sender,
        message_id = message_id,
        subject = subject,
    }
    save_attachments(attachments, sender, inbox_state[filename])
    save_state("inbox.json", inbox_state)
    return 200, {ok = true, filename = filename}
end

local function delete_inbox_attachments(meta)
    if not meta.attachments then return end
    for aname, ameta in pairs(meta.attachments) do
        if ameta.path and file_exists(ameta.path) then
            os.remove(ameta.path)
            log("deleted attachment: %s", aname)
        end
    end
end

local function handle_delete(data)
    local sender = data["from"]
    local message_id = data.message_id
    local attachment_id = data.attachment_id

    -- attachment-specific deletion
    if attachment_id then
        local inbox_state = load_state("inbox.json")
        for filename, meta in pairs(inbox_state) do
            if meta["from"] == sender and meta.attachments then
                for aname, ameta in pairs(meta.attachments) do
                    if ameta.attachment_id == attachment_id then
                        if ameta.path and file_exists(ameta.path) then
                            os.remove(ameta.path)
                            log("deleted attachment: %s (by sender %s)", aname, sender)
                        end
                        meta.attachments[aname] = nil
                        if not next(meta.attachments) then meta.attachments = nil end
                        save_state("inbox.json", inbox_state)
                        return 200, {ok = true}
                    end
                end
            end
        end
        return 404, {error = "attachment not found"}
    end

    if not message_id then return 404, {error = "missing message_id"} end

    -- sender asking us to delete from our inbox
    local inbox_state = load_state("inbox.json")
    for filename, meta in pairs(inbox_state) do
        if meta.message_id == message_id and meta["from"] == sender then
            if ON_DELETE then run_hook(ON_DELETE, sender) end
            if file_exists(INBOX .. "/" .. filename) then
                os.remove(INBOX .. "/" .. filename)
                log("deleted from inbox: %s (by sender %s)", filename, sender)
            end
            delete_inbox_attachments(meta)
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
                    if ON_DELETE then run_hook(ON_DELETE, recipient) end
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

    local text = read_file(CONTACTS)
    if not text or text == "" then
        return 404, {error = "sender not in contacts"}
    end
    local contacts = json.decode(text) or {}
    if not contacts[sender] then
        return 404, {error = "sender not in contacts"}
    end

    contacts[sender].host = new_host
    if new_port then contacts[sender].port = new_port end
    write_file(CONTACTS, json.encode(contacts, {indent = true}) .. "\n")

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

local function http_send_request(e)
    e.conn:settimeout(3)
    local sent = e.conn:send(
        "POST " .. e.req.path .. " HTTP/1.1\r\n" ..
        "Host: " .. e.req.host .. ":" .. e.req.port .. "\r\n" ..
        "Content-Type: application/json\r\n" ..
        "Content-Length: " .. #e.req.payload .. "\r\n" ..
        "Connection: close\r\n\r\n" ..
        e.req.payload)
    if sent then
        e.phase = "sent"
    else
        e.phase = "done"
        e.conn:close()
    end
end

local function http_read_response(e)
    e.conn:settimeout(3)
    local status_line = e.conn:receive("*l")
    if status_line then
        local status = tonumber(status_line:match("(%d+)"))
        local hdrs = {}
        while true do
            local line = e.conn:receive("*l")
            if not line or line == "" then break end
            local k, v = line:match("^(.-):%s*(.+)$")
            if k then hdrs[k:lower()] = v end
        end
        local resp_body = ""
        local len = tonumber(hdrs["content-length"] or 0)
        if len > 0 then resp_body = e.conn:receive(len) or "" end
        if resp_body ~= "" then
            local ok2, dec = pcall(json.decode, resp_body)
            if ok2 then e.data = dec or {} end
        end
        e.ok = (status == 200)
    end
    e.phase = "done"
    e.conn:close()
end

local function http_start_tls(e, lookup)
    local ctx = ssl.newcontext({
        mode = "client",
        protocol = "tlsv1_2",
        ciphers = "kECDHEPSK+HIGH:kDHEPSK+HIGH:kPSK+HIGH",
        psk = function(hint, max_identity_len, max_psk_len)
            return e.req.psk_identity, e.req.psk_key
        end,
    })
    if not ctx then
        e.phase = "done"
        e.conn:close()
        return
    end
    local old_conn = e.conn
    local ssl_conn = ssl.wrap(old_conn, ctx)
    if not ssl_conn then
        e.phase = "done"
        old_conn:close()
        return
    end
    lookup[old_conn] = nil
    e.conn = ssl_conn
    lookup[ssl_conn] = e
    ssl_conn:settimeout(0)
    local hok, herr = ssl_conn:dohandshake()
    if hok then
        http_send_request(e)
    elseif herr == "wantread" then
        e.phase = "handshaking"
        e.want = "read"
    elseif herr == "wantwrite" then
        e.phase = "handshaking"
        e.want = "write"
    else
        e.phase = "done"
        ssl_conn:close()
    end
end

local function http_retry_handshake(e)
    local hok, herr = e.conn:dohandshake()
    if hok then
        http_send_request(e)
    elseif herr == "wantread" then
        e.want = "read"
    elseif herr == "wantwrite" then
        e.want = "write"
    else
        e.phase = "done"
        e.conn:close()
    end
end

local function http_post_batch(requests)
    if #requests == 0 then return {} end

    local entries = {}
    local lookup = {}

    for i, req in ipairs(requests) do
        local conn = socket.tcp()
        conn:settimeout(0)
        conn:connect(req.host, req.port)
        entries[i] = {
            conn = conn, req = req,
            phase = "connecting",
            ok = false, data = {},
        }
        lookup[conn] = entries[i]
    end

    local deadline = socket.gettime() + 8

    while socket.gettime() < deadline do
        local recvt, sendt = {}, {}
        local any = false

        for _, e in ipairs(entries) do
            if e.phase == "connecting" then
                sendt[#sendt + 1] = e.conn
                any = true
            elseif e.phase == "handshaking" and e.want == "write" then
                sendt[#sendt + 1] = e.conn
                any = true
            elseif e.phase == "handshaking" and e.want == "read" then
                recvt[#recvt + 1] = e.conn
                any = true
            elseif e.phase == "sent" then
                recvt[#recvt + 1] = e.conn
                any = true
            end
        end

        if not any then break end

        local remaining = deadline - socket.gettime()
        if remaining <= 0 then break end

        local readable, writable = socket.select(
            #recvt > 0 and recvt or nil,
            #sendt > 0 and sendt or nil,
            math.min(remaining, 0.5))

        if writable then
            for _, conn in ipairs(writable) do
                local e = lookup[conn]
                if e and e.phase == "connecting" then
                    if e.req.psk_identity then
                        http_start_tls(e, lookup)
                    else
                        http_send_request(e)
                    end
                elseif e and e.phase == "handshaking" then
                    http_retry_handshake(e)
                end
            end
        end

        if readable then
            for _, conn in ipairs(readable) do
                local e = lookup[conn]
                if e and e.phase == "handshaking" then
                    http_retry_handshake(e)
                elseif e and e.phase == "sent" then
                    http_read_response(e)
                end
            end
        end
    end

    local results = {}
    for i, e in ipairs(entries) do
        if e.phase ~= "done" then
            log("timeout connecting to %s:%d", e.req.host, e.req.port)
            e.conn:close()
        end
        results[i] = {ok = e.ok, data = e.data}
    end
    return results
end

local function http_post(host, port, path, data, my_name, token)
    data["from"] = my_name
    data.token = token
    local results = http_post_batch({{
        host = host, port = port, path = path,
        payload = json.encode(data),
        psk_identity = my_name, psk_key = token,
    }})
    return results[1].ok, results[1].data
end

local function parse_outbox_file(path)
    local text = read_file(path)
    if not text then return nil, nil end

    -- collect all header lines (to: and attach:)
    local header_lines = {}
    local pos = 1
    while pos <= #text do
        local line_end = text:find("\n", pos) or #text + 1
        local line = text:sub(pos, line_end - 1)
        local lower = line:lower()
        if lower:match("^to:") or lower:match("^attach:") then
            header_lines[#header_lines + 1] = line
            pos = line_end + 1
        else
            break
        end
    end

    -- build per-recipient entries: each to: gets all attach: lines after it
    local entries = {}
    for i, line in ipairs(header_lines) do
        if line:lower():match("^to:") then
            local name = line:match("^[Tt][Oo]:%s*(.-)%s*$")
            if name and name ~= "" then
                local attachments = {}
                for j = i + 1, #header_lines do
                    if header_lines[j]:lower():match("^attach:") then
                        local fp = header_lines[j]:match("^[Aa][Tt][Tt][Aa][Cc][Hh]:%s*(.-)%s*$")
                        if fp and fp ~= "" then
                            attachments[#attachments + 1] = fp
                        end
                    end
                end
                entries[#entries + 1] = {name = name, attachments = attachments}
            end
        end
    end

    if #entries == 0 then return nil, nil end
    return entries, text:sub(pos)
end

local function remove_recipient_from_file(filepath, recipient)
    local text = read_file(filepath)
    if not text then return 0 end

    -- parse header lines
    local header_lines = {}
    local pos = 1
    while pos <= #text do
        local line_end = text:find("\n", pos) or #text + 1
        local line = text:sub(pos, line_end - 1)
        local lower = line:lower()
        if lower:match("^to:") or lower:match("^attach:") then
            header_lines[#header_lines + 1] = line
            pos = line_end + 1
        else
            break
        end
    end
    local body = text:sub(pos)

    -- remove the matching to: line
    local kept = {}
    for _, line in ipairs(header_lines) do
        if line:lower():match("^to:") then
            local r = line:match("^[Tt][Oo]:%s*(.-)%s*$")
            if r ~= recipient then
                kept[#kept + 1] = line
            end
        else
            kept[#kept + 1] = line
        end
    end

    -- remove orphan attach: lines (no to: above them)
    local cleaned = {}
    local has_to = false
    for _, line in ipairs(kept) do
        if line:lower():match("^to:") then
            has_to = true
            cleaned[#cleaned + 1] = line
        elseif has_to then
            cleaned[#cleaned + 1] = line
        end
    end

    -- count remaining recipients
    local count = 0
    for _, line in ipairs(cleaned) do
        if line:lower():match("^to:") then count = count + 1 end
    end

    if count == 0 then
        os.remove(filepath)
        return 0
    end

    local header = ""
    for _, line in ipairs(cleaned) do
        header = header .. line .. "\n"
    end
    write_file(filepath, header .. body)
    return count
end

local function encode_attachments(filepaths)
    local result = {}
    for _, filepath in ipairs(filepaths) do
        local raw = read_file_binary(filepath)
        if raw then
            result[#result + 1] = {
                filename = filepath:match("([^/]+)$"),
                attachment_id = uuid(),
                data = mime.b64(raw),
            }
        else
            log("attachment not found: %s", filepath)
        end
    end
    return result
end

local function sync_outbox(my_name)
    local contacts = load_contacts()
    local state = load_state("outbox.json")
    local did_work = false

    local current = {}
    for _, name in ipairs(list_files(OUTBOX)) do current[name] = true end

    -- detect contact renames via stored token
    local contact_by_token = {}
    for cname, contact in pairs(contacts) do
        if cname ~= my_name and contact.token then
            contact_by_token[contact.token] = cname
        end
    end
    for fname, fmeta in pairs(state) do
        if fmeta.recipients then
            local renames = {}
            for rname, rmeta in pairs(fmeta.recipients) do
                if rmeta.token and not contacts[rname] then
                    local new_name = contact_by_token[rmeta.token]
                    if new_name and not fmeta.recipients[new_name] then
                        renames[rname] = new_name
                    end
                end
            end
            for old_name, new_name in pairs(renames) do
                fmeta.recipients[new_name] = fmeta.recipients[old_name]
                fmeta.recipients[old_name] = nil
                log("contact renamed: %s -> %s (state migrated for %s)", old_name, new_name, fname)
                did_work = true
            end
        end
    end

    -- Phase 1: collect all pending operations
    local ops = {}

    for name in pairs(current) do
        local entries, body = parse_outbox_file(OUTBOX .. "/" .. name)
        local current_set = {}
        local current_attach = {}  -- name -> {filename -> filepath}
        if entries then
            for _, e in ipairs(entries) do
                current_set[e.name] = true
                local amap = {}
                for _, fp in ipairs(e.attachments) do
                    amap[fp:match("([^/]+)$")] = fp
                end
                current_attach[e.name] = amap
            end
        end

        if not entries and not state[name] then
            log("skipping %s: missing 'to:' header", name)
        else
            if not state[name] then state[name] = {recipients = {}} end

            -- removed recipients (sender deleted a to: line)
            for recipient, rmeta in pairs(state[name].recipients) do
                if not current_set[recipient] then
                    if contacts[recipient] then
                        ops[#ops + 1] = {
                            type = "notify_removal", filename = name,
                            recipient = recipient, message_id = rmeta.message_id,
                            contact = contacts[recipient],
                        }
                    else
                        state[name].recipients[recipient] = nil
                        did_work = true
                    end
                end
            end

            if entries then
                for _, entry in ipairs(entries) do
                    local rname = entry.name
                    if not state[name].recipients[rname] then
                        -- new recipient: deliver message + attachments
                        if contacts[rname] then
                            ops[#ops + 1] = {
                                type = "deliver", filename = name,
                                recipient = rname, message_id = uuid(),
                                subject = name, body = body,
                                contact = contacts[rname],
                                attach_paths = entry.attachments,
                            }
                        else
                            log("skipping %s: unknown contact '%s'", name, rname)
                        end
                    elseif contacts[rname] then
                        -- existing recipient: check attachment changes
                        local rmeta = state[name].recipients[rname]
                        local state_att = rmeta.attachments or {}
                        local cur_att = current_attach[rname] or {}

                        -- new attachments
                        local new_att = {}
                        for fname, fpath in pairs(cur_att) do
                            if not state_att[fname] then
                                new_att[#new_att + 1] = fpath
                            end
                        end
                        if #new_att > 0 then
                            ops[#ops + 1] = {
                                type = "deliver_attachment", filename = name,
                                recipient = rname,
                                message_id = rmeta.message_id,
                                contact = contacts[rname],
                                attach_paths = new_att,
                            }
                        end

                        -- removed attachments
                        for fname, ameta in pairs(state_att) do
                            if not cur_att[fname] then
                                ops[#ops + 1] = {
                                    type = "delete_attachment", filename = name,
                                    recipient = rname,
                                    attachment_name = fname,
                                    attachment_id = ameta.attachment_id,
                                    contact = contacts[rname],
                                }
                            end
                        end
                    end
                end
            end
        end
    end

    -- deleted files
    for name, meta in pairs(state) do
        if not current[name] and meta.recipients then
            for recipient, rmeta in pairs(meta.recipients) do
                if contacts[recipient] then
                    ops[#ops + 1] = {
                        type = "notify_deletion", filename = name,
                        recipient = recipient, message_id = rmeta.message_id,
                        contact = contacts[recipient],
                    }
                end
            end
        end
    end

    -- Phase 2: encode attachments and build requests
    if #ops > 0 then
        local requests = {}
        for i, op in ipairs(ops) do
            local path, data
            if op.type == "deliver" then
                path = "/deliver"
                local send_body = op.body
                if ON_SEND then
                    local transformed = run_hook(ON_SEND, op.body or "", op.recipient)
                    if transformed and transformed ~= "" then send_body = transformed end
                end
                local encoded = encode_attachments(op.attach_paths or {})
                data = {["from"] = my_name, token = op.contact.token,
                        subject = op.subject, message_id = op.message_id, body = send_body}
                if #encoded > 0 then data.attachments = encoded end
                op.encoded_attachments = encoded
            elseif op.type == "deliver_attachment" then
                path = "/deliver"
                local encoded = encode_attachments(op.attach_paths or {})
                data = {["from"] = my_name, token = op.contact.token,
                        message_id = op.message_id, attachments = encoded}
                op.encoded_attachments = encoded
            elseif op.type == "delete_attachment" then
                path = "/delete"
                data = {["from"] = my_name, token = op.contact.token,
                        attachment_id = op.attachment_id}
            else
                path = "/delete"
                data = {["from"] = my_name, token = op.contact.token,
                        message_id = op.message_id}
            end
            requests[i] = {
                host = op.contact.host, port = op.contact.port,
                path = path, payload = json.encode(data),
                psk_identity = my_name, psk_key = op.contact.token,
            }
        end

        local results = http_post_batch(requests)

        -- Phase 3: process results
        for i, op in ipairs(ops) do
            if op.type == "notify_removal" then
                if results[i].ok then
                    if state[op.filename] then
                        state[op.filename].recipients[op.recipient] = nil
                        remove_recipient_from_file(OUTBOX .. "/" .. op.filename, op.recipient)
                        log("notified %s of removal: %s", op.recipient, op.filename)
                        did_work = true
                    end
                else
                    log("failed to notify %s of removal: %s (will retry)", op.recipient, op.filename)
                end
            elseif op.type == "deliver" then
                if results[i].ok then
                    if state[op.filename] then
                        local att_state = {}
                        for _, att in ipairs(op.encoded_attachments or {}) do
                            att_state[att.filename] = {attachment_id = att.attachment_id}
                        end
                        state[op.filename].recipients[op.recipient] = {
                            message_id = op.message_id,
                            attachments = next(att_state) and att_state or nil,
                            token = op.contact.token,
                        }
                    end
                    log("sent: %s -> %s", op.filename, op.recipient)
                    did_work = true
                else
                    log("failed to send %s to %s", op.filename, op.recipient)
                end
            elseif op.type == "deliver_attachment" then
                if results[i].ok then
                    if state[op.filename] and state[op.filename].recipients[op.recipient] then
                        local rmeta = state[op.filename].recipients[op.recipient]
                        if not rmeta.attachments then rmeta.attachments = {} end
                        for _, att in ipairs(op.encoded_attachments or {}) do
                            rmeta.attachments[att.filename] = {attachment_id = att.attachment_id}
                        end
                    end
                    log("sent attachments to %s: %s", op.recipient, op.filename)
                    did_work = true
                end
            elseif op.type == "delete_attachment" then
                if results[i].ok then
                    if state[op.filename] and state[op.filename].recipients[op.recipient] then
                        local rmeta = state[op.filename].recipients[op.recipient]
                        if rmeta.attachments then
                            rmeta.attachments[op.attachment_name] = nil
                            if not next(rmeta.attachments) then rmeta.attachments = nil end
                        end
                    end
                    log("notified %s of attachment removal: %s", op.recipient, op.attachment_name)
                    did_work = true
                else
                    log("failed to notify %s of attachment removal: %s (will retry)", op.recipient, op.attachment_name)
                end
            elseif op.type == "notify_deletion" then
                if results[i].ok then
                    if state[op.filename] and state[op.filename].recipients then
                        state[op.filename].recipients[op.recipient] = nil
                    end
                    log("notified %s of deletion: %s", op.recipient, op.filename)
                    did_work = true
                else
                    log("failed to notify %s of deletion: %s (will retry)", op.recipient, op.filename)
                end
            end
        end
    end

    -- clean up deleted files from state (only when all recipients notified)
    for name in pairs(state) do
        if not current[name] then
            if not state[name].recipients or not next(state[name].recipients) then
                state[name] = nil
            end
        end
    end

    -- clean up files with no recipients left
    for name in pairs(current) do
        if state[name] and not next(state[name].recipients) then
            os.remove(OUTBOX .. "/" .. name)
            log("cleaned up %s: no recipients left", name)
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

    -- collect deletion notifications (newly missing files + pending retries)
    local ops = {}
    for name, meta in pairs(state) do
        if not current[name] then
            if not meta.pending_delete then
                -- first time: clean up local attachments, mark pending
                delete_inbox_attachments(meta)
                if ON_DELETE then run_hook(ON_DELETE, meta["from"] or "") end
                meta.pending_delete = true
                did_work = true
            end
            local sender = meta["from"] or ""
            if contacts[sender] then
                ops[#ops + 1] = {
                    filename = name, sender = sender,
                    message_id = meta.message_id,
                    contact = contacts[sender],
                }
            else
                -- sender not in contacts, can't notify, just drop
                state[name] = nil
                did_work = true
            end
        end
    end

    -- batch execute
    if #ops > 0 then
        local requests = {}
        for i, op in ipairs(ops) do
            requests[i] = {
                host = op.contact.host, port = op.contact.port,
                path = "/delete",
                payload = json.encode({
                    ["from"] = my_name, token = op.contact.token,
                    message_id = op.message_id,
                }),
                psk_identity = my_name, psk_key = op.contact.token,
            }
        end
        local results = http_post_batch(requests)
        for i, op in ipairs(ops) do
            if results[i].ok then
                state[op.filename] = nil
                log("notified %s of inbox deletion: %s", op.sender, op.filename)
                did_work = true
            else
                log("failed to notify %s of inbox deletion: %s (will retry)", op.sender, op.filename)
            end
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

local function detect_ip_change(my_name, port)
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

    -- write pending notifications for all contacts
    local contacts = load_contacts()
    local pending = load_state("pending-address.json")
    for name, contact in pairs(contacts) do
        if name ~= my_name and contact.host then
            pending[name] = {host = new_ip, port = port}
        end
    end
    save_state("pending-address.json", pending)
end

local function sync_address_notifications(my_name)
    local pending = load_state("pending-address.json")
    if not next(pending) then return false end

    local contacts = load_contacts()
    local ops = {}

    for name, info in pairs(pending) do
        if contacts[name] and contacts[name].host then
            ops[#ops + 1] = {
                name = name, contact = contacts[name],
                host = info.host, port = info.port,
            }
        else
            -- contact removed, drop the pending notification
            pending[name] = nil
        end
    end

    if #ops == 0 then
        save_state("pending-address.json", pending)
        return false
    end

    local requests = {}
    for i, op in ipairs(ops) do
        requests[i] = {
            host = op.contact.host, port = op.contact.port,
            path = "/update-address",
            payload = json.encode({
                ["from"] = my_name, token = op.contact.token,
                host = op.host, port = op.port, notify = NOTIFY_IP_CHANGE,
            }),
            psk_identity = my_name, psk_key = op.contact.token,
        }
    end

    local results = http_post_batch(requests)
    local did_work = false
    for i, op in ipairs(ops) do
        if results[i].ok then
            pending[op.name] = nil
            log("notified %s of address change", op.name)
            did_work = true
        else
            log("failed to notify %s of address change (will retry)", op.name)
        end
    end

    save_state("pending-address.json", pending)
    return did_work
end

-- ============================================================
-- Main
-- ============================================================

local function main()
    os.execute('mkdir -p "' .. INBOX .. '" "' .. OUTBOX .. '" "' .. STATE .. '" "' .. ATTACHMENTS .. '"')
    write_file(STATE .. "/new-mail", "")

    if not config.name then
        io.stderr:write("error: 'name' is not set in " .. CONFIG_PATH .. "\n")
        os.exit(1)
    end
    local contacts = load_contacts()
    local my_name = config.name
    local port = tonumber(config.port or 8025)

    log("rmail starting: name=%s port=%d", my_name, port)
    log("mail dir: %s", MAIL)
    log("TLS-PSK encryption enabled")

    -- NAT: clean up stale mapping from previous run
    pcall(nat_cleanup_old_mapping)

    -- NAT: security check (always runs on startup)
    pcall(nat_security_check, my_name)

    -- NAT: auto port forwarding (opt-in)
    local nat_mapping = nil
    if AUTO_PORT_FORWARD then
        log("attempting automatic port forwarding...")
        local ok_nat, result = pcall(nat_create_mapping, port)
        if ok_nat and result and result.protocol then
            nat_mapping = result
            log("port %d mapped via %s", port, result.protocol)
        else
            log("warning: auto port forward failed, port %d may not be reachable", port)
        end
    end

    local server_ssl_ctx = ssl.newcontext({
        mode = "server",
        protocol = "tlsv1_2",
        ciphers = "kECDHEPSK+HIGH:kDHEPSK+HIGH:kPSK+HIGH",
        psk = function(identity, max_psk_len)
            local c = load_contacts()
            if c[identity] and c[identity].token then
                return c[identity].token
            end
            return nil
        end,
    })
    if not server_ssl_ctx then
        log("error: failed to create TLS context")
        os.exit(1)
    end

    local server = assert(socket.bind("0.0.0.0", port))
    server:settimeout(1)
    log("listening on :%d", port)

    -- check for IP change on startup
    pcall(detect_ip_change, my_name, port)

    local interval = 300
    local MIN_INTERVAL = 60
    local last_sync = socket.gettime()

    while true do
        local client = server:accept()
        if client then
            local ssl_client = ssl.wrap(client, server_ssl_ctx)
            if ssl_client then
                ssl_client:settimeout(5)
                local hok, herr = ssl_client:dohandshake()
                if hok then
                    client = ssl_client
                else
                    log("TLS handshake failed: %s", tostring(herr))
                    ssl_client:close()
                    client = nil
                end
            else
                log("TLS wrap failed")
                client:close()
                client = nil
            end
        end
        if client then
            local ok, err = pcall(function()
                local method, path, headers, body = parse_request(client)
                if method == "GET" and path == "/" then
                    send_response(client, 200, {ok = true, name = my_name})
                elseif method == "GET" and path == "/deps" then
                    send_response(client, 200, {deps = DEPS_REGISTRY})
                elseif method == "GET" and path:match("^/deps/(.+)$") then
                    local dep_name = path:match("^/deps/(.+)$")
                    if DEPS_REGISTRY[dep_name] then
                        send_response(client, 200, DEPS_REGISTRY[dep_name])
                    else
                        send_response(client, 404, {error = "unknown dependency: " .. dep_name})
                    end
                elseif method == "GET" and path == "/install-script" then
                    local script_path = script_dir .. "scripts/install-deps.sh"
                    local f = io.open(script_path, "r")
                    if f then
                        local content = f:read("*a")
                        f:close()
                        local hash_handle = io.popen("sha256sum '" .. script_path:gsub("'", "'\\''") .. "'")
                        local sha256 = ""
                        if hash_handle then
                            sha256 = (hash_handle:read("*a") or ""):match("^(%x+)") or ""
                            hash_handle:close()
                        end
                        send_raw_response(client, 200, "application/x-shellscript", content, {["X-SHA256"] = sha256})
                    else
                        send_response(client, 404, {error = "install script not found"})
                    end
                elseif method == "POST" and body and body ~= "" then
                    local data = json.decode(body)
                    if not auth_check(data) then
                        send_response(client, 403, {error = "forbidden"})
                    elseif path == "/deliver" then
                        local s, r = handle_deliver(data, body)
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
                local w3 = sync_address_notifications(my_name)
                if w1 or w2 or w3 then
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

        -- NAT: renew mapping periodically (every 30 minutes)
        if nat_mapping then
            local nat_renew_interval = 1800
            if now - (nat_mapping.last_renewed or nat_mapping.created_at) >= nat_renew_interval then
                local ok_r, res = pcall(nat_create_mapping, port)
                if ok_r and res then
                    log("renewed NAT mapping via %s", res.protocol)
                end
                nat_mapping.last_renewed = now
            end
        end
    end
end

main()
