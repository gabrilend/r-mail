#!/usr/bin/env lua
-- rmail - file-based messaging daemon

-- ============================================================
-- Configuration (loaded from ~/.config/rmail/config)
-- ============================================================

local CONFIG_DIR  = (os.getenv("HOME") or "/tmp") .. "/.config/rmail"
local CONFIG_PATH = CONFIG_DIR .. "/config"

local DEFAULT_CONFIG = [[
# rmail configuration

# path to your mailbox directory
mail = ]] .. (os.getenv("HOME") or "/tmp") .. [[/mail

# extra lua libs path (searched before bundled libs/)
# libs = /path/to/lua-libs

# notify contacts when your IP changes
notify_ip_change = true

# use TLS-PSK encryption for all connections
encrypt = false

# script hooks (all called with a temp file path as first argument)

# runs while a received message is still in RAM, before writing to disk
# stdout replaces the message body written to disk
# on_receive_raw = /path/to/on-receive-raw.sh

# runs immediately after a message is written to inbox on disk
# on_receive = /path/to/on-message.sh

# runs immediately after an attachment is written to packages/ on disk
# on_package = /path/to/on-package.sh

# runs before sending a message from outbox (stdout replaces body)
# on_send = /path/to/on-send.sh

# runs when a delete request is received
# on_delete = /path/to/on-delete.sh
]]

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
local PACKAGES = MAIL .. "/packages"

local LIBS             = config.libs
local NOTIFY_IP_CHANGE = config.notify_ip_change ~= false
local ON_RECEIVE_RAW   = config.on_receive_raw
local ON_RECEIVE       = config.on_receive
local ON_PACKAGE       = config.on_package
local ON_SEND          = config.on_send
local ON_DELETE        = config.on_delete
local ENCRYPT          = config.encrypt == true

-- ============================================================

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

local ssl
if ENCRYPT then
    local ok3, _ssl = pcall(require, "ssl")
    if not ok3 then
        io.stderr:write("error: luasec not found (required when encrypt = true in config)\n")
        io.stderr:write("       run: scripts/install-deps.sh\n")
        os.exit(1)
    end
    ssl = _ssl
    if not ssl.config or not ssl.config.capabilities or not ssl.config.capabilities.psk then
        io.stderr:write("error: luasec was not compiled with PSK support\n")
        io.stderr:write("       run: scripts/install-deps.sh\n")
        os.exit(1)
    end
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

local function run_hook(script, data)
    local tmp = os.tmpname()
    write_file(tmp, data)
    local handle = io.popen(script .. " " .. shell_quote(tmp))
    if not handle then
        os.remove(tmp)
        return nil
    end
    local output = handle:read("*a")
    handle:close()
    os.remove(tmp)
    return output
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

local function save_attachments(attachments, sender, inbox_meta)
    if not attachments or #attachments == 0 then return end
    if not inbox_meta.attachments then inbox_meta.attachments = {} end
    for _, att in ipairs(attachments) do
        local att_filename = att.filename
        local target = PACKAGES .. "/" .. att_filename
        if file_exists(target) and not inbox_meta.attachments[att_filename] then
            att_filename = att.filename .. "-from-" .. sender
            target = PACKAGES .. "/" .. att_filename
        end
        local raw = mime.unb64(att.data)
        write_file_binary(target, raw)
        os.execute("chmod 444 " .. shell_quote(target))
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
    local filename = subject
    local target = INBOX .. "/" .. filename
    if file_exists(target) then
        local existing = inbox_state[filename]
        if existing and existing["from"] ~= sender then
            filename = subject .. "-from-" .. sender
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
            if ON_DELETE then
                local content = read_file(INBOX .. "/" .. filename) or ""
                run_hook(ON_DELETE, "from: " .. sender .. "\n" .. content)
            end
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
                    if ON_DELETE then
                        local _, file_body = parse_outbox_file(OUTBOX .. "/" .. filename)
                        run_hook(ON_DELETE, "to: " .. recipient .. "\n" .. (file_body or ""))
                    end
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
                    if ENCRYPT and e.req.psk_identity then
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
                    local hook_input = "to: " .. op.recipient .. "\n" .. (op.body or "")
                    local transformed = run_hook(ON_SEND, hook_input)
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
                if state[op.filename] then
                    state[op.filename].recipients[op.recipient] = nil
                    remove_recipient_from_file(OUTBOX .. "/" .. op.filename, op.recipient)
                    log("notified %s of removal: %s", op.recipient, op.filename)
                    did_work = true
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
                if state[op.filename] and state[op.filename].recipients[op.recipient] then
                    local rmeta = state[op.filename].recipients[op.recipient]
                    if rmeta.attachments then
                        rmeta.attachments[op.attachment_name] = nil
                        if not next(rmeta.attachments) then rmeta.attachments = nil end
                    end
                end
                log("notified %s of attachment removal: %s", op.recipient, op.attachment_name)
                did_work = true
            elseif op.type == "notify_deletion" then
                log("notified %s of deletion: %s", op.recipient, op.filename)
                did_work = true
            end
        end
    end

    -- clean up deleted files from state
    for name in pairs(state) do
        if not current[name] then
            state[name] = nil
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

    -- collect deletion notifications
    local ops = {}
    for name, meta in pairs(state) do
        if not current[name] then
            local sender = meta["from"] or ""
            if contacts[sender] then
                ops[#ops + 1] = {
                    filename = name, sender = sender,
                    message_id = meta.message_id,
                    contact = contacts[sender],
                }
            end
            state[name] = nil
            did_work = true
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
        http_post_batch(requests)
        for _, op in ipairs(ops) do
            log("notified %s of inbox deletion: %s", op.sender, op.filename)
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
    local requests = {}
    local names = {}
    for name, contact in pairs(contacts) do
        if name ~= "me" and contact.host then
            requests[#requests + 1] = {
                host = contact.host, port = contact.port,
                path = "/update-address",
                payload = json.encode({
                    ["from"] = my_name, token = contact.token,
                    host = new_ip, port = port, notify = NOTIFY_IP_CHANGE,
                }),
                psk_identity = my_name, psk_key = contact.token,
            }
            names[#names + 1] = name
        end
    end
    if #requests > 0 then
        http_post_batch(requests)
        for _, name in ipairs(names) do
            log("notified %s of address change", name)
        end
    end
end

-- ============================================================
-- Main
-- ============================================================

local function ensure_config()
    os.execute('mkdir -p "' .. CONFIG_DIR .. '"')
    local f = io.open(CONFIG_PATH, "r")
    if f then
        f:close()
    else
        write_file(CONFIG_PATH, DEFAULT_CONFIG)
        log("created default config: %s", CONFIG_PATH)
    end
    -- symlink in project directory
    os.execute('ln -sf "' .. CONFIG_PATH .. '" "' .. script_dir .. 'config"')
    -- symlink in mail directory (next to contacts)
    os.execute('ln -sf "' .. CONFIG_PATH .. '" "' .. MAIL .. '/config"')
end

local function main()
    os.execute('mkdir -p "' .. INBOX .. '" "' .. OUTBOX .. '" "' .. STATE .. '" "' .. PACKAGES .. '"')
    ensure_config()
    write_file(STATE .. "/new-mail", "")

    local contacts = load_contacts()
    local me = contacts["me"] or {}
    local my_name = me.name or "user"
    local port = tonumber(me.port or 8025)

    log("rmail starting: name=%s port=%d", my_name, port)
    log("mail dir: %s", MAIL)
    if ENCRYPT then log("TLS-PSK encryption enabled") end

    local server_ssl_ctx
    if ENCRYPT then
        server_ssl_ctx = ssl.newcontext({
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
    end

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
        if client and ENCRYPT then
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
