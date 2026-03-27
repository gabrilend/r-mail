#!/usr/bin/env lua
-- rmail - file-based messaging daemon

-- ============================================================
-- Configuration
-- ============================================================

-- Resolve the mail directory from the command-line argument.
-- Usage: lua rmail.lua /path/to/mailbox
local MAIL_ARG = arg and arg[1]
if not MAIL_ARG or MAIL_ARG == "" then
    io.stderr:write("usage: rmail.lua <mailbox-directory>\n")
    io.stderr:write("  e.g. lua rmail.lua ~/mail\n")
    os.exit(1)
end
-- expand ~ to HOME
MAIL_ARG = MAIL_ARG:gsub("^~", os.getenv("HOME") or "/tmp")
-- strip trailing slashes
MAIL_ARG = MAIL_ARG:gsub("/+$", "")

-- Find config file:
-- 1. Symlink at <mailbox>/config (preferred — survives renames)
-- 2. Derived path: ~/.config/rmail/config-<path-with-dashes>
-- 3. Error out
local function find_config_path(mail_dir)
    -- try symlink/file in the mailbox directory
    local symlink_path = mail_dir .. "/config"
    local f = io.open(symlink_path, "r")
    if f then f:close(); return symlink_path end
    -- derive from mail directory path: /home/ritz/mail -> config-home-ritz-mail
    local slug = mail_dir:gsub("^/", ""):gsub("/", "-")
    local derived = (os.getenv("HOME") or "/tmp") .. "/.config/rmail/config-" .. slug
    f = io.open(derived, "r")
    if f then f:close(); return derived end
    return nil
end

local CONFIG_PATH = find_config_path(MAIL_ARG)
if not CONFIG_PATH then
    io.stderr:write("error: no config file found\n")
    io.stderr:write("  looked for: " .. MAIL_ARG .. "/config (symlink)\n")
    local slug = MAIL_ARG:gsub("^/", ""):gsub("/", "-")
    io.stderr:write("  looked for: ~/.config/rmail/config-" .. slug .. "\n")
    io.stderr:write("  run scripts/install.sh to create one\n")
    os.exit(1)
end

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

-- Consolidated path constants (reduces upvalue count for Lua/LuaJIT 60-upvalue limit)
local MAIL = MAIL_ARG
local paths = {
    inbox       = MAIL .. "/inbox",
    outbox      = MAIL .. "/outbox",
    state       = MAIL .. "/.state",
    contacts    = MAIL .. "/contacts",
    attachments = config.attachments or (MAIL .. "/attachments"),
    pending     = config.attachment_pending_dir or "/tmp",
    transfers   = MAIL .. "/transfers",
}
paths.uploads = paths.attachments .. "/.uploads"

-- Consolidated config flags
local cfg = {
    chunk_size        = tonumber(config.attachment_chunk_size) or 5242880,
    allow_peer_addr   = config.allow_peer_address_requests ~= false,
    libs              = config.libs,
    notify_ip_change  = config.notify_ip_change ~= false,
    auto_port_forward = config.auto_port_forward == true,
}

-- Hook scripts
local hooks = {
    on_receive_raw = config.on_receive_raw,
    on_receive     = config.on_receive,
    on_package     = config.on_package,
    on_send        = config.on_send,
    on_delete      = config.on_delete,
}

-- Aliases for frequently-used paths (reduces table lookups in hot paths)
local INBOX    = paths.inbox
local OUTBOX   = paths.outbox
local STATE    = paths.state
local CONTACTS = paths.contacts

-- ============================================================

local DEPS_REGISTRY = {
    lua       = {min = "5.1",   max = "5.4.7", default = "5.4.7", required = true,
                 description = "Lua interpreter and headers"},
    luasocket = {min = "3.0.0", max = "3.1.0", default = "3.1.0", required = true,
                 description = "TCP networking for Lua"},
    openssl   = {min = "1.1.1", max = "3.2.1", default = "3.2.1", required = true,
                 description = "AES-256-GCM encryption via rmail_crypto.so"},
    dkjson    = {min = "2.5",   max = "2.8",   default = "2.8",   required = true,
                 description = "JSON encoding/decoding"},
    miniupnpc = {min = "2.0",   max = "2.3.3", default = "2.3.3", required = false,
                 description = "UPnP port forwarding (optional)"},
    libnatpmp = {min = "0.0.1", max = "latest", default = "latest", required = false,
                 description = "NAT-PMP port forwarding (optional)"},
}

-- find our own directory for libs/ imports
local script_dir = arg[0]:match("(.*/)") or "./"
if cfg.libs then
    package.path = cfg.libs .. "/?.lua;" .. script_dir .. "libs/?.lua;" .. package.path
    package.cpath = cfg.libs .. "/?.so;" .. script_dir .. "libs/?.so;" .. package.cpath
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
    io.stderr:write("       " .. tostring(socket) .. "\n")
    io.stderr:write("       run: scripts/install.sh\n")
    os.exit(1)
end

local mime = require("mime")  -- base64 encoding (part of luasocket)

local ok3, crypto = pcall(require, "rmail_crypto")
if not ok3 then
    io.stderr:write("error: rmail_crypto.so not found\n")
    io.stderr:write("       " .. tostring(crypto) .. "\n")
    io.stderr:write("       run: scripts/install.sh\n")
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

-- {{{ expand_tilde
-- Expand ~ at the start of a path to the user's home directory.
-- ~/foo becomes /home/user/foo. Paths not starting with ~ are unchanged.
local function expand_tilde(path)
    if path:sub(1, 1) == "~" then
        local home = os.getenv("HOME")
        if home then
            return home .. path:sub(2)
        end
    end
    return path
end
-- }}}

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

    -- migrate legacy JSON format transparently
    if text:match("^%s*{") then
        local old = json.decode(text)
        if old then
            log("migrating contacts file from JSON to new format")
            local new_lines = {"// rmail contacts", ""}
            for name, c in pairs(old) do
                local ip_val = c.ip or c.host
                if ip_val then
                    new_lines[#new_lines+1] = name .. ".ip    = " .. ip_val
                end
                if c.port then
                    new_lines[#new_lines+1] = name .. ".port  = " .. tostring(c.port)
                end
                if c.token then
                    new_lines[#new_lines+1] = name .. '.token = "' .. c.token .. '"'
                end
                new_lines[#new_lines+1] = ""
            end
            text = table.concat(new_lines, "\n") .. "\n"
            write_file(CONTACTS, text)
        end
    end

    local contacts = {}
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and not line:match("^[/#]") then
            local name, field, value = line:match("^([%w_%-]+)%.([%w_%-]+)%s*=%s*(.+)$")
            if name and field and value then
                value = value:match("^%s*(.-)%s*$")
                local unquoted = value:match('^"(.*)"$')
                if unquoted then value = unquoted end
                if not contacts[name] then contacts[name] = {} end
                contacts[name][field] = value
            else
                -- bare name line: create empty entry as a placeholder
                local bare = line:match("^([%w_%-]+)$")
                if bare and not contacts[bare] then contacts[bare] = {} end
            end
        end
    end
    return contacts
end

-- write or update specific fields for one contact in the contacts file,
-- preserving all comments, blank lines, and other contacts untouched
local function write_contact_fields(name, fields)
    local text = read_file(CONTACTS) or ""
    local lines = {}
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        lines[#lines + 1] = line
    end

    local last_idx = 0
    local replaced = {}
    for i, line in ipairs(lines) do
        local lname, lfield = line:match("^([%w_%-]+)%.([%w_%-]+)%s*=")
        if lname == name then
            last_idx = i
            if fields[lfield] ~= nil then
                local v = tostring(fields[lfield])
                if v:match("[^%d%.]") then v = '"' .. v .. '"' end
                lines[i] = name .. "." .. lfield .. " = " .. v
                replaced[lfield] = true
            end
        end
    end

    -- append any fields that had no existing line
    local insert_pos = last_idx > 0 and last_idx or #lines
    local additions = {}
    for field, value in pairs(fields) do
        if not replaced[field] and value ~= nil then
            local v = tostring(value)
            if v:match("[^%d%.]") then v = '"' .. v .. '"' end
            additions[#additions + 1] = name .. "." .. field .. " = " .. v
        end
    end
    for j = #additions, 1, -1 do
        table.insert(lines, insert_pos + 1, additions[j])
    end

    write_file(CONTACTS, table.concat(lines, "\n") .. "\n")
end

-- align the = signs within each contact's block; run once at startup
local function align_contacts()
    local text = read_file(CONTACTS)
    if not text then return end

    local lines = {}
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        lines[#lines + 1] = line
    end

    local result = {}
    local i = 1
    while i <= #lines do
        local name = lines[i]:match("^([%w_%-]+)%.")
        if name then
            -- collect all consecutive lines for this contact
            local block, j = {}, i
            while j <= #lines and lines[j]:match("^([%w_%-]+)%.") == name do
                block[#block + 1] = lines[j]
                j = j + 1
            end
            -- find max key length (everything before the =)
            local max_pre = 0
            for _, bline in ipairs(block) do
                local pre = bline:match("^(.-)%s*=")
                if pre then max_pre = math.max(max_pre, #pre) end
            end
            -- reformat with aligned =
            for _, bline in ipairs(block) do
                local pre, val = bline:match("^(.-)%s*=%s*(.+)$")
                if pre and val then
                    result[#result + 1] = pre .. string.rep(" ", max_pre - #pre) .. " = " .. val
                else
                    result[#result + 1] = bline
                end
            end
            i = j
        else
            result[#result + 1] = lines[i]
            i = i + 1
        end
    end

    local new_text = table.concat(result, "\n")
    if new_text ~= text then write_file(CONTACTS, new_text) end
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
-- Consolidated NAT/tools module (reduces upvalue count for Lua/LuaJIT 60-upvalue limit)
local nat = {}

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

local tools = {
    upnpc   = nat_find_tool("upnpc"),
    natpmpc = nat_find_tool("natpmpc"),
    zip     = nat_find_tool("zip"),
    unzip   = nat_find_tool("unzip"),
}

function nat.get_local_ip()
    -- Try common paths for 'ip' command (NixOS, standard Linux, etc.)
    local ip_paths = {
        "/run/current-system/sw/bin/ip",  -- NixOS
        "/usr/sbin/ip",
        "/sbin/ip",
        "/usr/bin/ip",
        "/bin/ip",
        "ip",  -- fallback to PATH
    }
    local ip_cmd = nil
    for _, path in ipairs(ip_paths) do
        local f = io.open(path, "r")
        if f then f:close(); ip_cmd = path; break end
    end
    if not ip_cmd then ip_cmd = "ip" end  -- hope it's in PATH

    local handle = io.popen(ip_cmd .. " route get 1.1.1.1 2>/dev/null")
    if not handle then return nil end
    local output = handle:read("*a")
    handle:close()
    if output then
        local ip = output:match("src%s+(%d+%.%d+%.%d+%.%d+)")
        if ip then return ip end
    end
    handle = io.popen(ip_cmd .. " -4 addr show 2>/dev/null")
    if not handle then return nil end
    output = handle:read("*a")
    handle:close()
    if output then
        return output:match("inet%s+(%d+%.%d+%.%d+%.%d+).*scope global")
    end
    return nil
end

function nat.try_upnp_probe()
    if not tools.upnpc then return false end
    local handle = io.popen(shell_quote(tools.upnpc) .. " -s 2>/dev/null")
    if not handle then return false end
    local output = handle:read("*a")
    handle:close()
    return output and output:match("Found valid IGD") ~= nil
end

function nat.try_upnp_add(local_ip, port)
    local cmd = string.format(
        "%s -e %s -a %s %d %d TCP 2>&1",
        shell_quote(tools.upnpc), shell_quote("rmail"), local_ip, port, port)
    local handle = io.popen(cmd)
    if not handle then return false end
    local output = handle:read("*a")
    handle:close()
    return output and (output:match("is redirected to") ~= nil
        or output:match("successfully") ~= nil)
end

function nat.try_upnp_delete(port)
    os.execute(string.format("%s -d %d TCP 2>/dev/null", shell_quote(tools.upnpc), port))
end

function nat.try_natpmp_probe()
    if not tools.natpmpc then return false end
    local handle = io.popen(shell_quote(tools.natpmpc) .. " 2>/dev/null")
    if not handle then return false end
    local output = handle:read("*a")
    handle:close()
    return output and output:match("Public IP") ~= nil
end

function nat.try_natpmp_add(port, lifetime)
    local cmd = string.format("%s -a %d %d tcp %d 2>&1", shell_quote(tools.natpmpc), port, port, lifetime)
    local handle = io.popen(cmd)
    if not handle then return false end
    local output = handle:read("*a")
    handle:close()
    return output and output:match("Mapped public port") ~= nil
end

function nat.try_natpmp_delete(port)
    os.execute(string.format("%s -a %d %d tcp 0 2>/dev/null", shell_quote(tools.natpmpc), port, port))
end

function nat.delete_mapping(port, protocol)
    if protocol == "upnp" then
        nat.try_upnp_delete(port)
    elseif protocol == "natpmp" then
        nat.try_natpmp_delete(port)
    end
end

function nat.cleanup_old_mapping()
    local old = load_state("nat_mapping.json")
    if old and old.protocol and old.port then
        log("cleaning up previous NAT mapping (%s port %d)", old.protocol, old.port)
        nat.delete_mapping(old.port, old.protocol)
    end
end

function nat.create_mapping(port)
    local local_ip = nat.get_local_ip()

    -- try UPnP first
    if tools.upnpc and local_ip then
        if nat.try_upnp_add(local_ip, port) then
            local mapping = {protocol = "upnp", port = port, created_at = os.time()}
            save_state("nat_mapping.json", mapping)
            return mapping
        end
    end

    -- try NAT-PMP
    if tools.natpmpc then
        local lifetime = 3600
        if nat.try_natpmp_add(port, lifetime) then
            local mapping = {protocol = "natpmp", port = port, lifetime = lifetime, created_at = os.time()}
            save_state("nat_mapping.json", mapping)
            return mapping
        end
    end

    return nil
end

function nat.security_check(my_name)
    local warned = load_state("nat_security_warned.json")
    if type(warned) ~= "table" then warned = {} end

    local vulnerabilities = {}

    -- probe UPnP
    if nat.try_upnp_probe() then
        local test_port = 60000 + (os.time() % 4000)
        local local_ip = nat.get_local_ip()
        if local_ip and nat.try_upnp_add(local_ip, test_port) then
            nat.try_upnp_delete(test_port)
            vulnerabilities[#vulnerabilities + 1] = "UPnP"
        end
    end

    -- probe NAT-PMP
    if nat.try_natpmp_probe() then
        vulnerabilities[#vulnerabilities + 1] = "NAT-PMP"
    end

    -- if no longer vulnerable but we previously were, send "fixed" notice
    if #vulnerabilities == 0 then
        if file_exists(STATE .. "/nat_security_vulnerability_active") then
            local contacts = load_contacts()
            local recipients = {}
            for name, _ in pairs(contacts) do
                if name ~= my_name and warned[name] then
                    recipients[#recipients + 1] = name
                end
            end
            if #recipients > 0 then
                local header = ""
                for _, name in ipairs(recipients) do
                    header = header .. "to: " .. name .. "\n"
                end
                local body = "RESOLVED: My router's insecure protocols (UPnP/NAT-PMP) " ..
                    "have been disabled. The security risk I warned you about earlier " ..
                    "has been addressed. You can resume sending sensitive information " ..
                    "through this system.\n\n" ..
                    "This is an automated message from rmail's security check."
                write_file(OUTBOX .. "/SECURITY-RESOLVED-nat-fixed", header .. "\n" .. body)
                log("security resolved notice sent to %d contact(s)", #recipients)
            end
            os.remove(STATE .. "/nat_security_vulnerability_active")
            -- reset warned set so new vulnerability triggers fresh warnings
            warned = {}
            save_state("nat_security_warned.json", warned)
        end
        return
    end

    local proto_list = table.concat(vulnerabilities, " and ")
    log("WARNING: router has %s enabled -- this is a security risk", proto_list)
    log("WARNING: any device on your network can open ports without authentication")
    log("WARNING: disable %s in your router settings", proto_list)

    -- mark vulnerability as active
    write_file(STATE .. "/nat_security_vulnerability_active", os.date("%Y-%m-%d %H:%M:%S") .. "\n")

    -- send warning to contacts not yet warned
    local contacts = load_contacts()
    local recipients = {}
    for name, _ in pairs(contacts) do
        if name ~= my_name and not warned[name] then
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
        log("security warning sent to %d new contact(s)", #recipients)
        -- record that these contacts were warned
        local timestamp = os.date("%Y-%m-%d %H:%M:%S")
        for _, name in ipairs(recipients) do
            warned[name] = timestamp
        end
        save_state("nat_security_warned.json", warned)
    end
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


local function save_attachments(attachments, sender, inbox_meta)
    if not attachments or #attachments == 0 then return end
    if not inbox_meta.attachments then inbox_meta.attachments = {} end
    for _, att in ipairs(attachments) do
        local att_filename = sanitize_filename(att.filename)
        local target = paths.attachments .. "/" .. att_filename
        if file_exists(target) and not inbox_meta.attachments[att_filename] then
            att_filename = sanitize_filename(att.filename .. "-from-" .. sender)
            target = paths.attachments .. "/" .. att_filename
        end
        local raw = mime.unb64(att.data)
        write_file_binary(target, raw)
        inbox_meta.attachments[att_filename] = {
            attachment_id = att.attachment_id,
            path = target,
        }
        log("attachment saved: %s from %s", att_filename, sender)
        if hooks.on_package then
            os.execute(hooks.on_package .. " " ..
                shell_quote(sender) .. " " .. shell_quote(att_filename) .. " " ..
                shell_quote(target) .. " &")
        end
    end
end

local function handle_deliver_message(data, sender)
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

    if hooks.on_receive_raw then
        local transformed = run_hook(hooks.on_receive_raw, sender, subject, body or "")
        if transformed and transformed ~= "" then body = transformed end
    end

    body = body:gsub("^[\n\r]+", "")
    write_file(target, body)
    log("delivered: %s from %s -> %s", message_id, sender, filename)

    if hooks.on_receive then
        os.execute(hooks.on_receive .. " " ..
            shell_quote(sender) .. " " .. shell_quote(subject) .. " " ..
            shell_quote(target) .. " &")
    end

    inbox_state[filename] = {
        ["from"] = sender,
        message_id = message_id,
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

-- delete a zip if no other active transfer still references it
local function release_zip(chunks, zip_id, compressed_path)
    for _, t in pairs(chunks) do
        if t.zip_id == zip_id then return end  -- still in use
    end
    if compressed_path and file_exists(compressed_path) then
        os.remove(compressed_path)
        log("deleted shared zip %s (no more recipients)", zip_id)
    end
end

-- {{{ remove_recipient_from_file
-- Remove a recipient's to: line from an outbox file.
-- Also removes orphan attach: lines that no longer have a to: above them.
-- Returns the count of remaining recipients (0 if file was deleted).
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
-- }}}

local function handle_delete(data, sender)
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
            if hooks.on_delete then run_hook(hooks.on_delete, sender) end
            if file_exists(INBOX .. "/" .. filename) then
                os.remove(INBOX .. "/" .. filename)
                log("deleted from inbox: %s (by sender %s)", filename, sender)
            end
            delete_inbox_attachments(meta)
            inbox_state[filename] = nil
            save_state("inbox.json", inbox_state)
            -- cancel any pending consent or in-progress chunks from this sender for this message
            local cpending = load_state("consent-pending.json")
            local cp_changed = false
            for att_id, entry in pairs(cpending) do
                if entry["from"] == sender and entry.message_id == message_id then
                    local consent_path = INBOX .. "/" .. entry.inbox_file
                    if file_exists(consent_path) then os.remove(consent_path) end
                    os.execute('rm -rf ' .. shell_quote(
                        paths.pending .. "/.pending/" .. att_id))
                    cpending[att_id] = nil
                    cp_changed = true
                    log("cancelled consent for %s from %s (sender deleted)", att_id, sender)
                end
            end
            if cp_changed then save_state("consent-pending.json", cpending) end
            return 200, {ok = true}
        end
    end

    -- recipient telling us they deleted something we sent
    local outbox_state = load_state("outbox.json")
    for filename, meta in pairs(outbox_state) do
        if meta.recipients then
            for recipient, rmeta in pairs(meta.recipients) do
                if rmeta.message_id == message_id and recipient == sender then
                    if hooks.on_delete then run_hook(hooks.on_delete, recipient) end
                    meta.recipients[recipient] = nil
                    local remaining = remove_recipient_from_file(OUTBOX .. "/" .. filename, recipient)
                    log("removed recipient %s from %s (they deleted)", recipient, filename)
                    if not next(meta.recipients) then
                        outbox_state[filename] = nil
                    end
                    save_state("outbox.json", outbox_state)
                    -- cancel any outgoing chunk transfers to this recipient for this message
                    local att_state = load_state("chunks-outgoing.json")
                    local att_changed = false
                    for att_id, transfer in pairs(att_state) do
                        if transfer.to == sender and transfer.message_id == message_id then
                            att_state[att_id] = nil
                            release_zip(att_state, transfer.zip_id, transfer.compressed_path)
                            att_changed = true
                            log("cancelled outgoing chunks for %s to %s (they deleted)", att_id, sender)
                        end
                    end
                    if att_changed then save_state("chunks-outgoing.json", att_state) end
                    return 200, {ok = true}
                end
            end
        end
    end

    return 404, {error = "message not found"}
end

local function handle_update_address(data, sender)
    local new_ip = data.ip or ""
    local new_port = data.port

    local contacts = load_contacts()
    if not contacts[sender] then
        return 404, {error = "sender not in contacts"}
    end

    local fields = {ip = new_ip}
    if new_port then fields.port = new_port end
    write_contact_fields(sender, fields)

    log("updated address for %s: %s:%s", sender, new_ip, tostring(new_port))

    -- drop a notification in inbox if the sender requested it
    if data.notify ~= false then
        local filename = "address-update-" .. sender
        local body = sender .. "'s address has changed to " .. new_ip .. ":" .. tostring(new_port) ..
            ".\nYour contacts file has been updated automatically."
        write_file(INBOX .. "/" .. filename, body)
    end
    return 200, {ok = true}
end

-- ============================================================
-- Encryption helpers (AES-256-GCM)
-- ============================================================

-- Derive a 32-byte AES key from a contact token string.
local function derive_key(token)
    return crypto.sha256(token)
end

-- Encode n as a 4-byte big-endian string.
local function uint32_be(n)
    return string.char(
        math.floor(n / 16777216) % 256,
        math.floor(n / 65536)   % 256,
        math.floor(n / 256)     % 256,
        n % 256)
end

-- Decode a 4-byte big-endian string to a number.
local function parse_uint32_be(s)
    local a, b, c, d = string.byte(s, 1, 4)
    return a * 16777216 + b * 65536 + c * 256 + d
end

-- Send a length-prefixed encrypted packet over sock.
-- Packet format: [4-byte length][12-byte nonce][ciphertext+16-byte tag]
local function send_encrypted(sock, key, plaintext)
    local nonce      = crypto.random_bytes(12)
    local ciphertext = crypto.aes_gcm_encrypt(key, nonce, plaintext)
    if not ciphertext then return false end
    local data       = uint32_be(#nonce + #ciphertext) .. nonce .. ciphertext
    -- Send all data, handling partial sends (important for large payloads)
    sock:settimeout(30)  -- allow time for large transfers
    local sent = 0
    while sent < #data do
        local bytes, err, partial = sock:send(data, sent + 1)
        if bytes then
            sent = sent + bytes
        elseif partial and partial > 0 then
            sent = sent + partial
        else
            return false  -- send failed
        end
    end
    return true
end

-- Receive and decrypt a length-prefixed encrypted packet.
-- Returns plaintext string or nil on error / auth failure.
local function recv_encrypted(sock, key)
    sock:settimeout(10)
    local len_bytes = sock:receive(4)
    if not len_bytes or #len_bytes ~= 4 then return nil end
    local len = parse_uint32_be(len_bytes)
    if len < 28 or len > 64 * 1024 * 1024 then return nil end  -- 12+16 min, 64 MB max
    local packet = sock:receive(len)
    if not packet or #packet ~= len then return nil end
    local nonce      = packet:sub(1, 12)
    local ciphertext = packet:sub(13)
    return crypto.aes_gcm_decrypt(key, nonce, ciphertext)
end

-- {{{ encrypt_packet
-- Encrypt a raw packet for UDP/datagram use (no length prefix).
-- Returns nonce..ciphertext, or nil on error.
local function encrypt_packet(key, plaintext)
    local nonce = crypto.random_bytes(12)
    local ciphertext = crypto.aes_gcm_encrypt(key, nonce, plaintext)
    if not ciphertext then return nil end
    return nonce .. ciphertext
end
-- }}}

-- {{{ decrypt_packet
-- Decrypt a raw packet (nonce..ciphertext+tag).
-- Returns plaintext or nil on error/auth failure.
local function decrypt_packet(key, packet)
    if #packet < 28 then return nil end  -- 12 nonce + 16 tag minimum
    local nonce = packet:sub(1, 12)
    local ciphertext = packet:sub(13)
    return crypto.aes_gcm_decrypt(key, nonce, ciphertext)
end
-- }}}

-- Try to decrypt a raw packet (nonce..ciphertext+tag) against every known
-- contact token. Returns (plaintext, contact_name) or (nil, nil).
local function trial_decrypt(packet)
    if #packet < 28 then return nil, nil end
    local nonce      = packet:sub(1, 12)
    local ciphertext = packet:sub(13)
    local contacts   = load_contacts()
    for name, c in pairs(contacts) do
        if c.token then
            local key       = derive_key(c.token)
            local plaintext = crypto.aes_gcm_decrypt(key, nonce, ciphertext)
            if plaintext then
                return plaintext, name
            end
        end
    end
    return nil, nil
end

-- Parse an HTTP request from a string (instead of a socket).
local function parse_request_string(s)
    local pos = 1
    local function read_line()
        local i = s:find("\n", pos, true)
        if not i then return nil end
        local line = s:sub(pos, i - 1):gsub("\r$", "")
        pos = i + 1
        return line
    end

    local request_line = read_line()
    if not request_line then return nil end
    local method, path = request_line:match("^(%S+)%s+(%S+)")
    if not method then return nil end

    local headers = {}
    while true do
        local line = read_line()
        if not line or line == "" then break end
        local k, v = line:match("^(.-):%s*(.+)$")
        if k then headers[k:lower()] = v end
    end

    local body = ""
    local length = tonumber(headers["content-length"] or 0)
    if length > 50 * 1024 * 1024 then
        return method, path, headers, nil
    end
    if length > 0 then
        body = s:sub(pos, pos + length - 1)
    end

    return method, path, headers, body
end

-- Create a response buffer that captures send() calls into a string.
-- Mimics the subset of the socket API used by send_response / send_raw_response.
local function make_response_buffer()
    local parts = {}
    local buf = {}
    function buf:send(data)
        if data then parts[#parts + 1] = data end
        return #(data or ""), nil
    end
    function buf:get()
        return table.concat(parts)
    end
    return buf
end

-- ============================================================
-- Sync (outgoing)
-- ============================================================

-- Encrypt and send the HTTP request, then mark as "sent" (waiting for response).
local function http_encrypt_and_send(e)
    local req_str =
        "POST " .. e.req.path .. " HTTP/1.1\r\n" ..
        "Host: " .. e.req.host .. ":" .. e.req.port .. "\r\n" ..
        "Content-Type: application/json\r\n" ..
        "Content-Length: " .. #e.req.payload .. "\r\n" ..
        "Connection: close\r\n\r\n" ..
        e.req.payload
    local key   = derive_key(e.req.psk_key)
    local nonce = crypto.random_bytes(12)
    local ct    = crypto.aes_gcm_encrypt(key, nonce, req_str)
    if not ct then
        e.phase = "done"
        e.conn:close()
        return
    end
    local data = uint32_be(#nonce + #ct) .. nonce .. ct
    -- Send all data, handling partial sends (critical for large payloads like chunks)
    e.conn:settimeout(30)
    local sent = 0
    while sent < #data do
        local bytes, err, partial = e.conn:send(data, sent + 1)
        if bytes then
            sent = sent + bytes
        elseif partial and partial > 0 then
            sent = sent + partial
        else
            log("http send failed at %d/%d bytes: %s", sent, #data, tostring(err))
            e.phase = "done"
            e.conn:close()
            return
        end
    end
    e.phase = "sent"
end

-- Read and decrypt the length-prefixed response, then parse the HTTP status/body.
local function http_read_encrypted_response(e)
    local key  = derive_key(e.req.psk_key)
    local text = recv_encrypted(e.conn, key)
    if text then
        local status = tonumber(text:match("^HTTP/%S+ (%d+)"))
        local body_start = text:find("\r\n\r\n", 1, true)
        local resp_body = body_start and text:sub(body_start + 4) or ""
        if resp_body ~= "" then
            local ok2, dec = pcall(json.decode, resp_body)
            if ok2 then e.data = dec or {} end
        end
        e.ok     = (status == 200)
        e.status = status
        if not e.ok then
            log("response from %s:%d status=%s", e.req.host, e.req.port, tostring(status))
        end
    else
        log("no response from %s:%d (connection may have failed)", e.req.host, e.req.port)
    end
    e.phase = "done"
    e.conn:close()
end

-- Hook for LAN IP resolution. Set by main() to enable same-network optimization.
local resolve_lan_host = nil

-- Hook for connection timeout. Set by main() to trigger LAN discovery on failure.
local on_connection_timeout = nil

local function http_post_batch(requests)
    if #requests == 0 then return {} end

    local entries = {}
    local lookup = {}

    for i, req in ipairs(requests) do
        local host = req.host
        if resolve_lan_host then
            local lan_host = resolve_lan_host(req.host, req.port)
            if lan_host and lan_host ~= host then
                log("using LAN IP %s instead of %s", lan_host, host)
                host = lan_host
            end
        end
        local conn = socket.tcp()
        conn:settimeout(0)
        conn:connect(host, req.port)
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
                    http_encrypt_and_send(e)
                end
            end
        end

        if readable then
            for _, conn in ipairs(readable) do
                local e = lookup[conn]
                if e and e.phase == "sent" then
                    http_read_encrypted_response(e)
                end
            end
        end
    end

    local results = {}
    for i, e in ipairs(entries) do
        if e.phase ~= "done" then
            log("timeout connecting to %s:%d", e.req.host, e.req.port)
            -- Trigger LAN discovery for same-network contacts on connection failure
            if on_connection_timeout then
                pcall(on_connection_timeout, e.req.host, e.req.port)
            end
            e.conn:close()
        end
        results[i] = {ok = e.ok, status = e.status, data = e.data}
    end
    return results
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
                            attachments[#attachments + 1] = expand_tilde(fp)
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


local function encode_attachments(filepaths)
    local result = {}
    for _, filepath in ipairs(filepaths) do
        local raw = read_file_binary(filepath)
        if raw then
            result[#result + 1] = {
                filename = filepath:gsub("/+$", ""):match("([^/]+)$"),
                attachment_id = uuid(),
                data = mime.b64(raw),
            }
        else
            log("attachment not found: %s", filepath)
        end
    end
    return result
end

-- ============================================================
-- Attachment consent & chunked transfer
-- ============================================================

local function fmt_bytes(n)
    if     n >= 1073741824 then return string.format("%.1f GB", n / 1073741824)
    elseif n >= 1048576    then return string.format("%.1f MB", n / 1048576)
    elseif n >= 1024       then return string.format("%.1f KB", n / 1024)
    else return tostring(n) .. " B"
    end
end

local function check_disk_space(path)
    local h = io.popen('df -B1 --output=avail,size ' .. shell_quote(path) .. ' 2>/dev/null | tail -1')
    if not h then return nil, nil end
    local out = h:read("*a"); h:close()
    local avail, total = out:match("(%d+)%s+(%d+)")
    return tonumber(avail), tonumber(total)
end

local function measure_size(path)
    local h = io.popen('du -sb ' .. shell_quote(path) .. ' 2>/dev/null')
    if not h then return nil end
    local out = h:read("*a"); h:close()
    return tonumber(out:match("^%d+"))
end

local function sha256_file(path)
    local h = io.popen('sha256sum ' .. shell_quote(path) .. ' 2>/dev/null')
    if not h then return nil end
    local out = h:read("*a"); h:close()
    return out:match("^(%x+)")
end

local function sha256_of_bytes(data)
    local tmp = "/tmp/rmail-sha-" .. tostring(math.floor(socket.gettime() * 1000000) % 1000000)
    write_file_binary(tmp, data)
    local result = sha256_file(tmp)
    os.remove(tmp)
    return result
end

local function compress_attachment(filepath, zip_id)
    os.execute('mkdir -p ' .. shell_quote(paths.pending))
    local zip_path = paths.pending .. "/rmail-" .. zip_id .. ".zip"
    local is_dir_h = io.popen('test -d ' .. shell_quote(filepath) .. ' && echo yes 2>/dev/null')
    local is_dir = is_dir_h and is_dir_h:read("*a"):match("yes")
    if is_dir_h then is_dir_h:close() end
    local flag = is_dir and "-rj" or "-j"
    local ret = os.execute(tools.zip .. ' ' .. flag .. ' ' .. shell_quote(zip_path) ..
                           ' ' .. shell_quote(filepath) .. ' >/dev/null 2>&1')
    -- Lua 5.4 returns true on success, Lua 5.1 returns 0. Check for falsy value.
    if not ret then return nil, nil, nil end
    local checksum = sha256_file(zip_path)
    local size_h = io.popen('wc -c < ' .. shell_quote(zip_path) .. ' 2>/dev/null')
    local comp_size = size_h and tonumber(size_h:read("*a"))
    if size_h then size_h:close() end
    if not checksum or not comp_size or comp_size == 0 then return nil, nil, nil end
    return zip_path, checksum, comp_size
end

-- remove a specific attach: line from an outbox file
local function remove_attach_from_file(filepath, attach_path)
    local text = read_file(filepath)
    if not text then return end
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
    local kept = {}
    for _, line in ipairs(header_lines) do
        if line:lower():match("^attach:") then
            local fp = line:match("^[Aa][Tt][Tt][Aa][Cc][Hh]:%s*(.-)%s*$")
            if fp ~= attach_path then kept[#kept + 1] = line end
        else
            kept[#kept + 1] = line
        end
    end
    local header = ""
    for _, line in ipairs(kept) do header = header .. line .. "\n" end
    write_file(filepath, header .. body)
end

-- ---- Receiver side ----

local function handle_attachment_request(data, sender)
    local att_id = data.attachment_id
    local filename = (data.filename or "unknown"):gsub("[\n\r]", "")
    local expected_size = tonumber(data.expected_size) or 0
    local message_id = data.message_id or uuid()
    if not att_id then return 400, {error = "missing attachment_id"} end

    os.execute('mkdir -p ' .. shell_quote(paths.attachments))
    local avail, total = check_disk_space(paths.attachments)
    avail = avail or 0
    local after = math.max(0, avail - expected_size)
    local pct_str = ""
    if total and total > 0 then
        pct_str = string.format(" (%d%% of capacity)", math.floor(after / total * 100))
    end
    local base = filename:gsub("%.[^%.]+$", "")
    if base == "" then base = filename end
    local consent_file = sanitize_filename(base .. "-attachment")
    write_file(INBOX .. "/" .. consent_file, string.format(
        "%s wants to send you an attachment.\n\n" ..
        "  File:          %s\n" ..
        "  Expected size: %s\n" ..
        "  Available:     %s on this drive\n" ..
        "  After:         %s remaining%s\n\n" ..
        "Delete one line and leave your choice behind for the system to read:\n\naccept\ndeny",
        sender, filename, fmt_bytes(expected_size), fmt_bytes(avail), fmt_bytes(after), pct_str))

    local pending = load_state("consent-pending.json")
    pending[att_id] = {
        inbox_file  = consent_file,
        ["from"]    = sender,
        filename    = filename,
        expected_size = expected_size,
        message_id  = message_id,
        status      = "pending",
    }
    save_state("consent-pending.json", pending)
    log("attachment request from %s: %s (%s)", sender, filename, fmt_bytes(expected_size))
    return 200, {ok = true}
end

local function check_consent_pending()
    local pending = load_state("consent-pending.json")
    if not next(pending) then return false end
    local responses = load_state("consent-responses.json")
    if type(responses) ~= "table" then responses = {} end
    -- ensure array form (dkjson may decode [] as {})
    local changed = false
    for att_id, entry in pairs(pending) do
        if entry.status == "pending" then
            local content = read_file(INBOX .. "/" .. entry.inbox_file)
            local decision
            if not content then
                decision = false  -- file deleted: treat as declined
            else
                local has_yes, has_no = false, false
                for line in (content .. "\n"):gmatch("([^\n]*)\n") do
                    line = line:match("^%s*(.-)%s*$")
                    if line == "accept" then has_yes = true end
                    if line == "deny"   then has_no  = true end
                end
                if     has_yes and not has_no then decision = true
                elseif has_no  and not has_yes then decision = false
                end
            end
            if decision ~= nil then
                entry.status = decision and "accepted" or "declined"
                responses[#responses + 1] = {
                    attachment_id = att_id, to = entry["from"],
                    consent = decision, message_id = entry.message_id,
                }
                changed = true
            end
        elseif entry.status == "receiving" then
            if not file_exists(INBOX .. "/" .. entry.inbox_file) then
                os.execute('rm -rf ' .. shell_quote(
                    paths.pending .. "/.pending/" .. att_id))
                entry.status = "cancel_pending"
                changed = true
                log("attachment transfer cancelled by user: %s from %s", att_id, entry["from"])
            end
        end
    end
    if changed then
        save_state("consent-pending.json", pending)
        save_state("consent-responses.json", responses)
    end
    return changed
end

local function send_consent_responses(my_name)
    local responses = load_state("consent-responses.json")
    if type(responses) ~= "table" or not responses[1] then return false end
    local contacts = load_contacts()
    local requests, valid = {}, {}
    for _, resp in ipairs(responses) do
        local c = contacts[resp.to]
        if c and c.ip then
            valid[#valid + 1] = resp
            requests[#requests + 1] = {
                host = c.ip, port = c.port, path = "/deliver",
                payload = json.encode({
                    type = "attachment_response",
                    attachment_id = resp.attachment_id,
                    consent = resp.consent,
                    message_id = resp.message_id,
                }),
                psk_key = c.token,
            }
        end
    end
    if #requests == 0 then return false end
    local results = http_post_batch(requests)
    local remaining = {}
    local pending = load_state("consent-pending.json")
    for i, resp in ipairs(valid) do
        if results[i].ok then
            log("sent consent %s to %s", resp.consent and "accepted" or "declined", resp.to)
            local entry = pending[resp.attachment_id]
            if entry then
                if resp.consent then
                    write_file(INBOX .. "/" .. entry.inbox_file,
                        "Sending: " .. entry["from"] .. "'s attachment " .. entry.filename ..
                        " is being transferred.")
                    entry.status = "receiving"
                    entry.start_time = os.time()
                else
                    write_file(INBOX .. "/" .. entry.inbox_file,
                        "You declined " .. entry["from"] .. "'s attachment " .. entry.filename .. ".")
                    pending[resp.attachment_id] = nil
                end
            end
        else
            remaining[#remaining + 1] = resp
            log("failed to send consent response to %s (will retry)", resp.to)
        end
    end
    save_state("consent-pending.json", pending)
    save_state("consent-responses.json", remaining)
    return #remaining < #valid
end

local function send_attachment_cancellations(my_name)
    local pending = load_state("consent-pending.json")
    if not next(pending) then return false end
    local contacts = load_contacts()
    local to_cancel = {}
    for att_id, entry in pairs(pending) do
        if entry.status == "cancel_pending" then
            to_cancel[#to_cancel + 1] = {att_id = att_id, entry = entry}
        end
    end
    if #to_cancel == 0 then return false end
    local requests, valid = {}, {}
    for _, item in ipairs(to_cancel) do
        local c = contacts[item.entry["from"]]
        if c and c.ip then
            valid[#valid + 1] = item
            requests[#requests + 1] = {
                host = c.ip, port = c.port, path = "/delete",
                payload = json.encode({
                    message_id = item.entry.message_id,
                }),
                psk_key = c.token,
            }
        else
            pending[item.att_id] = nil
        end
    end
    if #requests == 0 then
        save_state("consent-pending.json", pending)
        return true
    end
    local results = http_post_batch(requests)
    for i, item in ipairs(valid) do
        if results[i].ok then
            pending[item.att_id] = nil
            log("notified %s of attachment cancellation: %s", item.entry["from"], item.att_id)
        else
            log("failed to notify %s of attachment cancellation (will retry)", item.entry["from"])
        end
    end
    save_state("consent-pending.json", pending)
    return true
end

local function handle_attachment_chunk(data, sender)
    local att_id = data.attachment_id
    local chunk_index = tonumber(data.chunk_index)
    local total_chunks = tonumber(data.total_chunks)
    local filename = data.filename or "unknown"
    local chunk_checksum = data.chunk_checksum
    local total_checksum = data.total_checksum
    if not att_id or chunk_index == nil or not total_chunks or not data.data then
        return 400, {error = "missing required fields"}
    end
    local raw = mime.unb64(data.data)
    if not raw then return 400, {error = "invalid base64"} end

    -- Check cancellation before storing anything
    local cprog = load_state("consent-pending.json")
    local cpe = cprog[att_id]
    if cpe and cpe.status == "cancel_pending" then
        return 200, {ok = false, cancelled = true}
    end

    local pending_dir = paths.pending .. "/.pending/" .. att_id
    os.execute('mkdir -p ' .. shell_quote(pending_dir))
    local chunk_path = pending_dir .. "/chunk-" .. tostring(chunk_index)

    if chunk_checksum and sha256_of_bytes(raw) ~= chunk_checksum then
        -- discard bad chunk; it stays missing in the response
        log("chunk %d checksum mismatch from %s for %s", chunk_index, sender, filename)
    else
        write_file_binary(chunk_path, raw)
    end

    -- compute missing list
    local missing = {}
    for i = 0, total_chunks - 1 do
        if not file_exists(pending_dir .. "/chunk-" .. tostring(i)) then
            missing[#missing + 1] = i
        end
    end

    if cpe and cpe.status == "receiving" then
        -- Check if user deleted the progress file (cancellation during transfer)
        if not file_exists(INBOX .. "/" .. cpe.inbox_file) then
            os.execute('rm -rf ' .. shell_quote(
                paths.pending .. "/.pending/" .. att_id))
            cpe.status = "cancel_pending"
            cprog[att_id] = cpe
            save_state("consent-pending.json", cprog)
            log("attachment transfer cancelled by user: %s from %s", att_id, sender)
            return 200, {ok = false, cancelled = true}
        end
        local received = total_chunks - #missing
        local avg_str = ""
        if cpe.start_time and received > 0 then
            local elapsed = os.time() - cpe.start_time
            if elapsed > 0 then
                avg_str = string.format(
                    "\nAverage: %.1f seconds per chunk.", elapsed / received)
            end
        end
        write_file(INBOX .. "/" .. cpe.inbox_file, string.format(
            "Receiving %s from %s \xe2\x80\x94 %d / %d chunks (%d%%)%s\n\nDelete this file to cancel and clean up partial downloads.",
            filename, sender, received, total_chunks,
            math.floor(received / total_chunks * 100), avg_str))
    end

    if #missing > 0 then
        return 200, {ok = true, missing = missing}
    end

    -- all chunks present: reassemble
    local zip_path = pending_dir .. "/assembled.zip"
    local f = io.open(zip_path, "wb")
    if not f then return 500, {error = "cannot create assembled zip"} end
    for i = 0, total_chunks - 1 do
        local chunk_raw = read_file_binary(pending_dir .. "/chunk-" .. tostring(i))
        if chunk_raw then f:write(chunk_raw) end
    end
    f:close()

    if total_checksum and sha256_file(zip_path) ~= total_checksum then
        os.remove(zip_path)
        log("total checksum mismatch for %s from %s", filename, sender)
        return 500, {error = "total checksum mismatch"}
    end

    os.execute('mkdir -p ' .. shell_quote(paths.attachments))
    local ret = os.execute(tools.unzip .. ' -o ' .. shell_quote(zip_path) ..
                           ' -d ' .. shell_quote(paths.attachments) .. ' >/dev/null 2>&1')
    -- Lua 5.4 returns true on success, Lua 5.1 returns 0. Check for falsy value.
    if not ret then
        log("failed to extract %s from %s", filename, sender)
        return 500, {error = "extraction failed"}
    end

    local target = paths.attachments .. "/" .. filename
    if hooks.on_package then
        os.execute(hooks.on_package .. " " .. shell_quote(sender) .. " " ..
                   shell_quote(filename) .. " " .. shell_quote(target) .. " &")
    end

    if cprog[att_id] then
        if cprog[att_id].status ~= "cancel_pending" then
            write_file(INBOX .. "/" .. cprog[att_id].inbox_file, string.format(
                "Transfer complete:\n%s's attachment %s has arrived.\nSaved to: %s",
                sender, filename, target))
        end
        cprog[att_id] = nil
        save_state("consent-pending.json", cprog)
    end

    os.execute('rm -rf ' .. shell_quote(pending_dir))
    log("attachment received: %s from %s -> %s", filename, sender, target)
    return 200, {ok = true, missing = {}}
end

-- ---- Sender side ----

local function handle_attachment_response(data, sender)
    local att_id = data.attachment_id
    local consent = data.consent
    if not att_id then return 400, {error = "missing attachment_id"} end
    local chunks = load_state("chunks-outgoing.json")
    local transfer = chunks[att_id]
    if not transfer then return 200, {ok = true} end
    if consent then
        transfer.status = "sending"
        local m = {}
        for i = 0, transfer.total_chunks - 1 do m[#m + 1] = i end
        transfer.missing = m
        log("consent granted by %s for %s", sender, transfer.filename)
    else
        if transfer.compressed_path and file_exists(transfer.compressed_path) then
            os.remove(transfer.compressed_path)
        end
        write_file(INBOX .. "/declined-" .. sanitize_filename(transfer.filename),
            sender .. " declined your attachment " .. transfer.filename .. ".")
        chunks[att_id] = nil
        log("consent declined by %s for %s", sender, transfer.filename)
    end
    save_state("chunks-outgoing.json", chunks)
    return 200, {ok = true}
end


-- Write ~/mail/transfers showing outgoing attachment progress.
-- Groups active transfers by source file path, one section per file.
-- Removes the file when there are no active transfers.
local function write_transfers_file(att_state)
    local by_path = {}
    local path_order = {}
    for _, transfer in pairs(att_state) do
        if transfer.status == "awaiting_consent" or transfer.status == "sending" then
            local path = transfer.original_path
            if not by_path[path] then
                by_path[path] = {}
                path_order[#path_order + 1] = path
            end
            local progress
            if transfer.status == "awaiting_consent" then
                progress = "awaiting consent"
            else
                local missing_count = transfer.missing and #transfer.missing or 0
                local sent = transfer.total_chunks - missing_count
                progress = sent .. " / " .. transfer.total_chunks .. " chunks received"
            end
            by_path[path][transfer.to] = progress
        end
    end

    if #path_order == 0 then
        if file_exists(paths.transfers) then os.remove(paths.transfers) end
        return
    end

    table.sort(path_order)
    local sep = string.rep("-", 80)
    local lines = {}
    for _, path in ipairs(path_order) do
        lines[#lines + 1] = sep
        lines[#lines + 1] = path
        lines[#lines + 1] = ""
        local sorted_contacts = {}
        for cname in pairs(by_path[path]) do
            sorted_contacts[#sorted_contacts + 1] = cname
        end
        table.sort(sorted_contacts)
        for _, cname in ipairs(sorted_contacts) do
            lines[#lines + 1] = cname .. "  " .. by_path[path][cname]
        end
    end
    lines[#lines + 1] = sep
    write_file(paths.transfers, table.concat(lines, "\n") .. "\n")
end

-- Check ~/mail/transfers for user-initiated cancellations.
-- If a recipient line or entire file section was removed, cancel those
-- transfers in chunks-outgoing.json and stop sending their chunks.
local function check_transfers_file_cancellations()
    if not file_exists(paths.transfers) then return end
    local content = read_file(paths.transfers)
    if not content then return end

    local chunks = load_state("chunks-outgoing.json")
    if not next(chunks) then return end

    -- Parse file into {path -> {contact_name -> true}}
    local file_contacts = {}
    local current_path = nil
    local sep = string.rep("-", 80)
    for line in (content .. "\n"):gmatch("([^\n]*)\n") do
        line = line:match("^%s*(.-)%s*$")
        if line == sep then
            current_path = nil
        elseif not current_path and line ~= "" then
            current_path = line
            file_contacts[current_path] = {}
        elseif current_path and line ~= "" then
            local cname = line:match("^(%S+)")
            if cname then file_contacts[current_path][cname] = true end
        end
    end

    -- Collect cancellations (don't modify chunks while iterating)
    local to_cancel = {}
    for att_id, transfer in pairs(chunks) do
        if transfer.status == "awaiting_consent" or transfer.status == "sending" then
            local contacts_in_file = file_contacts[transfer.original_path]
            if not contacts_in_file or not contacts_in_file[transfer.to] then
                to_cancel[att_id] = transfer
            end
        end
    end

    local changed = false
    for att_id, transfer in pairs(to_cancel) do
        release_zip(chunks, transfer.zip_id, transfer.compressed_path)
        chunks[att_id] = nil
        log("transfer cancelled via transfers file: %s to %s", transfer.filename, transfer.to)
        changed = true
    end

    if changed then
        save_state("chunks-outgoing.json", chunks)
        write_transfers_file(chunks)
    end
end

local function send_next_chunks(my_name)
    local chunks = load_state("chunks-outgoing.json")
    if not next(chunks) then return false end
    local contacts = load_contacts()
    local did_work = false
    local changed = false
    for att_id, transfer in pairs(chunks) do
        if transfer.status ~= "sending" then goto continue end
        local contact = contacts[transfer.to]
        if not contact or not contact.ip then
            log("chunk transfer: unknown contact %s, skipping", transfer.to)
            goto continue
        end
        if not file_exists(transfer.compressed_path) then
            log("chunk transfer: zip missing for %s, cancelling", att_id)
            chunks[att_id] = nil
            release_zip(chunks, transfer.zip_id, transfer.compressed_path)
            changed = true; goto continue
        end
        local f = io.open(transfer.compressed_path, "rb")
        if not f then goto continue end
        local missing = transfer.missing or {}
        local aborted = false
        local cancelled = false
        for _, chunk_index in ipairs(missing) do
            f:seek("set", chunk_index * cfg.chunk_size)
            local raw = f:read(cfg.chunk_size)
            if not raw then
                log("chunk read error at %d for %s", chunk_index, att_id)
                aborted = true; break
            end
            local results = http_post_batch({{
                host = contact.ip, port = contact.port, path = "/deliver",
                payload = json.encode({
                    type = "attachment_chunk",
                    attachment_id = att_id,
                    message_id = transfer.message_id,
                    filename = transfer.filename,
                    chunk_index = chunk_index,
                    total_chunks = transfer.total_chunks,
                    data = mime.b64(raw),
                    chunk_checksum = sha256_of_bytes(raw),
                    total_checksum = transfer.total_checksum,
                }),
                psk_key = contact.token,
            }})
            local resp = results[1].data or {}
            if results[1].ok then
                -- receiver tells us what's still missing
                local new_missing = resp.missing
                if type(new_missing) == "table" then
                    transfer.missing = new_missing
                end
                changed = true; did_work = true
                if #transfer.missing == 0 then break end
            elseif resp.cancelled then
                log("transfer cancelled by receiver: %s to %s", transfer.filename, transfer.to)
                cancelled = true; break
            else
                log("chunk %d/%d failed for %s -> %s, will retry",
                    chunk_index + 1, transfer.total_chunks, transfer.filename, transfer.to)
                aborted = true; break
            end
        end
        f:close()
        if cancelled then
            release_zip(chunks, transfer.zip_id, transfer.compressed_path)
            chunks[att_id] = nil
            changed = true
        elseif not aborted and #transfer.missing == 0 then
            transfer.status = "complete"
            log("all chunks sent for %s to %s", transfer.filename, transfer.to)
            changed = true
        end
        ::continue::
    end
    -- clean up completed transfers and release shared zips
    for att_id, transfer in pairs(chunks) do
        if transfer.status == "complete" then
            chunks[att_id] = nil
            release_zip(chunks, transfer.zip_id, transfer.compressed_path)
            changed = true
        end
    end
    if changed then save_state("chunks-outgoing.json", chunks) end
    return did_work
end

local function handle_deliver(data, sender)
    local msg_type = data and data.type
    if not msg_type then
        return 400, {error = "missing type field"}
    end
    if     msg_type == "message"             then return handle_deliver_message(data, sender)
    elseif msg_type == "attachment_request"  then return handle_attachment_request(data, sender)
    elseif msg_type == "attachment_response" then return handle_attachment_response(data, sender)
    elseif msg_type == "attachment_chunk"    then return handle_attachment_chunk(data, sender)
    elseif msg_type == "chunk_failed"        then return 200, {ok = true}
    else return 400, {error = "unknown type: " .. tostring(msg_type)}
    end
end

-- self-delivery helpers: handle messages sent to own name without network
local function self_delete_from_inbox(my_name, message_id)
    local inbox_state = load_state("inbox.json")
    for filename, meta in pairs(inbox_state) do
        if meta.message_id == message_id and meta["from"] == my_name then
            if file_exists(INBOX .. "/" .. filename) then
                os.remove(INBOX .. "/" .. filename)
                log("self-delete from inbox: %s", filename)
            end
            if hooks.on_delete then run_hook(hooks.on_delete, my_name) end
            delete_inbox_attachments(meta)
            inbox_state[filename] = nil
            save_state("inbox.json", inbox_state)
            return
        end
    end
end

local function self_delete_from_outbox(my_name, message_id)
    local outbox_state = load_state("outbox.json")
    for filename, meta in pairs(outbox_state) do
        if meta.recipients then
            for recipient, rmeta in pairs(meta.recipients) do
                if rmeta.message_id == message_id and rmeta.self then
                    if hooks.on_delete then run_hook(hooks.on_delete, my_name) end
                    meta.recipients[recipient] = nil
                    remove_recipient_from_file(OUTBOX .. "/" .. filename, recipient)
                    if not next(meta.recipients) then
                        outbox_state[filename] = nil
                    end
                    save_state("outbox.json", outbox_state)
                    return
                end
            end
        end
    end
end

local function sync_outbox(my_name)
    local contacts = load_contacts()
    local state = load_state("outbox.json")
    local att_state = load_state("chunks-outgoing.json")
    local att_state_changed = false
    local did_work = false

    -- clean up completed transfers: remove attach: lines from outbox files
    for att_id, transfer in pairs(att_state) do
        if transfer.status == "complete" then
            local outbox_path = OUTBOX .. "/" .. transfer.outbox_file
            if file_exists(outbox_path) then
                remove_attach_from_file(outbox_path, transfer.original_path)
            end
            att_state[att_id] = nil
            att_state_changed = true
            did_work = true
            log("attachment transfer complete, removed attach: %s", transfer.filename)
        end
    end

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
                    local fname = fp:gsub("/+$", ""):match("([^/]+)$")
                    if fname then amap[fname] = fp end
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
                    if rmeta.self then
                        self_delete_from_inbox(my_name, rmeta.message_id)
                        state[name].recipients[recipient] = nil
                        did_work = true
                    elseif contacts[recipient] then
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
                        -- new recipient: deliver message body only
                        if rname == my_name then
                            -- self-delivery: write directly to own inbox
                            local inbox_state = load_state("inbox.json")
                            local msg_id = uuid()
                            local inbox_name = sanitize_filename(name)
                            local target = INBOX .. "/" .. inbox_name
                            if file_exists(target) then
                                local existing = inbox_state[inbox_name]
                                if existing and existing["from"] ~= my_name then
                                    inbox_name = sanitize_filename(name .. "-from-" .. my_name)
                                    target = INBOX .. "/" .. inbox_name
                                end
                            end
                            local inbox_body = body or ""
                            if hooks.on_send then
                                local transformed = run_hook(hooks.on_send, my_name, name, inbox_body)
                                if transformed and transformed ~= "" then inbox_body = transformed end
                            end
                            if hooks.on_receive_raw then
                                local transformed = run_hook(hooks.on_receive_raw, my_name, name, inbox_body)
                                if transformed and transformed ~= "" then inbox_body = transformed end
                            end
                            inbox_body = inbox_body:gsub("^[\n\r]+", "")
                            write_file(target, inbox_body)
                            inbox_state[inbox_name] = {
                                ["from"] = my_name,
                                message_id = msg_id,
                            }
                            save_state("inbox.json", inbox_state)
                            if hooks.on_receive then
                                os.execute(hooks.on_receive .. " " ..
                                    shell_quote(my_name) .. " " .. shell_quote(name) .. " " ..
                                    shell_quote(target) .. " &")
                            end
                            state[name].recipients[my_name] = {
                                message_id = msg_id,
                                self = true,
                            }
                            log("self-delivered: %s -> %s", name, inbox_name)
                            did_work = true
                        elseif contacts[rname] then
                            ops[#ops + 1] = {
                                type = "deliver", filename = name,
                                recipient = rname, message_id = uuid(),
                                subject = name, body = body,
                                contact = contacts[rname],
                            }
                        else
                            log("skipping %s: unknown contact '%s'", name, rname)
                        end
                    elseif contacts[rname] then
                        -- existing recipient: check for new attach: lines not yet in progress
                        local rmeta = state[name].recipients[rname]
                        if not rmeta.error then
                            for _, filepath in ipairs(entry.attachments) do
                                local in_progress = false
                                for _, transfer in pairs(att_state) do
                                    if transfer.to == rname and
                                       transfer.outbox_file == name and
                                       transfer.original_path == filepath then
                                        in_progress = true; break
                                    end
                                end
                                if not in_progress then
                                    local att_id = uuid()
                                    local basename = filepath:gsub("/+$", ""):match("([^/]+)$") or filepath
                                    local expected_size = measure_size(filepath) or 0
                                    -- find existing zip for this file (shared across recipients)
                                    local zip_id, zip_path, checksum, total_chunks
                                    for _, t in pairs(att_state) do
                                        if t.outbox_file == name and
                                           t.original_path == filepath and
                                           t.zip_id and
                                           file_exists(t.compressed_path) then
                                            zip_id       = t.zip_id
                                            zip_path     = t.compressed_path
                                            checksum     = t.total_checksum
                                            total_chunks = t.total_chunks
                                            break
                                        end
                                    end
                                    if not zip_id then
                                        zip_id = uuid()
                                        local comp_size
                                        zip_path, checksum, comp_size =
                                            compress_attachment(filepath, zip_id)
                                        if zip_path then
                                            total_chunks = math.max(1,
                                                math.ceil(comp_size / cfg.chunk_size))
                                        end
                                    end
                                    if zip_path then
                                        att_state[att_id] = {
                                            to = rname, outbox_file = name,
                                            original_path = filepath, filename = basename,
                                            zip_id = zip_id,
                                            compressed_path = zip_path,
                                            total_chunks = total_chunks,
                                            total_checksum = checksum,
                                            expected_size = expected_size,
                                            message_id = rmeta.message_id,
                                            status = "awaiting_consent",
                                        }
                                        att_state_changed = true
                                        ops[#ops + 1] = {
                                            type = "attachment_request",
                                            att_id = att_id, filename = name,
                                            recipient = rname,
                                            contact = contacts[rname],
                                            att_filename = basename,
                                            expected_size = expected_size,
                                            message_id = rmeta.message_id,
                                        }
                                    else
                                        log("failed to compress %s for %s", filepath, rname)
                                    end
                                end
                            end
                            -- Recipient stays in state after delivery.
                            -- Cleanup happens when recipient deletes from
                            -- inbox (they send /delete) or sender removes
                            -- the to: line / deletes the outbox file.
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
                if rmeta.self then
                    self_delete_from_inbox(my_name, rmeta.message_id)
                    meta.recipients[recipient] = nil
                    did_work = true
                elseif contacts[recipient] then
                    ops[#ops + 1] = {
                        type = "notify_deletion", filename = name,
                        recipient = recipient, message_id = rmeta.message_id,
                        contact = contacts[recipient],
                    }
                end
            end
        end
    end

    -- track which outbox files had ops this cycle (to avoid premature cleanup on delivery failure)
    local files_with_ops = {}
    for _, op in ipairs(ops) do files_with_ops[op.filename] = true end

    -- Phase 2: encode attachments and build requests
    if #ops > 0 then
        local requests = {}
        local req_to_op = {}  -- compact requests index → ops index
        for i, op in ipairs(ops) do
            local path, data
            if op.type == "deliver" then
                local body_size = #(op.body or "")
                if body_size > 131072 then
                    local kb = math.floor(body_size / 1024)
                    local err_body = string.format(
                        "error sending \"%s\": message body is too large (%d KB).\n" ..
                        "The maximum message body size is 128 KB.\n" ..
                        "To send large content, use an attach: line in your outbox file instead.",
                        op.subject or op.filename or "untitled", kb)
                    write_file(INBOX .. "/error-" .. sanitize_filename(op.subject or op.filename or "untitled"), err_body)
                    -- mark state to prevent retry
                    if state[op.filename] then
                        state[op.filename].recipients[op.recipient] = {error = "body_too_large"}
                    end
                    log("body too large (%d KB), not sending %s to %s", kb, op.filename, op.recipient)
                    did_work = true
                    op.skip = true
                end
                if not op.skip then
                    path = "/deliver"
                    local send_body = op.body
                    if hooks.on_send then
                        local transformed = run_hook(hooks.on_send, op.recipient, op.subject or op.filename, op.body or "")
                        if transformed and transformed ~= "" then send_body = transformed end
                    end
                    data = {type = "message",
                            subject = op.subject, message_id = op.message_id, body = send_body}
                end
            elseif op.type == "attachment_request" then
                path = "/deliver"
                data = {type = "attachment_request",
                        attachment_id = op.att_id,
                        message_id = op.message_id,
                        filename = op.att_filename,
                        expected_size = op.expected_size}
            else
                path = "/delete"
                data = {message_id = op.message_id}
            end
            if not op.skip then
                local j = #requests + 1
                requests[j] = {
                    host = op.contact.ip, port = op.contact.port,
                    path = path, payload = json.encode(data),
                    psk_key = op.contact.token,
                }
                req_to_op[j] = i
            end
        end

        local raw_results = http_post_batch(requests)
        -- expand results back to ops indexing
        local results = {}
        for j, oi in ipairs(req_to_op) do
            results[oi] = raw_results[j]
        end

        -- Phase 3: process results
        for i, op in ipairs(ops) do
            if op.skip then
                -- already handled in Phase 2
            elseif op.type == "notify_removal" then
                if results[i].ok or results[i].status == 404 then
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
                        state[op.filename].recipients[op.recipient] = {
                            message_id = op.message_id,
                            token = op.contact.token,
                        }
                    end
                    log("sent: %s -> %s", op.filename, op.recipient)
                    did_work = true
                else
                    log("failed to send %s to %s", op.filename, op.recipient)
                end
            elseif op.type == "attachment_request" then
                if results[i].ok then
                    log("sent attachment request to %s: %s", op.recipient, op.att_filename)
                    did_work = true
                else
                    -- remove this recipient's entry; release shared zip if no other recipients need it
                    local transfer = att_state[op.att_id]
                    if transfer then
                        att_state[op.att_id] = nil
                        release_zip(att_state, transfer.zip_id, transfer.compressed_path)
                        att_state_changed = true
                    end
                    log("failed to send attachment request to %s (will retry)", op.recipient)
                end
            elseif op.type == "notify_deletion" then
                if results[i].ok or results[i].status == 404 then
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
                -- cancel any outgoing chunk transfers for this outbox file
                for att_id, transfer in pairs(att_state) do
                    if transfer.outbox_file == name then
                        att_state[att_id] = nil
                        release_zip(att_state, transfer.zip_id, transfer.compressed_path)
                        att_state_changed = true
                        log("cancelled outgoing chunks for %s (outbox file deleted)", att_id)
                    end
                end
            end
        end
    end

    -- clean up files with no recipients left (skip files that had ops this cycle to allow retry)
    for name in pairs(current) do
        if state[name] and not next(state[name].recipients) and not files_with_ops[name] then
            os.remove(OUTBOX .. "/" .. name)
            log("cleaned up %s: no recipients left", name)
            state[name] = nil
            did_work = true
        end
    end

    if att_state_changed then save_state("chunks-outgoing.json", att_state) end
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
                if hooks.on_delete then run_hook(hooks.on_delete, meta["from"] or "") end
                meta.pending_delete = true
                did_work = true
            end
            local sender = meta["from"] or ""
            if sender == my_name then
                -- self-sent message deleted from inbox: remove from outbox
                self_delete_from_outbox(my_name, meta.message_id)
                state[name] = nil
                did_work = true
            elseif contacts[sender] then
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
                host = op.contact.ip, port = op.contact.port,
                path = "/delete",
                payload = json.encode({
                    message_id = op.message_id,
                }),
                psk_key = op.contact.token,
            }
        end
        local results = http_post_batch(requests)
        for i, op in ipairs(ops) do
            if results[i].ok or results[i].status == 404 then
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
    conn:send("GET " .. service.path .. " HTTP/1.0\r\n" ..
        "Host: " .. service.host .. "\r\nConnection: close\r\n\r\n")

    local status_line = conn:receive("*l")
    if not status_line or not status_line:find(" 200 ") then conn:close(); return nil end

    while true do
        local line = conn:receive("*l")
        if not line or line == "" then break end
    end

    local ip = conn:receive("*l")
    conn:close()
    if ip then ip = ip:match("^%s*(.-)%s*$") end
    if ip and ip:match("^%d+%.%d+%.%d+%.%d+$") then return ip end
    return nil
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
    -- Discard stored value if it's not a valid IP (e.g. stale HTML from old bug)
    if stored_ip and not stored_ip:match("^%d+%.%d+%.%d+%.%d+$") then stored_ip = nil end

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
        if name ~= my_name and contact.ip then
            pending[name] = {ip = new_ip, port = port}
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
        if contacts[name] and contacts[name].ip then
            ops[#ops + 1] = {
                name = name, contact = contacts[name],
                ip = info.ip, port = info.port,
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
            host = op.contact.ip, port = op.contact.port,
            path = "/update-address",
            payload = json.encode({
                ip = op.ip, port = op.port, notify = cfg.notify_ip_change,
            }),
            psk_key = op.contact.token,
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
-- Phone API endpoints
-- ============================================================

local function infer_attachment_category(filename)
    local ext = (filename:match("%.([^%.]+)$") or ""):lower()
    local images = {jpg=1,jpeg=1,png=1,gif=1,bmp=1,webp=1,heic=1,heif=1,svg=1,tiff=1,tif=1}
    local audio  = {mp3=1,wav=1,ogg=1,m4a=1,flac=1,aac=1,opus=1,wma=1}
    local text   = {txt=1,md=1,csv=1,json=1,xml=1,html=1,htm=1,log=1,lua=1,sh=1,py=1,js=1}
    if   images[ext] then return "image"
    elseif audio[ext] then return "audio"
    elseif text[ext]  then return "text"
    else return "other" end
end

-- Serialize contacts in a canonical, deterministic form for hashing and wire transfer.
-- Contacts sorted by name, fields sorted by key. Values are quoted when non-numeric.
local function serialize_contacts_canonical()
    local contacts = load_contacts()
    local names = {}
    for name in pairs(contacts) do names[#names+1] = name end
    table.sort(names)
    local lines = {}
    for _, name in ipairs(names) do
        local c = contacts[name]
        local fields = {}
        for field in pairs(c) do fields[#fields+1] = field end
        table.sort(fields)
        for _, field in ipairs(fields) do
            local v = tostring(c[field])
            if not v:match("^%d+$") then v = '"' .. v .. '"' end
            lines[#lines+1] = name .. "." .. field .. " = " .. v
        end
        lines[#lines+1] = ""
    end
    return table.concat(lines, "\n")
end

local function canonical_contacts_hash()
    local bytes = crypto.sha256(serialize_contacts_canonical())
    local hex = ""
    for i = 1, #bytes do hex = hex .. string.format("%02x", bytes:byte(i)) end
    return hex
end

-- GET /peer-address — return the caller's stored address (ip/port) from our contacts file.
-- Used by phones to recover the home server's public IP after a dynamic IP change.
-- Available to any authenticated contact, not restricted to own-device entries.
local function handle_peer_address(contact_name)
    if not cfg.allow_peer_addr then
        return 403, {error = "peer address requests disabled"}
    end
    local contacts = load_contacts()
    local c = contacts[contact_name]
    if not c then return 404, {error = "contact not found"} end
    return 200, {ip = c.ip or "", port = c.port or ""}
end

-- GET /api/myaddress — return this daemon's current public IP and configured port.
local function handle_api_myaddress(my_name, port)
    local ip = check_public_ip()
    local lan_ip = nat.get_local_ip()
    return 200, {ip = ip or "", port = port, name = my_name, lan_ip = lan_ip or ""}
end

-- POST /api/sync — core phone sync endpoint.
-- Phone sends its current state; server responds with what to fetch/remove.
local function handle_api_sync(data, caller_name, my_name)
    local phone_inbox    = data.inbox or {}          -- {message_id -> filename}
    local deleted_inbox  = data.deleted_inbox or {}  -- [{message_id, from}]
    local phone_outbox   = data.outbox or {}         -- ["filename", ...]
    local deleted_outbox = data.deleted_outbox or {} -- ["filename", ...]

    -- Process inbox deletions from phone
    local inbox_state = load_state("inbox.json")
    for _, del in ipairs(deleted_inbox) do
        for filename, meta in pairs(inbox_state) do
            if meta.message_id == del.message_id and not meta.pending_delete then
                if file_exists(INBOX .. "/" .. filename) then
                    os.remove(INBOX .. "/" .. filename)
                end
                delete_inbox_attachments(meta)
                if hooks.on_delete then run_hook(hooks.on_delete, meta["from"] or "") end
                meta.pending_delete = true  -- sync_inbox will notify original sender
                log("phone deleted inbox: %s (from %s)", filename, meta["from"] or "?")
                break
            end
        end
    end
    save_state("inbox.json", inbox_state)

    -- Process outbox deletions from phone (delete file; sync_outbox notifies recipients)
    for _, fname in ipairs(deleted_outbox) do
        fname = sanitize_filename(fname)
        local fpath = OUTBOX .. "/" .. fname
        if file_exists(fpath) then
            os.remove(fpath)
            log("phone deleted outbox: %s", fname)
        end
    end

    -- Build set of message IDs the phone currently has
    local phone_ids = {}
    for mid, _ in pairs(phone_inbox) do phone_ids[mid] = true end

    -- Build server's current ID set (excluding pending-delete entries)
    local server_ids = {}
    for _, meta in pairs(inbox_state) do
        if not meta.pending_delete then server_ids[meta.message_id] = true end
    end

    -- fetch_inbox: server has it, phone doesn't
    local fetch_inbox = {}
    for filename, meta in pairs(inbox_state) do
        if not meta.pending_delete and not phone_ids[meta.message_id] then
            fetch_inbox[#fetch_inbox+1] = {
                message_id = meta.message_id,
                filename   = filename,
                from       = meta["from"] or "",
            }
        end
    end

    -- remove_inbox: phone has it, server no longer has it
    local remove_inbox = {}
    for mid, _ in pairs(phone_inbox) do
        if not server_ids[mid] then remove_inbox[#remove_inbox+1] = mid end
    end

    -- fetch_outbox: server has it, phone doesn't
    local phone_outbox_set = {}
    for _, fname in ipairs(phone_outbox) do phone_outbox_set[fname] = true end
    local server_outbox_files = list_files(OUTBOX)
    local fetch_outbox = {}
    for _, fname in ipairs(server_outbox_files) do
        if not phone_outbox_set[fname] then fetch_outbox[#fetch_outbox+1] = fname end
    end

    -- remove_outbox: phone has it, server doesn't
    local server_outbox_set = {}
    for _, fname in ipairs(server_outbox_files) do server_outbox_set[fname] = true end
    local remove_outbox = {}
    for _, fname in ipairs(phone_outbox) do
        if not server_outbox_set[fname] then remove_outbox[#remove_outbox+1] = fname end
    end

    -- contacts: include full text when hashes differ, omit when same
    local contacts_text = nil
    local phone_hash = data.contacts_hash
    if not phone_hash or phone_hash ~= canonical_contacts_hash() then
        contacts_text = serialize_contacts_canonical()
    end

    return 200, {
        fetch_inbox    = fetch_inbox,
        remove_inbox   = remove_inbox,
        fetch_outbox   = fetch_outbox,
        remove_outbox  = remove_outbox,
        contacts       = contacts_text,
        mailbox_name   = my_name,
        mailbox_path   = MAIL,
    }
end

-- GET /api/file/inbox/<f> or /api/file/outbox/<f> — download a mail file to the phone.
local function handle_api_get_file(dir, filename)
    filename = sanitize_filename(filename)
    local content = read_file(dir .. "/" .. filename)
    if not content then return 404, nil, nil end
    return 200, "text/plain; charset=utf-8", content
end

-- POST /api/file/outbox/<f> — create or replace an outbox file from the phone.
local function handle_api_post_outbox_file(filename, body)
    filename = sanitize_filename(filename)
    write_file(OUTBOX .. "/" .. filename, body)
    log("phone created outbox: %s", filename)
    return 200, {ok = true}
end

-- GET /api/contacts — return contacts in canonical serialization for hashing/transfer.
local function handle_api_get_contacts()
    return 200, "text/plain; charset=utf-8", serialize_contacts_canonical()
end

-- POST /api/contacts — accept contacts file from phone, replacing server's version.
local function handle_api_post_contacts(body)
    if not body or body == "" then return 400, {error = "empty body"} end
    write_file(CONTACTS, body)
    align_contacts()
    log("contacts updated from phone")
    return 200, {ok = true}
end

-- GET /api/attachments — list received attachments with name, size, category, sender.
local function handle_api_list_attachments()
    local inbox_state = load_state("inbox.json")
    local sender_for = {}
    for _, meta in pairs(inbox_state) do
        if meta.attachments then
            for att_filename, _ in pairs(meta.attachments) do
                sender_for[att_filename] = meta["from"] or ""
            end
        end
    end
    local result = {}
    for _, f in ipairs(list_files(paths.attachments)) do
        local path = paths.attachments .. "/" .. f
        local h = io.popen("wc -c < " .. shell_quote(path) .. " 2>/dev/null")
        local size = h and tonumber(h:read("*a"))
        if h then h:close() end
        result[#result+1] = {
            filename = f,
            size     = size or 0,
            category = infer_attachment_category(f),
            sender   = sender_for[f] or "",
            checksum = sha256_file(path) or "",
        }
    end
    return 200, {files = result}
end

-- GET /api/attachments/<filename> — download an attachment file to the phone.
local function handle_api_get_attachment(filename)
    filename = sanitize_filename(filename)
    local content = read_file_binary(paths.attachments .. "/" .. filename)
    if not content then return 404, nil, nil end
    return 200, "application/octet-stream", content
end

-- POST /api/log — accept a log message from a phone and write it to the daemon's log.
local function handle_api_log(data, caller_name)
    local msg = data and data.message or "(no message)"
    local level = data and data.level or "info"
    log("[%s] %s: %s", caller_name or "phone", level, msg)
    return 200, {ok = true}
end

-- DELETE /api/attachments/<filename> — delete an attachment from the server.
local function handle_api_delete_attachment(filename)
    filename = sanitize_filename(filename)
    local path = paths.attachments .. "/" .. filename
    if not file_exists(path) then return 404, {error = "not found"} end
    os.remove(path)
    log("attachment deleted by phone: %s", filename)
    return 200, {ok = true}
end

-- GET /api/attachments/<filename>/info — return file size and chunk count for chunked download.
local DOWNLOAD_CHUNK_SIZE = 256 * 1024  -- 256 KiB per chunk (small for resumability over flaky connections)

local function handle_api_attachment_info(filename)
    filename = sanitize_filename(filename)
    local path = paths.attachments .. "/" .. filename
    local h = io.popen("wc -c < " .. shell_quote(path) .. " 2>/dev/null")
    local size = h and tonumber(h:read("*a"))
    if h then h:close() end
    if not size or size == 0 then return 404, {error = "not found"} end
    local num_chunks = math.ceil(size / DOWNLOAD_CHUNK_SIZE)
    -- Compute per-chunk checksums so the client can verify each chunk
    local chunk_checksums = {}
    local f = io.open(path, "rb")
    if f then
        for i = 1, num_chunks do
            local data = f:read(DOWNLOAD_CHUNK_SIZE)
            if data then
                local bytes = crypto.sha256(data)
                local hex = ""
                for j = 1, #bytes do hex = hex .. string.format("%02x", bytes:byte(j)) end
                chunk_checksums[i] = hex
            end
        end
        f:close()
    end
    return 200, {
        size = size,
        num_chunks = num_chunks,
        chunk_size = DOWNLOAD_CHUNK_SIZE,
        chunk_checksums = chunk_checksums,
        file_checksum = sha256_file(path) or "",
    }
end

-- GET /api/attachments/<filename>/chunk/<n> — download one chunk of an attachment.
local function handle_api_attachment_chunk(filename, chunk_n)
    filename = sanitize_filename(filename)
    local path = paths.attachments .. "/" .. filename
    local f = io.open(path, "rb")
    if not f then return 404, nil, nil end
    local offset = chunk_n * DOWNLOAD_CHUNK_SIZE
    f:seek("set", offset)
    local data = f:read(DOWNLOAD_CHUNK_SIZE)
    f:close()
    if not data or #data == 0 then return 404, nil, nil end
    return 200, "application/octet-stream", data
end

-- POST /api/upload/start — register a new phone-to-server attachment upload.
-- Returns upload_id and the server_path the phone should reference in attach: lines.
local function handle_api_upload_start(data)
    if not data or not data.filename then return 400, {error = "missing filename"} end
    local filename   = sanitize_filename(data.filename)
    local num_chunks = tonumber(data.num_chunks)
    if not num_chunks or num_chunks < 1 or num_chunks > 100000 then
        return 400, {error = "invalid num_chunks"}
    end
    local upload_id  = uuid()
    local upload_dir = paths.uploads .. "/" .. upload_id
    os.execute("mkdir -p " .. shell_quote(upload_dir))
    local server_path = upload_dir .. "/" .. filename
    local uploads = load_state("uploads.json")
    uploads[upload_id] = {
        filename   = filename,
        num_chunks = num_chunks,
        path       = server_path,
        upload_dir = upload_dir,
        created_at = os.time(),
    }
    save_state("uploads.json", uploads)
    log("phone upload started: %s (%d chunks) id=%s", filename, num_chunks, upload_id)
    return 200, {upload_id = upload_id, server_path = server_path}
end

-- PUT /api/upload/<id>/chunk/<n> — receive one chunk of a phone-to-server upload.
-- Auto-assembles the file once all chunks are present.
local function handle_api_upload_chunk(upload_id, chunk_n, body)
    if not body or body == "" then return 400, {error = "empty chunk"} end
    local uploads = load_state("uploads.json")
    local upload = uploads[upload_id]
    if not upload then return 404, {error = "upload not found"} end
    if chunk_n < 0 or chunk_n >= upload.num_chunks then
        return 400, {error = "chunk index out of range"}
    end
    write_file_binary(upload.upload_dir .. "/chunk-" .. tostring(chunk_n), body)
    -- Check whether all chunks are now present
    for i = 0, upload.num_chunks - 1 do
        if not file_exists(upload.upload_dir .. "/chunk-" .. tostring(i)) then
            save_state("uploads.json", uploads)
            return 200, {ok = true, complete = false}
        end
    end
    -- All chunks present: assemble and clean up
    local f = io.open(upload.path, "wb")
    if not f then return 500, {error = "cannot create output file"} end
    for i = 0, upload.num_chunks - 1 do
        local cp = upload.upload_dir .. "/chunk-" .. tostring(i)
        local d  = read_file_binary(cp)
        if d then f:write(d) end
        os.remove(cp)
    end
    f:close()
    uploads[upload_id] = nil
    save_state("uploads.json", uploads)
    log("phone upload complete: %s id=%s", upload.filename, upload_id)
    return 200, {ok = true, complete = true}
end

-- ============================================================
-- Extracted functions (formerly inside main, broken out to stay
-- under LuaJIT's 60-upvalue limit per function)
-- ============================================================

-- rmail multicast group address (239.x.x.x is organization-local scope)
local MULTICAST_ADDR = "239.192.82.77"

local function check_lan_ip_change(port)
    local new_lan_ip = nat.get_local_ip()
    if not new_lan_ip then return end
    local stored_lan_ip = read_file(STATE .. "/lan_ip")
    if stored_lan_ip then stored_lan_ip = stored_lan_ip:match("^%s*(.-)%s*$") end
    if stored_lan_ip and not stored_lan_ip:match("^%d+%.%d+%.%d+%.%d+$") then stored_lan_ip = nil end
    write_file(STATE .. "/lan_ip", new_lan_ip)
    if not stored_lan_ip then log("LAN IP recorded: %s", new_lan_ip); return end
    if stored_lan_ip == new_lan_ip then return end
    log("LAN IP changed: %s -> %s", stored_lan_ip, new_lan_ip)
    if cfg.auto_port_forward then
        log("auto port forward is enabled — UPnP/NAT-PMP mapping will use new LAN IP"); return
    end
    write_file(INBOX .. "/lan-ip-changed", string.format(
        "Your local IP address changed from %s to %s.\n\n" ..
        "If you use manual port forwarding, your router is still forwarding port %d\n" ..
        "to %s. Update your router's port forwarding rule to point to %s instead,\n" ..
        "or set a DHCP reservation / static IP so this doesn't happen again.",
        stored_lan_ip, new_lan_ip, port, stored_lan_ip, new_lan_ip))
end

local function do_resolve_lan_host(lan_peers, host, target_port)
    local my_public = read_file(STATE .. "/public_ip")
    if not my_public then return nil end
    my_public = my_public:match("^%s*(.-)%s*$")
    if host ~= my_public then return nil end
    local contacts = load_contacts()
    for name, c in pairs(contacts) do
        if c.ip == host and tostring(c.port or "") == tostring(target_port) then
            local lan_ip = c.lan_ip or lan_peers[name]
            if lan_ip then
                log("same-network: using LAN IP %s for %s (instead of %s)", lan_ip, name, host)
                return lan_ip
            end
        end
    end
    return nil
end

-- {{{ UDP LAN Discovery

local function join_multicast_group(udp_socket)
    local ok, err = udp_socket:setoption("ip-add-membership", {
        multiaddr = MULTICAST_ADDR, interface = "0.0.0.0"
    })
    if ok then log("joined multicast group %s", MULTICAST_ADDR)
    else log("failed to join multicast group: %s", tostring(err)) end
    return ok
end

local function send_lan_discovery(contacts, my_name, my_port, my_public_ip)
    local my_lan_ip = nat.get_local_ip()
    if not my_lan_ip then return end
    local subnet_base = my_lan_ip:match("^(%d+%.%d+%.%d+%.)")
    local my_last_octet = tonumber(my_lan_ip:match("%.(%d+)$"))
    for name, c in pairs(contacts) do
        if c.ip == my_public_ip and c.token and c.port then
            local payload = "RMAIL-DISCOVER " .. my_name .. " " .. my_port .. " " .. my_lan_ip
            local key = derive_key(c.token)
            local encrypted = encrypt_packet(key, payload)
            if encrypted then
                local udp = socket.udp()
                udp:setoption("ip-multicast-ttl", 1)
                udp:sendto(encrypted, MULTICAST_ADDR, c.port)
                udp:close()
                if subnet_base then
                    for i = 1, 254 do
                        if i ~= my_last_octet then
                            local udp2 = socket.udp()
                            udp2:sendto(encrypted, subnet_base .. i, c.port)
                            udp2:close()
                        end
                    end
                end
                log("LAN discovery: multicast + subnet scan for %s (port %d)", name, c.port)
            end
        end
    end
end

local function handle_udp_discovery(data, sender_ip, sender_port, contacts, my_name, my_port, my_public_ip, lan_peers)
    for name, c in pairs(contacts) do
        if c.token then
            local key = derive_key(c.token)
            local plaintext = decrypt_packet(key, data)
            if plaintext then
                local disc_name, disc_port, disc_lan_ip = plaintext:match("^RMAIL%-DISCOVER%s+(%S+)%s+(%d+)%s+(%S+)")
                if disc_name and disc_lan_ip then
                    lan_peers[disc_name] = disc_lan_ip
                    log("LAN discovery: %s is at %s (received request)", disc_name, disc_lan_ip)
                    local my_lan_ip = nat.get_local_ip()
                    if not my_lan_ip then return end
                    local resp_payload = "RMAIL-HERE " .. my_name .. " " .. my_lan_ip
                    local resp_encrypted = encrypt_packet(derive_key(c.token), resp_payload)
                    if resp_encrypted then
                        local udp = socket.udp()
                        udp:sendto(resp_encrypted, disc_lan_ip, tonumber(disc_port))
                        udp:close()
                    end
                    return
                end
                local here_name, here_lan_ip = plaintext:match("^RMAIL%-HERE%s+(%S+)%s+(%S+)")
                if here_name and here_lan_ip then
                    lan_peers[here_name] = here_lan_ip
                    log("LAN discovery: %s is at %s (received response)", here_name, here_lan_ip)
                    return
                end
            end
        end
    end
end

local function poll_udp_discovery(udp, contacts, my_name, my_port, my_public_ip, lan_peers)
    while true do
        local data, sender_ip, sender_port = udp:receivefrom()
        if not data then break end
        pcall(handle_udp_discovery, data, sender_ip, sender_port, contacts, my_name, my_port, my_public_ip, lan_peers)
    end
end

-- }}}

local function do_on_connection_timeout(rt, host, target_port)
    local my_public = read_file(STATE .. "/public_ip")
    if not my_public then return end
    my_public = my_public:match("^%s*(.-)%s*$")
    if host ~= my_public then return end
    local my_lan_ip = nat.get_local_ip()
    if not my_lan_ip then return end
    local contacts = load_contacts()
    for name, c in pairs(contacts) do
        if c.ip == host and tostring(c.port or "") == tostring(target_port) and c.token then
            if rt.lan.discovery_sent[name] then return end
            rt.lan.discovery_sent[name] = true
            local payload = "RMAIL-DISCOVER " .. rt.my_name .. " " .. rt.port .. " " .. my_lan_ip
            local key = derive_key(c.token)
            local encrypted = encrypt_packet(key, payload)
            if encrypted then
                local udp = socket.udp()
                udp:setoption("ip-multicast-ttl", 1)
                udp:sendto(encrypted, MULTICAST_ADDR, c.port)
                udp:close()
                local subnet_base = my_lan_ip:match("^(%d+%.%d+%.%d+%.)")
                local my_last_octet = tonumber(my_lan_ip:match("%.(%d+)$"))
                if subnet_base then
                    for i = 1, 254 do
                        if i ~= my_last_octet then
                            local udp2 = socket.udp()
                            udp2:sendto(encrypted, subnet_base .. i, c.port)
                            udp2:close()
                        end
                    end
                end
                log("LAN discovery: multicast + subnet scan on connection failure (looking for %s)", name)
            end
            return
        end
    end
end

-- ============================================================
-- Request handler (extracted from main)
-- ============================================================

local function handle_request(rt, client)
    client:settimeout(10)

    -- Known sender from previous request on this connection (for keep-alive)
    local known_contact = nil
    local known_key = nil

    while true do
        -- Read first 4 bytes — length prefix or "GET " for health check
        -- Use a longer timeout for keep-alive idle (waiting for next request)
        client:settimeout(known_contact and 30 or 10)
        local first4 = client:receive(4)
        if not first4 or #first4 ~= 4 then return end  -- connection closed or timeout

        -- Plaintext health check
        if first4 == "GET " then
            while true do
                local line = client:receive("*l")
                if not line or line == "" then break end
            end
            local hc_body = json.encode({ok = true, name = rt.my_name})
            client:send(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n" ..
                "Content-Length: " .. #hc_body .. "\r\nConnection: close\r\n\r\n" .. hc_body)
            return  -- health check doesn't support keep-alive
        end

        -- Encrypted frame
        client:settimeout(10)
        local len = parse_uint32_be(first4)
        if len < 28 or len > 64 * 1024 * 1024 then return end
        local packet = client:receive(len)
        if not packet or #packet ~= len then return end

        -- Decrypt: try known sender's key first (fast path for keep-alive)
        local plaintext, contact_name
        if known_contact and known_key then
            plaintext = crypto.aes_gcm_decrypt(known_key, packet:sub(1, 12), packet:sub(13))
            if plaintext then
                contact_name = known_contact
            end
        end
        -- Fall back to trial decryption if fast path failed or this is the first request
        if not plaintext then
            plaintext, contact_name = trial_decrypt(packet)
        end
        if not plaintext then log("decryption failed: no matching contact key"); return end

        -- Cache sender for subsequent requests on this connection
        if not known_contact then
            known_contact = contact_name
            local cc = load_contacts()
            if cc[contact_name] then
                known_key = derive_key(cc[contact_name].token)
            end

            -- Cache peer LAN IP on first request only
            local peer_ip = client:getpeername()
            if peer_ip and contact_name and not rt.lan.peers[contact_name] then
                local is_private = peer_ip:match("^192%.168%.") or
                                   peer_ip:match("^10%.") or peer_ip:match("^172%.")
                if is_private then
                    local my_public = (read_file(STATE .. "/public_ip") or ""):match("^%s*(.-)%s*$")
                    if cc[contact_name] and cc[contact_name].ip == my_public then
                        rt.lan.peers[contact_name] = peer_ip
                    end
                end
            end
        end

        local method, path, headers, body = parse_request_string(plaintext)
        if not method then return end

        local contacts = load_contacts()
        local key = derive_key(contacts[contact_name].token)
        local is_own_device = contacts[contact_name].own == "true"
    local resp = make_response_buffer()

    if method == "GET" and path == "/" then
        send_response(resp, 200, {ok = true, name = rt.my_name})
    elseif method == "GET" and path == "/deps" then
        send_response(resp, 200, {deps = DEPS_REGISTRY})
    elseif method == "GET" and path:match("^/deps/(.+)$") then
        local dep_name = path:match("^/deps/(.+)$")
        if DEPS_REGISTRY[dep_name] then send_response(resp, 200, DEPS_REGISTRY[dep_name])
        else send_response(resp, 404, {error = "unknown dependency: " .. dep_name}) end
    elseif method == "GET" and path == "/install-script" then
        local script_path = script_dir .. "scripts/install.sh"
        local f = io.open(script_path, "r")
        if f then
            local content = f:read("*a"); f:close()
            local hh = io.popen("sha256sum '" .. script_path:gsub("'", "'\\''") .. "'")
            local sha = ""; if hh then sha = (hh:read("*a") or ""):match("^(%x+)") or ""; hh:close() end
            send_raw_response(resp, 200, "application/x-shellscript", content, {["X-SHA256"] = sha})
        else send_response(resp, 404, {error = "install script not found"}) end
    elseif method == "GET" and path == "/peer-address" then
        local s, r = handle_peer_address(contact_name); send_response(resp, s, r)
    elseif path:match("^/api/") then
        if not is_own_device then
            send_response(resp, 403, {error = "own device required"})
        else
            local fn
            if method == "GET" and path == "/api/myaddress" then
                local s, r = handle_api_myaddress(rt.my_name, rt.port); send_response(resp, s, r)
            elseif method == "GET" and path == "/api/contacts" then
                local s, ct, c = handle_api_get_contacts(); send_raw_response(resp, s, ct, c)
            elseif method == "POST" and path == "/api/contacts" then
                local s, r = handle_api_post_contacts(body); send_response(resp, s, r)
            elseif method == "POST" and path == "/api/sync" then
                local data = json.decode(body or "{}") or {}
                local s, r = handle_api_sync(data, contact_name, rt.my_name); send_response(resp, s, r)
            elseif method == "GET" and path:match("^/api/file/inbox/(.+)$") then
                fn = path:match("^/api/file/inbox/(.+)$")
                local s, ct, c = handle_api_get_file(INBOX, fn)
                if ct then send_raw_response(resp, s, ct, c) else send_response(resp, s, {error = "not found"}) end
            elseif method == "GET" and path:match("^/api/file/outbox/(.+)$") then
                fn = path:match("^/api/file/outbox/(.+)$")
                local s, ct, c = handle_api_get_file(OUTBOX, fn)
                if ct then send_raw_response(resp, s, ct, c) else send_response(resp, s, {error = "not found"}) end
            elseif method == "POST" and path:match("^/api/file/outbox/(.+)$") then
                fn = path:match("^/api/file/outbox/(.+)$")
                local s, r = handle_api_post_outbox_file(fn, body or ""); send_response(resp, s, r)
            elseif method == "GET" and path == "/api/attachments" then
                local s, r = handle_api_list_attachments(); send_response(resp, s, r)
            elseif method == "GET" and path:match("^/api/attachments/(.+)/info$") then
                fn = path:match("^/api/attachments/(.+)/info$")
                local s, r = handle_api_attachment_info(fn); send_response(resp, s, r)
            elseif method == "GET" and path:match("^/api/attachments/(.+)/chunk/(%d+)$") then
                fn = path:match("^/api/attachments/(.+)/chunk/(%d+)$")
                local cn = tonumber(path:match("/chunk/(%d+)$"))
                local s, ct, c = handle_api_attachment_chunk(fn, cn)
                if ct then send_raw_response(resp, s, ct, c) else send_response(resp, s, {error = "not found"}) end
            elseif method == "GET" and path:match("^/api/attachments/(.+)$") then
                fn = path:match("^/api/attachments/(.+)$")
                local s, ct, c = handle_api_get_attachment(fn)
                if ct then send_raw_response(resp, s, ct, c) else send_response(resp, s, {error = "not found"}) end
            elseif method == "DELETE" and path:match("^/api/attachments/(.+)$") then
                fn = path:match("^/api/attachments/(.+)$")
                local s, r = handle_api_delete_attachment(fn); send_response(resp, s, r)
            elseif method == "POST" and path == "/api/log" then
                local data = json.decode(body or "{}") or {}
                local s, r = handle_api_log(data, contact_name); send_response(resp, s, r)
            elseif method == "POST" and path == "/api/upload/start" then
                local data = json.decode(body or "{}") or {}
                local s, r = handle_api_upload_start(data); send_response(resp, s, r)
            elseif method == "PUT" and path:match("^/api/upload/([^/]+)/chunk/(%d+)$") then
                local uid, cn = path:match("^/api/upload/([^/]+)/chunk/(%d+)$")
                local s, r = handle_api_upload_chunk(uid, tonumber(cn), body or ""); send_response(resp, s, r)
            else send_response(resp, 404, {error = "not found"}) end
        end
    elseif method == "POST" and body and body ~= "" then
        local data = json.decode(body)
        if path == "/deliver" then local s, r = handle_deliver(data, contact_name); send_response(resp, s, r)
        elseif path == "/delete" then local s, r = handle_delete(data, contact_name); send_response(resp, s, r)
        elseif path == "/update-address" then local s, r = handle_update_address(data, contact_name); send_response(resp, s, r)
        else send_response(resp, 404, {error = "not found"}) end
    else send_response(resp, 404, {error = "not found"}) end

    send_encrypted(client, key, resp:get())

    -- Loop back for next request on this keep-alive connection
    end -- while true (keep-alive loop)
end

-- ============================================================
-- Sync cycle (extracted from main)
-- ============================================================

local function run_sync_cycle(rt)
    check_transfers_file_cancellations()
    local w1 = sync_outbox(rt.my_name)
    local w2 = sync_inbox(rt.my_name)
    local w3 = sync_address_notifications(rt.my_name)
    local w4 = check_consent_pending()
    local w5 = send_consent_responses(rt.my_name)
    local w6 = send_next_chunks(rt.my_name)
    local w7 = send_attachment_cancellations(rt.my_name)
    write_transfers_file(load_state("chunks-outgoing.json"))
    if w1 or w2 or w3 or w4 or w5 or w6 or w7 then
        rt.interval = math.max(rt.min_interval, rt.interval - 240)
        log("had work, interval -> %ds", rt.interval)
    else
        rt.interval = math.min(rt.interval + 360, rt.max_interval)
        log("idle, interval -> %ds", rt.interval)
    end
end

local function poll_udp_cycle(rt)
    local my_public = read_file(STATE .. "/public_ip")
    if my_public then
        my_public = my_public:match("^%s*(.-)%s*$")
        local contacts = load_contacts()
        poll_udp_discovery(rt.lan.udp, contacts, rt.my_name, rt.port, my_public, rt.lan.peers)
    end
end

-- ============================================================
-- Init runtime — setup, validation, returns state table
-- ============================================================

local function init_runtime()
    os.execute('mkdir -p "' .. INBOX .. '" "' .. OUTBOX .. '" "' .. STATE .. '" "' ..
               paths.attachments .. '" "' .. paths.pending .. '" "' .. paths.uploads .. '"')
    if not config.name then
        io.stderr:write("error: 'name' is not set in " .. CONFIG_PATH .. "\n"); os.exit(1)
    end
    if not tools.zip then
        io.stderr:write("error: 'zip' not found\n       run: scripts/install.sh\n"); os.exit(1)
    end
    if not tools.unzip then
        io.stderr:write("error: 'unzip' not found\n       run: scripts/install.sh\n"); os.exit(1)
    end
    align_contacts()

    local rt = {
        my_name      = config.name,
        port         = tonumber(config.port or 8025),
        nat_mapping  = nil,
        interval     = 10,   -- TODO: increase for production
        min_interval = 10,
        max_interval = 30,   -- TODO: increase for production
        last_sync    = socket.gettime(),
        lan = { udp = nil, peers = {}, discovery_sent = {} },
    }

    log("rmail starting: name=%s port=%d", rt.my_name, rt.port)
    log("mail dir: %s", MAIL)
    log("AES-256-GCM encryption enabled")

    pcall(nat.cleanup_old_mapping)
    pcall(nat.security_check, rt.my_name)

    if cfg.auto_port_forward then
        log("attempting automatic port forwarding...")
        local ok_nat, result = pcall(nat.create_mapping, rt.port)
        if ok_nat and result and result.protocol then
            rt.nat_mapping = result
            log("port %d mapped via %s", rt.port, result.protocol)
        else
            log("warning: auto port forward failed, port %d may not be reachable", rt.port)
        end
    end

    rt.server = assert(socket.bind("0.0.0.0", rt.port))
    rt.server:settimeout(1)

    rt.lan.udp = socket.udp()
    assert(rt.lan.udp:setsockname("0.0.0.0", rt.port))
    rt.lan.udp:settimeout(0)

    log("listening on :%d (TCP + UDP)", rt.port)

    pcall(detect_ip_change, rt.my_name, rt.port)
    pcall(check_lan_ip_change, rt.port)
    join_multicast_group(rt.lan.udp)

    -- Initial LAN discovery
    pcall(function()
        local my_public = read_file(STATE .. "/public_ip")
        if my_public then
            my_public = my_public:match("^%s*(.-)%s*$")
            send_lan_discovery(load_contacts(), rt.my_name, rt.port, my_public)
        end
    end)

    return rt
end

-- ============================================================
-- Cooperative socket wrapper — yields to event loop on block
-- ============================================================

-- Wraps a raw TCP socket so that receive/send yield the current coroutine
-- instead of blocking. The event loop resumes the coroutine when select()
-- says the socket is ready.

local function make_async_socket(raw_sock)
    local wrapper = {_sock = raw_sock, _timeout = 10}
    raw_sock:settimeout(0)  -- non-blocking

    function wrapper:receive(pattern)
        local deadline = socket.gettime() + self._timeout
        local buffer = ""
        while true do
            -- For line mode, try to receive with whatever we have
            local data, err, partial = self._sock:receive(pattern)
            if data then
                if #buffer > 0 then return buffer .. data end
                return data
            end
            if partial and #partial > 0 then
                buffer = buffer .. partial
                if type(pattern) == "number" then
                    pattern = pattern - #partial
                    if pattern <= 0 then return buffer end
                end
                -- For "*l" mode, partial means we got data but no newline yet
                -- Keep accumulating — LuaSocket will continue from where it left off
            end
            if err == "timeout" or err == "wantread" then
                if socket.gettime() > deadline then
                    return nil, "timeout", buffer
                end
                coroutine.yield("read", self._sock)
            elseif err == "closed" then
                if #buffer > 0 then return nil, "closed", buffer end
                return nil, "closed"
            else
                return nil, err, partial
            end
        end
    end

    function wrapper:send(data, i)
        i = i or 1
        local deadline = socket.gettime() + 30
        while i <= #data do
            local bytes, err, last = self._sock:send(data, i)
            if bytes then
                -- LuaSocket returns the index of the last byte sent
                if bytes >= #data then return bytes end
                i = bytes + 1
            elseif err == "timeout" or err == "wantwrite" then
                if last and last >= i then i = last + 1 end
                if i > #data then return #data end
                if socket.gettime() > deadline then return nil, "timeout", i - 1 end
                coroutine.yield("write", self._sock)
            else
                return nil, err, last
            end
        end
        return #data
    end

    function wrapper:settimeout(t) self._timeout = t end
    function wrapper:getpeername() return self._sock:getpeername() end
    function wrapper:close() return self._sock:close() end

    return wrapper
end

-- ============================================================
-- Coroutine event loop — concurrent connection handling
-- ============================================================

-- Active client coroutines: each connection gets its own coroutine.
-- The main loop uses socket.select() to multiplex across all active
-- sockets and resumes coroutines when their socket is ready.
-- The sync cycle runs inline between select iterations (not as a
-- coroutine) to keep state management simple.

local function main()
    local rt = init_runtime()

    resolve_lan_host = function(host, target_port)
        return do_resolve_lan_host(rt.lan.peers, host, target_port)
    end
    on_connection_timeout = function(host, target_port)
        do_on_connection_timeout(rt, host, target_port)
    end

    -- Active client coroutines: raw_socket -> {co, wait_type, wait_sock, last_activity}
    -- wait_type is "read" or "write", wait_sock is the raw socket to select on
    local clients = {}

    rt.server:settimeout(0)  -- non-blocking accept

    local function resume_client(raw_sock)
        local info = clients[raw_sock]
        if not info or coroutine.status(info.co) ~= "suspended" then return end
        info.last_activity = socket.gettime()
        local ok, wait_type, wait_sock = coroutine.resume(info.co)
        if not ok then
            log("request error: %s", tostring(wait_type))  -- wait_type is the error on failure
            pcall(function() raw_sock:close() end)
            clients[raw_sock] = nil
        elseif coroutine.status(info.co) == "dead" then
            pcall(function() raw_sock:close() end)
            clients[raw_sock] = nil
        else
            -- Coroutine yielded — it wants to wait for I/O
            info.wait_type = wait_type   -- "read" or "write"
            info.wait_sock = wait_sock or raw_sock
        end
    end

    while true do
        -- Build socket lists for select
        local recvt = {rt.server}
        local sendt = {}
        for raw_sock, info in pairs(clients) do
            if info.wait_type == "read" then
                recvt[#recvt + 1] = info.wait_sock
            elseif info.wait_type == "write" then
                sendt[#sendt + 1] = info.wait_sock
            end
        end

        local readable, writable = socket.select(
            #recvt > 0 and recvt or nil,
            #sendt > 0 and sendt or nil,
            0.5)

        -- Handle readable sockets
        if readable then
            for _, sock in ipairs(readable) do
                if sock == rt.server then
                    local raw_client = rt.server:accept()
                    if raw_client then
                        local async_client = make_async_socket(raw_client)
                        local co = coroutine.create(function()
                            handle_request(rt, async_client)
                        end)
                        clients[raw_client] = {
                            co = co, wait_type = nil, wait_sock = nil,
                            last_activity = socket.gettime()
                        }
                        -- Start processing — will run until first yield or completion
                        local ok, wait_type, wait_sock = coroutine.resume(co)
                        if not ok then
                            log("request error: %s", tostring(wait_type))
                            pcall(function() raw_client:close() end)
                            clients[raw_client] = nil
                        elseif coroutine.status(co) == "dead" then
                            pcall(function() raw_client:close() end)
                            clients[raw_client] = nil
                        else
                            clients[raw_client].wait_type = wait_type
                            clients[raw_client].wait_sock = wait_sock or raw_client
                        end
                    end
                else
                    -- Find which client owns this socket and resume it
                    for raw_sock, info in pairs(clients) do
                        if info.wait_sock == sock and info.wait_type == "read" then
                            resume_client(raw_sock)
                            break
                        end
                    end
                end
            end
        end

        -- Handle writable sockets
        if writable then
            for _, sock in ipairs(writable) do
                for raw_sock, info in pairs(clients) do
                    if info.wait_sock == sock and info.wait_type == "write" then
                        resume_client(raw_sock)
                        break
                    end
                end
            end
        end

        -- Clean up stale connections (idle > 30s)
        local now = socket.gettime()
        for raw_sock, info in pairs(clients) do
            if now - info.last_activity > 30 then
                pcall(function() raw_sock:close() end)
                clients[raw_sock] = nil
            end
        end

        -- UDP discovery (non-blocking)
        pcall(poll_udp_cycle, rt)

        -- Sync cycle (runs inline, not as a coroutine — simpler state management)
        if file_exists(STATE .. "/sync-now") then
            os.remove(STATE .. "/sync-now")
            rt.last_sync = 0
            log("manual sync triggered")
        end
        if now - rt.last_sync >= rt.interval then
            rt.lan.discovery_sent = {}
            local ok, err = pcall(run_sync_cycle, rt)
            if not ok then log("sync error: %s", tostring(err)) end
            rt.last_sync = now
        end

        -- NAT renewal
        if rt.nat_mapping then
            if now - (rt.nat_mapping.last_renewed or rt.nat_mapping.created_at) >= 1800 then
                local ok_r, res = pcall(nat.create_mapping, rt.port)
                if ok_r and res then log("renewed NAT mapping via %s", res.protocol) end
                rt.nat_mapping.last_renewed = now
            end
        end
    end
end

main()
