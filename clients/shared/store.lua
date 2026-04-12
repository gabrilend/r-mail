-- store.lua — local state management for rmail thin client
--
-- Mirrors the daemon's directory layout:
--   mailbox-<id>/
--     inbox/          — received message files
--     outbox/         — messages to send
--     attachments/    — downloaded attachment cache
--     sync-state.json — sync state
--     contacts        — contacts file

local json = require("dkjson")
local crypto = require("rmail_crypto")

local store = {}
store.__index = store

function store.new(base_dir, mailbox_id)
    local self = setmetatable({}, store)
    self.root = base_dir .. "/mailbox-" .. mailbox_id
    self.inbox_dir = self.root .. "/inbox"
    self.outbox_dir = self.root .. "/outbox"
    self.attachments_dir = self.root .. "/attachments"
    self.state_file = self.root .. "/sync-state.json"
    self.contacts_file = self.root .. "/contacts"

    -- Ensure directories exist (cross-platform)
    local sep = package.config:sub(1, 1)  -- "/" on POSIX, "\" on Windows
    self.sep = sep
    local function mkdirs(path)
        if sep == "\\" then
            os.execute('if not exist "' .. path .. '" mkdir "' .. path .. '"')
        else
            os.execute('mkdir -p "' .. path .. '"')
        end
    end
    mkdirs(self.inbox_dir)
    mkdirs(self.outbox_dir)
    mkdirs(self.attachments_dir)
    return self
end

-- ── File helpers ────────────────────────────────────────────────────────

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    return content
end

local function write_file(path, content)
    local f = io.open(path, "wb")
    if not f then return false end
    f:write(content)
    f:close()
    return true
end

local function list_files(dir)
    local files = {}
    local sep = package.config:sub(1, 1)
    local cmd = sep == "\\" and ('dir /b "' .. dir .. '" 2>nul')
                             or ('ls -1 "' .. dir .. '" 2>/dev/null')
    local handle = io.popen(cmd)
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

-- ── Inbox ──────────────────────────────────────────────────────────────

function store:list_inbox()
    return list_files(self.inbox_dir)
end

function store:read_inbox(filename)
    return read_file(self.inbox_dir .. "/" .. filename)
end

function store:write_inbox(filename, content)
    return write_file(self.inbox_dir .. "/" .. filename, content)
end

function store:delete_inbox(filename)
    os.remove(self.inbox_dir .. "/" .. filename)
end

-- ── Outbox ─────────────────────────────────────────────────────────────

function store:list_outbox()
    return list_files(self.outbox_dir)
end

function store:read_outbox(filename)
    return read_file(self.outbox_dir .. "/" .. filename)
end

function store:write_outbox(filename, content)
    return write_file(self.outbox_dir .. "/" .. filename, content)
end

function store:delete_outbox(filename)
    os.remove(self.outbox_dir .. "/" .. filename)
end

-- ── Contacts ───────────────────────────────────────────────────────────

function store:read_contacts()
    return read_file(self.contacts_file) or ""
end

function store:write_contacts(content)
    return write_file(self.contacts_file, content)
end

-- Canonical contacts hash matching the server's canonical_contacts_hash().
-- Parse name.key = value lines, sort by name then key, re-emit, SHA-256.
function store:contacts_hash()
    local text = self:read_contacts()
    if not text or text == "" then return nil end

    local contacts = {}
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and trimmed:sub(1, 1) ~= "#" and trimmed:sub(1, 1) ~= "/" then
            local eq = trimmed:find("=")
            if eq then
                local dotkey = trimmed:sub(1, eq - 1):match("^%s*(.-)%s*$")
                local value = trimmed:sub(eq + 1):match("^%s*(.-)%s*$")
                -- Unquote value
                if value:sub(1, 1) == '"' and value:sub(-1) == '"' then
                    value = value:sub(2, -2)
                end
                local dot = dotkey:find("%.")
                if dot then
                    local name = dotkey:sub(1, dot - 1):match("^%s*(.-)%s*$")
                    local key = dotkey:sub(dot + 1):match("^%s*(.-)%s*$")
                    if not contacts[name] then contacts[name] = {} end
                    contacts[name][key] = value
                end
            end
        end
    end

    -- Sort and serialize canonically
    local names = {}
    for name in pairs(contacts) do names[#names + 1] = name end
    table.sort(names)

    local lines = {}
    for _, name in ipairs(names) do
        local keys = {}
        for key in pairs(contacts[name]) do keys[#keys + 1] = key end
        table.sort(keys)
        for _, key in ipairs(keys) do
            local raw = contacts[name][key]
            local v = raw:match("^%d+$") and raw or ('"' .. raw .. '"')
            lines[#lines + 1] = name .. "." .. key .. " = " .. v
        end
        lines[#lines + 1] = ""
    end
    local canonical = table.concat(lines, "\n")
    -- SHA-256 hex
    local hash_bytes = crypto.sha256(canonical)
    local hex = {}
    for i = 1, #hash_bytes do
        hex[#hex + 1] = string.format("%02x", hash_bytes:byte(i))
    end
    return table.concat(hex)
end

-- Parse contact names (excluding own devices)
function store:contact_names()
    local text = self:read_contacts()
    if not text or text == "" then return {} end

    local names = {}
    local own = {}
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        local trimmed = line:match("^%s*(.-)%s*$")
        if trimmed ~= "" and trimmed:sub(1, 1) ~= "#" and trimmed:sub(1, 2) ~= "//" then
            local eq = trimmed:find("=")
            if eq then
                local dotkey = trimmed:sub(1, eq - 1):match("^%s*(.-)%s*$")
                local value = trimmed:sub(eq + 1):match("^%s*(.-)%s*$"):gsub('^"', ''):gsub('"$', '')
                local dot = dotkey:find("%.")
                if dot then
                    local name = dotkey:sub(1, dot - 1):match("^%s*(.-)%s*$")
                    local field = dotkey:sub(dot + 1):match("^%s*(.-)%s*$")
                    names[name] = true
                    if field == "own" and value == "true" then own[name] = true end
                end
            end
        end
    end

    local result = {}
    for name in pairs(names) do
        if not own[name] then result[#result + 1] = name end
    end
    table.sort(result)
    return result
end

-- ── Sync state ─────────────────────────────────────────────────────────

function store:read_sync_state()
    local text = read_file(self.state_file)
    if not text then return { inbox = {}, outbox = {}, contacts_hash = nil } end
    local data = json.decode(text)
    if not data then return { inbox = {}, outbox = {}, contacts_hash = nil } end

    -- Parse inbox map: { message_id -> { filename, from } }
    local inbox = {}
    if data.inbox then
        for id, entry in pairs(data.inbox) do
            inbox[id] = { filename = entry.filename, from = entry["from"] }
        end
    end

    -- Parse outbox set
    local outbox = {}
    if data.outbox then
        for _, name in ipairs(data.outbox) do
            outbox[name] = true
        end
    end

    return {
        inbox = inbox,
        outbox = outbox,
        contacts_hash = data.contacts_hash
    }
end

function store:write_sync_state(state)
    local data = {
        inbox = {},
        outbox = {},
        contacts_hash = state.contacts_hash
    }
    for id, entry in pairs(state.inbox) do
        data.inbox[id] = { filename = entry.filename, ["from"] = entry.from }
    end
    local outbox_list = {}
    for name in pairs(state.outbox) do
        outbox_list[#outbox_list + 1] = name
    end
    table.sort(outbox_list)
    data.outbox = outbox_list

    write_file(self.state_file, json.encode(data, { indent = true }) .. "\n")
end

-- ── Attachments ────────────────────────────────────────────────────────

function store:list_cached_attachments()
    return list_files(self.attachments_dir)
end

function store:is_attachment_cached(filename)
    local f = io.open(self.attachments_dir .. "/" .. filename, "r")
    if f then f:close(); return true end
    return false
end

function store:attachment_path(filename)
    return self.attachments_dir .. "/" .. filename
end

return store
