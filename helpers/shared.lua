#!/usr/bin/env lua
-- helpers/shared.lua — bi-directional file sharing between contacts
--
-- on_update hook that makes living messages two-way: when a remote edit
-- arrives, mirror it into your outbox so your contacts see it too.
--
-- Configure in ~/.config/rmail/config:
--   on_update = /path/to/helpers/shared.lua
--
-- Called by the daemon on each living message update.  Mirrors the new
-- body into the matching outbox file and passes it through to stdout
-- (so the inbox write proceeds normally).  Auto-creates the outbox file
-- on first update with "to: <sender>".
--
-- Loop prevention: the hook only writes when the body has actually
-- changed.  The daemon's body checksum check is the second safety net —
-- identical content never generates network traffic.
--
-- Security: same as regular messages (AES-256-GCM, contact tokens).
-- If the outbox file has multiple "to:" lines (e.g. to: bob, to: gary),
-- all recipients see all edits.  The outbox owner is the hub.

local mail_dir = os.getenv("RMAIL_MAILDIR") or (os.getenv("HOME") .. "/mail")
local outbox_dir = mail_dir .. "/outbox"

local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local text = f:read("*a")
    f:close()
    return text
end

-- Skip to:/attach: header lines, return everything after
local function parse_body(text)
    local pos = 1
    while pos <= #text do
        local line_end = text:find("\n", pos) or #text + 1
        local line = text:sub(pos, line_end - 1):lower()
        if line:match("^to:") or line:match("^attach:") then
            pos = line_end + 1
        else
            break
        end
    end
    return text:sub(pos)
end

-- Return the to:/attach: header block as a string
local function parse_header(text)
    local lines = {}
    local pos = 1
    while pos <= #text do
        local line_end = text:find("\n", pos) or #text + 1
        local line = text:sub(pos, line_end - 1)
        if line:lower():match("^to:") or line:lower():match("^attach:") then
            lines[#lines + 1] = line
            pos = line_end + 1
        else
            break
        end
    end
    return table.concat(lines, "\n")
end

-- ---- main ----

local sender     = arg[1]  -- who sent the update
local inbox_path = arg[2]  -- path to existing inbox file
local new_body   = arg[3]  -- updated content

-- pass update through to inbox (stdout replaces body)
io.write(new_body)

-- mirror to outbox
local filename = inbox_path:match("([^/]+)$")
local outbox_path = outbox_dir .. "/" .. filename
local outbox_text = read_file(outbox_path)

if outbox_text then
    local old_body = parse_body(outbox_text)
    if old_body == new_body then os.exit(0) end
    -- preserve existing headers, replace body
    local header = parse_header(outbox_text)
    local f = io.open(outbox_path, "w")
    if f then
        f:write(header .. "\n" .. new_body)
        f:close()
    end
else
    -- first mirror: create outbox file with to: pointing back
    local f = io.open(outbox_path, "w")
    if f then
        f:write("to: " .. sender .. "\n" .. new_body)
        f:close()
    end
end
