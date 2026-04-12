#!/usr/bin/env lua
-- rmail-client.lua — thin client sync daemon
--
-- Keeps a local mailbox directory in sync with a home rmail daemon.
-- The user reads/writes files with their own tools (editor, cat, etc).
--
-- Usage:
--   lua rmail-client.lua [--host HOST] [--port PORT] [--token TOKEN]
--                        [--dir PATH] [--interval SECONDS]
--
-- The local mailbox layout mirrors the daemon:
--   ~/mail-remote/
--     inbox/        — received messages (read with any editor)
--     outbox/       — write a file here to send it
--     contacts      — synced contacts file
--     attachments/  — downloaded attachments

local script_dir = arg[0]:match("(.*/)") or "./"
package.path  = script_dir .. "../shared/?.lua;" .. package.path
package.cpath = script_dir .. "../shared/?.so;" ..
                script_dir .. "../../libs/?.so;" .. package.cpath

local socket   = require("socket")
local protocol = require("protocol")
local store    = require("store")
local sync     = require("sync")
local watcher  = require("watcher")

-- ── Parse arguments ────────────────────────────────────────────────────

local function parse_args()
    local config = {
        host = nil, port = nil, token = nil,
        dir = (os.getenv("HOME") or os.getenv("USERPROFILE")) .. "/mail-remote",
        interval = 300,  -- 5 minutes default
    }
    local i = 1
    while i <= #arg do
        if     arg[i] == "--host"     then i = i + 1; config.host = arg[i]
        elseif arg[i] == "--port"     then i = i + 1; config.port = tonumber(arg[i])
        elseif arg[i] == "--token"    then i = i + 1; config.token = arg[i]
        elseif arg[i] == "--dir"      then i = i + 1; config.dir = arg[i]
        elseif arg[i] == "--interval" then i = i + 1; config.interval = tonumber(arg[i])
        end
        i = i + 1
    end
    return config
end

local function prompt(msg)
    io.write(msg); io.flush()
    return io.read("*l")
end

local function log(fmt, ...)
    io.write(os.date("%Y-%m-%d %H:%M:%S ") .. string.format(fmt, ...) .. "\n")
    io.flush()
end

-- ── Main ───────────────────────────────────────────────────────────────

local function main()
    local config = parse_args()

    if not config.host then config.host = prompt("Home daemon host: ") end
    if not config.port then
        local p = prompt("Port [8025]: ")
        config.port = tonumber(p) or 8025
    end
    if not config.token then config.token = prompt("Device token: ") end

    if not config.host or config.host == "" then
        io.stderr:write("error: host is required\n"); os.exit(1)
    end
    if not config.token or config.token == "" then
        io.stderr:write("error: token is required\n"); os.exit(1)
    end

    -- Set up local store
    local mailbox = store.new(config.dir, "0")
    log("mailbox: %s", mailbox.root)

    -- Connect
    local client = protocol.new(config.host, config.port, config.token)
    log("connecting to %s:%d", config.host, config.port)
    local ok, err = client:connect()
    if not ok then
        log("connection failed: %s", err or "unknown")
        os.exit(1)
    end
    log("connected")

    -- Initial sync
    local result, serr = sync.run(client, mailbox)
    if result then
        log("synced: %s (%d new)",
            result.mailbox_name or config.host, result.new_messages or 0)
    else
        log("sync error: %s", serr or "unknown")
    end

    -- ── Watch outbox and contacts for local changes ────────────────────

    local outbox_fd, outbox_sock
    local contacts_fd, contacts_sock

    if watcher.available then
        local mask = watcher.IN_CLOSE_WRITE + watcher.IN_CREATE +
                     watcher.IN_DELETE + watcher.IN_MOVED_TO
        outbox_fd = watcher.init()
        if outbox_fd then
            watcher.add_watch(outbox_fd, mailbox.outbox_dir, mask)
            outbox_sock = setmetatable({}, {
                __index = { getfd = function() return outbox_fd end }
            })
            log("watching outbox for changes")
        end

        local file_mask = watcher.IN_CLOSE_WRITE + watcher.IN_MODIFY
        contacts_fd = watcher.init()
        if contacts_fd then
            watcher.add_watch(contacts_fd, mailbox.contacts_file, file_mask)
            contacts_sock = setmetatable({}, {
                __index = { getfd = function() return contacts_fd end }
            })
            log("watching contacts for changes")
        end
    else
        log("no file watcher available — using interval sync only")
    end

    -- ── Sync loop ──────────────────────────────────────────────────────

    local last_sync = socket.gettime()
    log("sync interval: %ds — edit files in %s/", config.interval, mailbox.root)

    while true do
        local recvt = {}
        if outbox_sock then recvt[#recvt + 1] = outbox_sock end
        if contacts_sock then recvt[#recvt + 1] = contacts_sock end

        local time_to_sync = math.max(0, config.interval - (socket.gettime() - last_sync))
        local timeout = #recvt > 0 and time_to_sync or config.interval
        local readable = socket.select(
            #recvt > 0 and recvt or nil, nil, timeout)

        local outbox_changed = false
        local contacts_changed = false

        if readable then
            for _, sock in ipairs(readable) do
                if sock == outbox_sock then
                    watcher.read(outbox_fd)
                    outbox_changed = true
                elseif sock == contacts_sock then
                    watcher.read(contacts_fd)
                    contacts_changed = true
                end
            end
        end

        local now = socket.gettime()
        if outbox_changed or contacts_changed or now - last_sync >= config.interval then
            if outbox_changed then log("outbox changed") end
            if contacts_changed then log("contacts changed") end

            result, serr = sync.run(client, mailbox)
            if result then
                local msg = "synced"
                if result.new_messages and result.new_messages > 0 then
                    msg = msg .. string.format(" (%d new)", result.new_messages)
                end
                log(msg)
            else
                log("sync error: %s", serr or "unknown")
                client:close()
            end
            last_sync = now

            -- Drain events from our own sync writes
            if outbox_fd then watcher.read(outbox_fd) end
            if contacts_fd then watcher.read(contacts_fd) end
        end
    end
end

main()
