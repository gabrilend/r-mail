#!/usr/bin/env lua
-- rmail-monitor.lua — what the rmail mailboxes on this machine are doing
-- SPDX-License-Identifier: AGPL-3.0-or-later WITH AdditionRef-rmail-hook-exception
--
-- Issue #713.  Each mailbox runs alone as its own service (#613), and
-- until this nothing on a machine could say which mailboxes it has,
-- which of them are running, or what version each one runs.
--
-- It describes itself by what it can do, not by what it is -- the issue's
-- "dave the barbarian" rather than "movement_controller".  Run with no
-- arguments, it says what it can do, one sentence each, with the words
-- that ask it to.  Every ability is one of those words:
--
--   list            every mailbox on this machine: running or not, port,
--                   version, and the service that starts it
--   tell MAILBOX    everything known about one of them
--   story [FROM [TO]]
--                   the chapters of transitions/ between two versions:
--                   what changed, why, and how
--   version         which rmail this checkout holds
--
-- `list --plain` prints one tab-separated line per mailbox and nothing
-- else, for other programs: the monitor is meant to be something other
-- tools talk to, and a line per mailbox is the plainest way to be that.
--
-- Where it looks.  A mailbox is found two ways, and the two are merged
-- by the config file each names, because the config is the mailbox
-- (#102):
--
--   * the service files of the five init systems install.sh writes for
--     (systemd user and system, runit, openrc, NixOS), whatever is
--     running here -- a machine that changed init systems keeps old
--     units -- taking any named rmail or rmail-*; each one's command
--     line names `rmail.lua <config>`
--   * the processes running now whose command line has rmail.lua in it,
--     so a mailbox started by hand is listed too
--
-- A mailbox whose config says `monitor = no` is not listed, told about
-- or counted.  That is the opt-out the issue asks for.
--
-- Versions.  rmail.lua carries RMAIL_VERSION, and a daemon writes the
-- one it is running to .state/version when it starts.  The monitor
-- keeps the last version it saw for each mailbox in
-- ${XDG_STATE_HOME:-~/.local/state}/rmail/monitor-versions, and when a
-- mailbox has moved past it says so once and names the story between.
-- It does not run anything against the mailbox when it does: a listing
-- that changes mail would be a surprise, and the changes between
-- versions so far have needed no migration.
--
-- For the tests, RMAIL_MONITOR_ROOT is put in front of every /etc path
-- and RMAIL_MONITOR_PROC replaces /proc.

local ROOT_PREFIX = os.getenv("RMAIL_MONITOR_ROOT") or ""
local PROC = os.getenv("RMAIL_MONITOR_PROC") or "/proc"
local HOME = os.getenv("HOME") or "/tmp"
local SCRIPT_DIR = (arg and arg[0] or ""):match("^(.*)/[^/]*$") or "."
local CHECKOUT = SCRIPT_DIR .. "/.."
local TRANSITIONS = CHECKOUT .. "/transitions"
local CACHE_DIR = (os.getenv("XDG_STATE_HOME") or (HOME .. "/.local/state")) .. "/rmail"
local CACHE = CACHE_DIR .. "/monitor-versions"

-- {{{ small helpers
local function read_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

local function shell_quote(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

-- the names in a directory, sorted; none when it does not exist
local function list_dir(dir)
    local names = {}
    local p = io.popen("ls -1 " .. shell_quote(dir) .. " 2>/dev/null")
    if p then
        for name in p:lines() do names[#names + 1] = name end
        p:close()
    end
    table.sort(names)
    return names
end

local function readlink(path)
    local p = io.popen("readlink " .. shell_quote(path) .. " 2>/dev/null")
    if not p then return nil end
    local s = p:read("*l")
    p:close()
    if s and s ~= "" then return s end
    return nil
end

-- /a/./b//c/../d -> /a/b/d, so one config named two ways is one mailbox
local function normalize(path)
    local parts = {}
    for part in path:gmatch("[^/]+") do
        if part == ".." then
            if #parts > 0 then table.remove(parts) end
        elseif part ~= "." then
            parts[#parts + 1] = part
        end
    end
    return "/" .. table.concat(parts, "/")
end

local function dirname(path)
    return path:match("^(.*)/[^/]*$") or "."
end

-- the same reading rmail.lua does: key = value, # comments, quotes kept
local function parse_config(path)
    local text = read_file(path)
    if not text then return nil end
    local cfg = {}
    for line in text:gmatch("[^\n]+") do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and line:sub(1, 1) ~= "#" then
            local key, value = line:match("^(%S+)%s*=%s*(.+)$")
            if key then cfg[key] = value:match("^(.-)%s*$") end
        end
    end
    return cfg
end
-- }}}

-- {{{ versions
local function version_parts(v)
    local parts = {}
    for n in tostring(v or ""):gmatch("%d+") do parts[#parts + 1] = tonumber(n) end
    return parts
end

-- -1, 0 or 1, comparing part by part as numbers: 0.10.0 is after 0.9.0
local function version_cmp(a, b)
    local pa, pb = version_parts(a), version_parts(b)
    for i = 1, math.max(#pa, #pb) do
        local x, y = pa[i] or 0, pb[i] or 0
        if x ~= y then return x < y and -1 or 1 end
    end
    return 0
end

-- the version a program file carries, read from its text and not run
local function program_version(path)
    local text = path and read_file(path)
    if not text then return nil end
    return text:match('\nlocal RMAIL_VERSION = "([^"\n]+)"')
end

local function ran_version(mailbox)
    local text = read_file(mailbox .. "/.state/version")
    return text and text:match("^%s*(%S+)") or nil
end

local function read_cache()
    local seen = {}
    local text = read_file(CACHE)
    if text then
        for version, mailbox in text:gmatch("([^\t\n]+)\t([^\n]+)") do
            seen[mailbox] = version
        end
    end
    return seen
end

local function write_cache(seen)
    os.execute("mkdir -p " .. shell_quote(CACHE_DIR))
    local keys = {}
    for mailbox in pairs(seen) do keys[#keys + 1] = mailbox end
    table.sort(keys)
    local f = io.open(CACHE .. ".tmp", "w")
    if not f then return false end
    for _, mailbox in ipairs(keys) do f:write(seen[mailbox], "\t", mailbox, "\n") end
    f:close()
    return os.rename(CACHE .. ".tmp", CACHE)
end
-- }}}

-- {{{ finding mailboxes
-- where install.sh puts a service file, per init system, and how a file
-- there is named: a directory holding `run`, or a file with a suffix
local function service_places()
    return {
        { dir = HOME .. "/.config/systemd/user", suffix = ".service", kind = "systemd user" },
        { dir = ROOT_PREFIX .. "/etc/systemd/system", suffix = ".service", kind = "systemd" },
        { dir = ROOT_PREFIX .. "/etc/sv", inner = "/run", kind = "runit" },
        { dir = ROOT_PREFIX .. "/etc/init.d", suffix = "", kind = "openrc" },
        { dir = ROOT_PREFIX .. "/etc/nixos", suffix = ".nix", kind = "nixos" },
    }
end

-- the program and config a command line names: the word that is
-- rmail.lua or ends in /rmail.lua, and the word after it.  A service
-- file's line can wrap them in its own syntax (openrc's
-- command_args="...", NixOS's ExecStart = "...";), which is peeled off.
local function program_and_config(words)
    for i, w in ipairs(words) do
        local program = w:match('([^="]*)$')
        if (program == "rmail.lua" or program:match("/rmail%.lua$")) and words[i + 1] then
            local config = words[i + 1]:gsub('^"', ""):gsub('"?;?$', "")
            return program, config
        end
    end
    return nil
end

local function from_services(found)
    for _, place in ipairs(service_places()) do
        for _, entry in ipairs(list_dir(place.dir)) do
            local name, file
            if place.inner then
                name, file = entry, place.dir .. "/" .. entry .. place.inner
            elseif place.suffix == "" or entry:sub(-#place.suffix) == place.suffix then
                name = place.suffix == "" and entry or entry:sub(1, -#place.suffix - 1)
                file = place.dir .. "/" .. entry
            end
            if name and (name == "rmail" or name:match("^rmail%-")) then
                local text = read_file(file)
                for line in (text or ""):gmatch("[^\n]+") do
                    local words = {}
                    for w in line:gmatch("%S+") do words[#words + 1] = w end
                    local program, config = program_and_config(words)
                    if program and config:sub(1, 1) == "/" then
                        found(normalize(config), { program = program,
                            service = name, service_kind = place.kind, service_file = file })
                        break
                    end
                end
            end
        end
    end
end

local function from_processes(found)
    for _, pid in ipairs(list_dir(PROC)) do
        if pid:match("^%d+$") then
            local raw = read_file(PROC .. "/" .. pid .. "/cmdline")
            if raw and raw:find("rmail.lua", 1, true) then
                local words = {}
                for w in raw:gmatch("[^%z]+") do words[#words + 1] = w end
                local program, config = program_and_config(words)
                if program then
                    local cwd = readlink(PROC .. "/" .. pid .. "/cwd") or "/"
                    if config:sub(1, 1) ~= "/" then config = cwd .. "/" .. config end
                    if program:sub(1, 1) ~= "/" then program = cwd .. "/" .. program end
                    -- a process naming no readable config is not a mailbox:
                    -- an editor open on rmail.lua, say
                    if read_file(config) then
                        found(normalize(config), { program = normalize(program), pid = tonumber(pid) })
                    end
                end
            end
        end
    end
end

-- every mailbox, merged by config, opted-out ones left out; sorted by path
local function mailboxes()
    local by_config, order = {}, {}
    local function found(config, facts)
        local m = by_config[config]
        if not m then
            m = { config = config, mailbox = dirname(config), pids = {} }
            by_config[config] = m
            order[#order + 1] = m
        end
        if facts.pid then
            m.pids[#m.pids + 1] = facts.pid
            m.running_program = m.running_program or facts.program
        end
        if facts.service then
            m.service, m.service_kind, m.service_file = facts.service, facts.service_kind, facts.service_file
            m.program = m.program or facts.program
        end
    end
    from_services(found)
    from_processes(found)

    local out = {}
    for _, m in ipairs(order) do
        local cfg = parse_config(m.config)
        local opt = cfg and tostring(cfg.monitor or ""):lower():gsub("[\"']", "")
        if not (opt == "no" or opt == "false" or opt == "off") then
            m.cfg = cfg
            m.port = cfg and cfg.port
            m.name = cfg and cfg.name
            table.sort(m.pids)
            m.program = m.running_program or m.program
            m.program_version = program_version(m.program)
            m.ran_version = ran_version(m.mailbox)
            m.version = m.ran_version or m.program_version
            out[#out + 1] = m
        end
    end
    table.sort(out, function(a, b) return a.mailbox < b.mailbox end)
    return out
end
-- }}}

-- {{{ what a mailbox is doing, in words
local function status_words(m)
    if not m.cfg then return "no config at " .. m.config end
    if #m.pids > 1 then
        return "running twice (pids " .. table.concat(m.pids, ", ") .. ")"
    elseif #m.pids == 1 then
        return "running (pid " .. m.pids[1] .. ")"
    end
    return "stopped"
end

-- a note when the program on disk is newer than what last ran
local function pending_words(m)
    if m.ran_version and m.program_version and version_cmp(m.program_version, m.ran_version) > 0 then
        if #m.pids > 0 then
            return "restart it to run " .. m.program_version
        end
        return "runs " .. m.program_version .. " when started"
    end
    return nil
end

local function service_words(m)
    if m.service then return m.service .. " (" .. m.service_kind .. ")" end
    return "no service file: started by hand"
end
-- }}}

local abilities = {
    { "list", "I can list every rmail mailbox on this machine, running or not",
      "list [--plain]" },
    { "tell", "I can tell you everything I know about one of them",
      "tell MAILBOX" },
    { "story", "I can tell you the story of how a version was built, change by change",
      "story [FROM [TO]]" },
    { "version", "I can tell you which rmail this checkout holds",
      "version" },
}

local cannot_yet = {
    "restart a mailbox",
    "run a script against a mailbox's hooks",
    "relay a message between mailboxes",
}

local commands = {}

function commands.help()
    print("rmail monitor.  What I can do:")
    print("")
    for _, a in ipairs(abilities) do
        print("  " .. a[2] .. ":")
        print("      rmail-monitor.lua " .. a[3])
    end
    print("")
    print("What I cannot do yet (#713): " .. table.concat(cannot_yet, ", ") .. ".")
    return 0
end
commands["what-can-you-do"] = commands.help
commands["--help"] = commands.help
commands["-h"] = commands.help

function commands.version()
    print("rmail " .. (program_version(CHECKOUT .. "/rmail.lua") or "unknown"))
    return 0
end

-- the versions transitions/ has a chapter for, in order
local function chapters()
    local list = {}
    for _, name in ipairs(list_dir(TRANSITIONS)) do
        local v = name:match("^(%d[%d%.]*)%.md$")
        if v then list[#list + 1] = v end
    end
    table.sort(list, function(a, b) return version_cmp(a, b) < 0 end)
    return list
end

local function story_command(from, to)
    return "rmail-monitor.lua story " .. from .. " " .. to
end

function commands.list(args)
    local plain = args[1] == "--plain"
    local found = mailboxes()
    local seen = read_cache()
    local news, changed = {}, false
    for _, m in ipairs(found) do
        if m.version then
            local before = seen[m.mailbox]
            if before and version_cmp(m.version, before) > 0 then
                news[m.mailbox] = before
            end
            if not before or version_cmp(m.version, before) > 0 then
                seen[m.mailbox] = m.version
                changed = true
            end
        end
    end
    -- written only when it learned something, so a machine with no
    -- mailboxes is left with no file
    if changed then write_cache(seen) end

    if plain then
        for _, m in ipairs(found) do
            print(table.concat({
                m.mailbox,
                #m.pids > 0 and "running" or "stopped",
                #m.pids > 0 and table.concat(m.pids, ",") or "-",
                m.port or "-",
                m.version or "-",
                m.service or "-",
            }, "\t"))
        end
        return 0
    end

    if #found == 0 then
        print("No rmail mailboxes on this machine.")
        return 0
    end
    print(#found .. " rmail mailbox" .. (#found == 1 and "" or "es") .. " on this machine:")
    for _, m in ipairs(found) do
        print("")
        print("  " .. m.mailbox)
        print("      " .. status_words(m) .. ", port " .. (m.port or "?")
            .. ", version " .. (m.version or "unknown"))
        print("      " .. service_words(m))
        local pending = pending_words(m)
        if pending then print("      " .. pending) end
        if news[m.mailbox] then
            print("      new since I last looked: " .. news[m.mailbox] .. " -> " .. m.version
                .. "; what changed: " .. story_command(news[m.mailbox], m.version))
        end
    end
    return 0
end

function commands.tell(args)
    local want = args[1]
    if not want then
        io.stderr:write("tell which mailbox?  rmail-monitor.lua tell MAILBOX\n")
        return 2
    end
    local abs = want:sub(1, 1) == "/" and want or ((os.getenv("PWD") or ".") .. "/" .. want)
    abs = normalize(abs)
    for _, m in ipairs(mailboxes()) do
        if m.mailbox == abs or m.config == abs or m.service == want then
            print(m.mailbox)
            print("  config:        " .. m.config)
            print("  status:        " .. status_words(m))
            print("  name:          " .. (m.name or "?"))
            print("  port:          " .. (m.port or "?"))
            print("  last ran:      " .. (m.ran_version or "never, as far as .state/version says"))
            print("  program:       " .. (m.program or "?") .. " (" .. (m.program_version or "no version") .. ")")
            print("  service:       " .. service_words(m))
            if m.service_file then print("  service file:  " .. m.service_file) end
            local pending = pending_words(m)
            if pending then print("  note:          " .. pending) end
            return 0
        end
    end
    io.stderr:write("no mailbox " .. want .. " on this machine")
    io.stderr:write(" (or it asked not to be listed)\n")
    return 1
end

function commands.story(args)
    local from = args[1] or "0"
    local to = args[2] or program_version(CHECKOUT .. "/rmail.lua") or "0"
    local told = 0
    for _, v in ipairs(chapters()) do
        if version_cmp(v, from) > 0 and version_cmp(v, to) <= 0 then
            if told > 0 then print("") end
            io.write(read_file(TRANSITIONS .. "/" .. v .. ".md") or "")
            told = told + 1
        end
    end
    if told == 0 then
        print("Nothing changed between " .. from .. " and " .. to .. " that has a chapter in transitions/.")
    end
    return 0
end

local name = arg and arg[1] or "help"
local command = commands[name]
if not command then
    io.stderr:write("I cannot " .. name .. ".  ")
    commands.help()
    os.exit(2)
end
local rest = {}
for i = 2, #(arg or {}) do rest[#rest + 1] = arg[i] end
os.exit(command(rest))
