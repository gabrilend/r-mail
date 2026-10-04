#!/usr/bin/env luajit
-- fill-guide-examples.lua — write the service guide's example files from the
-- real service templates, so the guide shows exactly what the installer writes
--
-- The installer writes each mailbox's service file from a template in
-- scripts/.templates/services/.  The service guide shows an example of each.
-- Written by hand, those examples drifted from the real files; so they are
-- made from the templates instead (#614).  In docs/.templates/service.md an
-- example sits between two marker lines:
--
--   <!-- {{{ example: runit-run -->
--   ...everything here is rewritten...
--   <!-- }}} example -->
--
-- and this tool replaces what is between them with that template, filled
-- with the readable example values the docs use everywhere (/home/you/...,
-- SERVICE-NAME, YOURUSER), inside a fenced code block.  The docs build then
-- turns /home/you/... into the machine's real paths, as for every document.
--
-- Usage:
--   scripts/fill-guide-examples.lua              # rewrite the examples
--   scripts/fill-guide-examples.lua --check      # change nothing; exit 1 and
--                                                # name each example that no
--                                                # longer matches its template
--   scripts/fill-guide-examples.lua [--check] /path   # another checkout
--
-- Exit status: 0 written (or, with --check, all match); 1 otherwise.

-- {{{ configuration
local CHECK = false
local DIR = "/mnt/mtwo/programs/r-mail"
for _, a in ipairs(arg) do
    if a == "--check" then CHECK = true else DIR = a end
end
DIR = DIR:gsub("/+$", "")
local GUIDE = DIR .. "/docs/.templates/service.md"
local TEMPLATES = DIR .. "/scripts/.templates/services/"

-- The example values.  The paths are the docs' own placeholders, which the
-- docs build replaces with real ones; the rest are names a reader swaps.
local VALUES = {
    ROOT        = "/home/you/programs/email",
    MAILBOX     = "/home/you/mail",
    CONFIG_FILE = "/home/you/mail/config",
    LUA_BIN     = "/home/you/programs/email/deps/lua/bin/lua",
    SERVICE     = "SERVICE-NAME",
    SERVICE_LOG = "/tmp/SERVICE-NAME.log",
    USER        = "YOURUSER",
    HOME        = "/home/YOURUSER",
    PORT        = "8025",
}

-- The fence's language, by the template's ending; a template with none
-- (runit's run, OpenRC's init) is a shell script.
local LANGUAGE = { service = "ini", nix = "nix" }
-- }}}

-- {{{ local function fail
local function fail(msg)
    io.stderr:write("fill-guide-examples: " .. msg .. "\n")
    os.exit(1)
end
-- }}}

-- {{{ local function read
local function read(path)
    local f = io.open(path, "r")
    if not f then fail("cannot read " .. path) end
    local s = f:read("*a")
    f:close()
    return s
end
-- }}}

-- {{{ local function filled
-- The template, every @NAME@ replaced, inside a fenced block.  An @NAME@
-- with no value here is refused: the example would show a blank.
local function filled(name)
    local text = read(TEMPLATES .. name)
    text = text:gsub("@([A-Z_]+)@", function(key)
        local v = VALUES[key]
        if not v then fail(name .. " asks for @" .. key .. "@, which has no example value") end
        return v
    end)
    text = text:gsub("\n+$", "")
    local lang = LANGUAGE[name:match("%.(%w+)$") or ""] or "sh"
    return "```" .. lang .. "\n" .. text .. "\n```"
end
-- }}}

-- {{{ local function rebuild
-- Walks the guide line by line; copies everything outside an example, and
-- replaces each example's inside with its filled template.  Returns the new
-- text and the names of the examples whose inside changed.
local function rebuild(guide)
    local out, changed = {}, {}
    local inside, name, old = false, nil, nil
    -- every line ends in a newline, the last one included
    if not guide:match("\n$") then guide = guide .. "\n" end
    for line in guide:gmatch("([^\n]*)\n") do
        if not inside then
            out[#out + 1] = line
            name = line:match("^<!%-%- {{{ example: (%S+) %-%->$")
            if name then inside, old = true, {} end
        elseif line:match("^<!%-%- }}} example %-%->$") then
            local new = filled(name)
            if table.concat(old, "\n") ~= new then changed[#changed + 1] = name end
            out[#out + 1] = new
            out[#out + 1] = line
            inside = false
        else
            old[#old + 1] = line
        end
    end
    if inside then fail("the example for " .. name .. " has no end marker") end
    return table.concat(out, "\n") .. "\n", changed
end
-- }}}

local guide = read(GUIDE)
local new, changed = rebuild(guide)

-- Two paths: --check reports and changes nothing; otherwise the guide is
-- written, and only when something differs.
if CHECK then
    if #changed > 0 then
        io.stderr:write("fill-guide-examples: out of date: " .. table.concat(changed, ", ") .. "\n")
        io.stderr:write("  run scripts/fill-guide-examples.lua to rewrite them\n")
        os.exit(1)
    end
    print("every example matches its template")
    os.exit(0)
end
if new ~= guide then
    local f = io.open(GUIDE, "w")
    if not f then fail("cannot write " .. GUIDE) end
    f:write(new)
    f:close()
    print("rewrote " .. #changed .. " example(s): " .. table.concat(changed, ", "))
else
    print("every example already matches its template")
end
