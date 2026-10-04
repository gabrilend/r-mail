#!/usr/bin/env luajit
-- generate-phase-progress.lua — write each phase's progress file from the issue files themselves
--
-- Every phase of the project keeps a file, issues/phase-N-progress.md,
-- saying what the phase is about, what in it is done and what is open.
-- Written by hand, such a file goes stale the moment an issue moves; so it
-- is generated: the phase's theme from the table below, and for each issue
-- its number, its title, and the first sentence of its Current Behavior
-- (what exists now).  Done means the file sits in issues/completed/, the
-- same rule the progress dashboard uses.  Counts are not written down —
-- the file names the dashboard command that gives them — so they cannot
-- go stale either.
--
-- Anything below the line "<!-- notes: kept when regenerated -->" is the
-- owner's and is carried over untouched.
--
-- Usage:
--   scripts/generate-phase-progress.lua              # this checkout
--   scripts/generate-phase-progress.lua /path        # another checkout
--
-- Exit status: 0 written; 1 an issue file named for a phase that has no
-- theme below (add the phase to PHASES first).

-- {{{ configuration
local DIR = arg[1] or "/mnt/mtwo/programs/r-mail"
DIR = DIR:gsub("/+$", "")
local DASHBOARD = "/home/ritz/programming/ai-stuff/scripts/progress-dashboard.lua"
local NOTES_MARK = "<!-- notes: kept when regenerated -->"

-- The nine phases (#621, 2026-10-04).  Foundations first: a phase stands
-- on the ones before it.
local PHASES = {
    ["1"] = {"The daemon's core",
        "One daemon serving one mailbox: starting up, the main loop, the sealed frames everything travels in, the sync cycle and its per-contact timers, the log."},
    ["2"] = {"Messages as files",
        "A message is a file: the outbox format, sending and receiving, edits, deletes in both directions, dates, and the hooks that let the owner's scripts take part."},
    ["3"] = {"Attachments and consent",
        "No file moves before its recipient says yes; then it travels in checked pieces, is unpacked under strict rules, and every recipient's answer is kept."},
    ["4"] = {"Addresses and networking",
        "Knowing our own address, telling contacts when it changes, reaching them at whichever of their addresses answers, the router, IPv6 and the local network."},
    ["5"] = {"Contacts, identity and saved state",
        "The contacts file, the mailbox's name for itself, and what the daemon keeps about people in its records."},
    ["6"] = {"Installation, services, drives and the documents",
        "Installing rmail, running each mailbox as a service, portable drives, other systems, and the documents that describe it all."},
    ["7"] = {"Helpers, the owner's own devices, desktop tools",
        "Shell helpers for a mailbox's files, the door the home daemon opens for the owner's own devices, and the desktop programs that use it."},
    ["8"] = {"The Android client",
        "The phone app: a copy of each home mailbox, kept in step through the door of phase 7, and its screens."},
    ["9"] = {"Privacy against watchers; new transports",
        "Hiding from someone watching the network what the sealed frames do not hide, and carrying rmail over other networks and machines."},
}
-- }}}

-- {{{ local function read
local function read(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("*a"); f:close()
    return s
end
-- }}}

-- {{{ local function list
local function list(dir)
    local out = {}
    local h = io.popen("ls -1 '" .. dir .. "' 2>/dev/null")
    for name in h:lines() do out[#out + 1] = name end
    h:close()
    return out
end
-- }}}

-- {{{ local function summary
-- The title and the first sentence of the Current Behavior section, both
-- on one line, markdown kept as it is.
-- The paragraph is the first one of prose: not a heading, a table, a
-- list, code, a "Built:"-style label or a status line ("Completed ...").  From Current Behavior when the
-- issue has one; older issues without it give their first prose anywhere.
local function first_prose(section)
    -- code blocks first: a blank line inside one would split it into
    -- paragraphs that look like prose
    section = section:gsub("```.-```", "")
    local first_item
    for para in (section .. "\n\n"):gmatch("(.-)\n%s*\n") do
        local p = para:gsub("^%s+", "")
        local lead = p:match("^[^\n]*") or ""
        if p ~= "" and not lead:match("^#") and not lead:match("^|") and not lead:match("^```")
           and not lead:match("^[%-%*] ") and not lead:match("^%d+%. ") and not para:match("^    ")
           and not (lead:match("^[%w ]+:$") and #lead < 25) and not lead:match("^%*%*[^*]+:%*%*$")
           and not lead:match("^Completed") and not lead:match("^FIXED") and not lead:match("^Open[%.,]")
           and not lead:match("^%*%*Completed") then
            return p
        end
        -- a section that is only a list: its first item, if nothing better
        if not first_item and lead:match("^[%-%*] ") then first_item = lead:gsub("^[%-%*] ", "") .. " " .. (p:match("^[^\n]*\n([^%-%*][^\n]*)") or "") end
    end
    return first_item or ""
end

local function summary(text)
    local title = text:match("^#%s+#?%d%d%d+%l?%s+[—%-]+%s+([^\n]+)")
        or text:match("^#%s+#?new%-[%w%-]+%s+[—%-]+%s+([^\n]+)")
        or text:match("^#%s+([^\n]+)") or "?"
    local body = text:match("\n## Current Behavior%s*\n(.-)\n## ") or text:match("\n## Current Behavior%s*\n(.*)$")
    local para = first_prose(body or "")
    if para == "" then para = first_prose((text:gsub("^[^\n]*\n", ""))) end
    -- a bold lead-in label ("**The offer.**  Once ...") is not the sentence
    para = para:gsub("^%*%*[^*]+[%.:]%*%*%s+", "")
    para = para:gsub("%*%*", ""):gsub("%s+", " "):gsub("^%s+", "")
    local first = para:match("^(.-[%.%!%?])%s") or para:match("^(.-[%.%!%?])$") or para
    if #first > 260 then first = first:sub(1, 257) .. "..." end
    return title, first
end
-- }}}

-- {{{ local function issues_by_phase
-- { [phase] = { {id, stem, done, title, first}, ... } }, and the names of
-- issue files whose phase has no theme.
local function issues_by_phase()
    local by, strays = {}, {}
    for _, sub in ipairs({{"issues", false}, {"issues/completed", true}}) do
        for _, name in ipairs(list(DIR .. "/" .. sub[1])) do
            local stem = name:match("^(.+)%.md$")
            local id = stem and stem:match("^(%d%d%d%l?)%-")
            if id then
                local phase = id:sub(1, 1)
                if not PHASES[phase] then
                    strays[#strays + 1] = name
                else
                    local title, first = summary(read(DIR .. "/" .. sub[1] .. "/" .. name) or "")
                    by[phase] = by[phase] or {}
                    by[phase][#by[phase] + 1] = {id = id, stem = stem, done = sub[2],
                        title = title, first = first, dir = sub[1]}
                end
            end
        end
    end
    for _, l in pairs(by) do
        table.sort(l, function(a, b) return a.id < b.id end)
    end
    return by, strays
end
-- }}}

-- {{{ local function render
local function render(phase, issues, notes)
    local theme = PHASES[phase]
    local out = {
        "# Phase " .. phase .. " progress — " .. theme[1], "",
        theme[2], "",
        "Generated by `scripts/generate-phase-progress.lua` from the issue files;",
        "regenerate it rather than editing above the notes line.  Counts:",
        "",
        "    " .. DASHBOARD .. " " .. DIR .. " -p " .. phase,
        "",
    }
    for _, part in ipairs({{"Done", true}, {"Open", false}}) do
        out[#out + 1] = "## " .. part[1]
        out[#out + 1] = ""
        local any = false
        for _, i in ipairs(issues or {}) do
            if i.done == part[2] then
                any = true
                out[#out + 1] = string.format("- **[#%s](%s) — %s**  %s",
                    i.id, (i.done and "completed/" or "") .. i.stem .. ".md", i.title, i.first)
            end
        end
        if not any then out[#out + 1] = "(none)" end
        out[#out + 1] = ""
    end
    out[#out + 1] = NOTES_MARK
    out[#out + 1] = notes or ""
    -- (in parentheses: gsub also returns a count, which must not be written)
    return (table.concat(out, "\n"):gsub("\n*$", "\n"))
end
-- }}}

-- {{{ local function main
local function main()
    local by, strays = issues_by_phase()
    if #strays > 0 then
        io.stderr:write("issue files in a phase with no theme in PHASES:\n")
        for _, s in ipairs(strays) do io.stderr:write("  " .. s .. "\n") end
        return 1
    end
    local phases = {}
    for p in pairs(PHASES) do phases[#phases + 1] = p end
    table.sort(phases)
    for _, p in ipairs(phases) do
        local path = DIR .. "/issues/phase-" .. p .. "-progress.md"
        local old = read(path) or ""
        local s = old:find(NOTES_MARK, 1, true)
        local notes = s and old:sub(s + #NOTES_MARK):gsub("^\n", "") or ""
        local f = assert(io.open(path, "w"))
        f:write(render(p, by[p], notes))
        f:close()
        local done, open = 0, 0
        for _, i in ipairs(by[p] or {}) do if i.done then done = done + 1 else open = open + 1 end end
        print(string.format("phase %s: %d done, %d open -> %s", p, done, open, path))
    end
    return 0
end
-- }}}

os.exit(main())
