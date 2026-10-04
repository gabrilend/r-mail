#!/usr/bin/env luajit
-- renumber-issues.lua — give issue files new numbers, and make every mention of them follow
--
-- Issue files are named {phase}{id}-{words}.md (404f-arriving-pieces-…),
-- and their numbers are quoted all over a project: "#404" in comments,
-- docs, tests, other issues and the phone app's source; whole file names
-- in links.  Moving an issue to another phase means changing its number
-- everywhere at once, which by hand is how references get missed.  This
-- tool reads a mapping (old number -> new number), checks it, renames the
-- files and rewrites every mention in the project's text files.
--
-- It swaps in two steps: every old mention becomes a placeholder first,
-- and only then do placeholders become new numbers.  So an issue moving
-- to a number another issue is moving away from cannot be rewritten
-- twice.  The conversation transcripts (llm-transcripts/) are never
-- rewritten: they record what was said at the time.
--
-- Usage:
--   scripts/renumber-issues.lua <mapping file> [--dry-run]
--   scripts/renumber-issues.lua <project dir> <mapping file> [--dry-run]
--
-- The mapping file, one issue per line, blank lines and # comments ignored:
--
--   404f 312           an issue numbered 404f becomes 312
--   new-sync-cycle 103 a file issues/new-sync-cycle.md (a blueprint not
--                      numbered yet) becomes 103-sync-cycle.md; cite such
--                      a blueprint as "#new-sync-cycle" and the citation
--                      becomes "#103"
--
-- It refuses, changing nothing, when: an old number names no issue file;
-- two lines give the same new number; a new number is held by an issue
-- the mapping does not move.  It reports every file it changed, and every
-- line still holding a bare old number near an issue mention, for a
-- person to check (a range like "#302–304" carries the second number with
-- no #, and is left alone on purpose: three-digit numbers mean many other
-- things, HTTP 404 among them).
--
-- Exit status: 0 done (or dry run clean), 1 refused.

-- {{{ configuration
local DIR = "/mnt/mtwo/programs/r-mail"
local args = {...}
local dry_run = false
for i = #args, 1, -1 do
    if args[i] == "--dry-run" then dry_run = true; table.remove(args, i) end
end
local MAPPING
if #args == 2 then DIR, MAPPING = args[1], args[2]
elseif #args == 1 then MAPPING = args[1]
else
    io.stderr:write("usage: renumber-issues.lua [project dir] <mapping file> [--dry-run]\n")
    os.exit(1)
end
DIR = DIR:gsub("/+$", "")
-- }}}

-- {{{ local function read_file
local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("*a"); f:close()
    return s
end
-- }}}

-- {{{ local function write_file
local function write_file(path, text)
    local f = assert(io.open(path, "wb"))
    f:write(text); f:close()
end
-- }}}

-- {{{ local function lines_of
-- Lines of a command's output.  Read-only listings only.
local function lines_of(cmd)
    local out = {}
    local h = assert(io.popen(cmd))
    for line in h:lines() do out[#out + 1] = line end
    h:close()
    return out
end
-- }}}

-- {{{ local function quote
local function quote(s) return "'" .. s:gsub("'", "'\\''") .. "'" end
-- }}}

-- {{{ local function find_issues
-- Every issue file: { [key] = {dir = "issues" | "issues/completed",
-- stem = file name without .md, slug = the words after the number} }.
-- The key is the number ("404f"), or the whole stem for an unnumbered
-- blueprint ("new-sync-cycle").  Progress files are not issues.
local function find_issues()
    local issues = {}
    for _, sub in ipairs({"issues", "issues/completed"}) do
        for _, name in ipairs(lines_of("ls -1 " .. quote(DIR .. "/" .. sub))) do
            local stem = name:match("^(.+)%.md$")
            if stem and not stem:match("^phase%-") then
                local id, slug = stem:match("^(%d%d%d+%l?)%-(.+)$")
                if id then
                    issues[id] = {dir = sub, stem = stem, slug = slug}
                elseif stem:match("^new%-") then
                    issues[stem] = {dir = sub, stem = stem, slug = stem:sub(5)}
                end
            end
        end
    end
    return issues
end
-- }}}

-- {{{ local function read_mapping
-- The mapping file -> list of {old, new}, in file order.
local function read_mapping(path)
    local text = read_file(path)
    if not text then return nil, "cannot read " .. path end
    local pairs_list = {}
    local n = 0
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        n = n + 1
        line = line:gsub("#.*$", ""):match("^%s*(.-)%s*$")
        if line ~= "" then
            local old, new = line:match("^(%S+)%s+(%S+)$")
            if not old or not new:match("^%d%d%d+%l?$") then
                return nil, string.format("%s:%d: expected '<old> <new number>', got: %s", path, n, line)
            end
            pairs_list[#pairs_list + 1] = {old = old, new = new}
        end
    end
    return pairs_list
end
-- }}}

-- {{{ local function check_mapping
-- Refuse a mapping that cannot be carried out cleanly.  Returns the moves
-- (old != new) or nil and every problem found.
local function check_mapping(mapping, issues)
    local problems, targets, moving, moves = {}, {}, {}, {}
    for _, m in ipairs(mapping) do moving[m.old] = true end
    for _, m in ipairs(mapping) do
        if not issues[m.old] then
            problems[#problems + 1] = "no issue file for " .. m.old
        end
        if targets[m.new] then
            problems[#problems + 1] = "two issues get " .. m.new .. ": " .. targets[m.new] .. " and " .. m.old
        end
        targets[m.new] = m.old
        if issues[m.new] and not moving[m.new] then
            problems[#problems + 1] = m.new .. " is held by " .. issues[m.new].stem .. ", which the mapping does not move"
        end
        if m.old ~= m.new then moves[#moves + 1] = m end
    end
    if #problems > 0 then return nil, problems end
    return moves
end
-- }}}

-- {{{ local function text_files
-- The project's text files, tracked or new, minus transcripts.  A file
-- holding a zero byte is not text.
local function text_files()
    local out = {}
    for _, rel in ipairs(lines_of("git -C " .. quote(DIR) .. " ls-files --cached --others --exclude-standard")) do
        if not rel:match("^llm%-transcripts/") then
            local body = read_file(DIR .. "/" .. rel)
            if body and not body:find("\0", 1, true) then out[#out + 1] = rel end
        end
    end
    return out
end
-- }}}

-- {{{ local function rewrite
-- Every mention of a moving issue in `text` -> its placeholder, then each
-- placeholder -> the new form.  Returns the new text, how many mentions
-- changed, and the text as it stood with placeholders in (what is still
-- an old number there was not recognised as a mention).  `own_key` is the
-- issue this file is, if it is one: its title line may carry its number
-- with no #.
--
-- Mentions recognised:
--   the file's stem          404f-arriving-pieces-wait-on-disk
--   #number                  #404f, not #404fx and not #4041
--   issue / issues number    "issue 404", "issues 371"
--   the title line           "# 100 - Lua..." in issue 100's own file
local function rewrite(text, moves_by_old, own_key)
    local count = 0
    local slots = {}          -- placeholder index -> replacement text
    local function slot(replacement)
        slots[#slots + 1] = replacement
        count = count + 1
        -- a letter before the index, so a placeholder never reads as a number
        return "\1P" .. #slots .. "\2"
    end
    -- whole stems, longest first, so 404f-x is not cut by 404-x
    local stems = {}
    for _, m in pairs(moves_by_old) do stems[#stems + 1] = m end
    table.sort(stems, function(a, b) return #a.old_stem > #b.old_stem end)
    -- "#new-sync-cycle", an unnumbered blueprint cited the way a numbered
    -- issue is: it becomes "#112", not "#112-sync-cycle"
    for _, m in ipairs(stems) do
        if m.old_stem:match("^new%-") then
            local s = 1
            while true do
                local a, b = text:find("#" .. m.old_stem, s, true)
                if not a then break end
                local after = text:sub(b + 1, b + 1)
                if after:match("[%w%-]") then
                    s = b + 1    -- the start of a longer name
                else
                    local ph = slot(m.new)
                    text = text:sub(1, a) .. ph .. text:sub(b + 1)
                    s = a + 1 + #ph
                end
            end
        end
    end
    -- a stem is a whole name: not part of a longer one on either side
    -- ("new-delta" in "new-deltas" is not a mention)
    for _, m in ipairs(stems) do
        local s = 1
        while true do
            local a, b = text:find(m.old_stem, s, true)
            if not a then break end
            local before = a > 1 and text:sub(a - 1, a - 1) or ""
            local after = text:sub(b + 1, b + 1)
            if before:match("[%w%-]") or after:match("[%w%-]") then
                s = b + 1
            else
                local ph = slot(m.new_stem)
                text = text:sub(1, a - 1) .. ph .. text:sub(b + 1)
                s = a + #ph
            end
        end
    end
    -- #number, bounded on the right
    text = text:gsub("#(%d%d%d+%l?)(%w?)", function(id, after)
        local m = moves_by_old[id]
        if not m or after ~= "" then return nil end
        return "#" .. slot(m.new)
    end)
    -- "issue 404", "issues 371", "Issue 404"
    text = text:gsub("([Ii]ssues? )(%d%d%d+%l?)(%w?)", function(word, id, after)
        local m = moves_by_old[id]
        if not m or after ~= "" then return nil end
        return word .. slot(m.new)
    end)
    -- the issue's own title line
    if own_key and moves_by_old[own_key] then
        text = text:gsub("^(# #?)(%d%d%d+%l?)([^%w])", function(head, id, after)
            if id ~= own_key then return nil end
            return head .. slot(moves_by_old[id].new) .. after
        end, 1)
    end
    local held = text
    text = text:gsub("\1P(%d+)\2", function(n) return slots[tonumber(n)] end)
    return text, count, held
end
-- }}}

-- {{{ local function leftovers
-- Lines that still hold a bare old number while mentioning issues: for a
-- person to look at.  Read from the placeholder stage, so the new numbers
-- just written are not mistaken for old ones.
local function leftovers(text, moves_by_old)
    local found = {}
    local n = 0
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        n = n + 1
        -- (a "#" may be followed by a placeholder here, not a digit)
        if line:find("#[%d\1]") or line:lower():find("issue") then
            for word in line:gmatch("%f[%w](%d%d%d+%l?)%f[^%w]") do
                if moves_by_old[word] then
                    found[#found + 1] = {line = n, text = line, id = word}
                    break
                end
            end
        end
    end
    return found
end
-- }}}

-- {{{ local function main
local function main()
    local issues = find_issues()
    local mapping, err = read_mapping(MAPPING)
    if not mapping then io.stderr:write(err .. "\n"); return 1 end
    local moves, problems = check_mapping(mapping, issues)
    if not moves then
        io.stderr:write("refused, nothing changed:\n")
        for _, p in ipairs(problems) do io.stderr:write("  " .. p .. "\n") end
        return 1
    end
    local moves_by_old = {}
    for _, m in ipairs(moves) do
        local issue = issues[m.old]
        moves_by_old[m.old] = {
            old = m.old, new = m.new, dir = issue.dir,
            old_stem = issue.stem, new_stem = m.new .. "-" .. issue.slug,
        }
    end
    print(string.format("%s%d issue(s) move", dry_run and "dry run: " or "", #moves))

    -- the stem -> key of every issue file, to know which file is which issue
    local key_of_path = {}
    for key, issue in pairs(issues) do
        key_of_path[issue.dir .. "/" .. issue.stem .. ".md"] = key
    end

    local changed_files, review = 0, {}
    for _, rel in ipairs(text_files()) do
        local text = read_file(DIR .. "/" .. rel)
        local new_text, count, held = rewrite(text, moves_by_old, key_of_path[rel])
        if count > 0 then
            changed_files = changed_files + 1
            print(string.format("  %-60s %d mention(s)", rel, count))
            if not dry_run then write_file(DIR .. "/" .. rel, new_text) end
        end
        for _, l in ipairs(leftovers(held, moves_by_old)) do
            review[#review + 1] = string.format("  %s:%d (%s): %s", rel, l.line, l.id, l.text)
        end
    end
    print(string.format("%d file(s) %s", changed_files, dry_run and "would change" or "changed"))

    for _, m in pairs(moves_by_old) do
        local from = DIR .. "/" .. m.dir .. "/" .. m.old_stem .. ".md"
        local to = DIR .. "/" .. m.dir .. "/" .. m.new_stem .. ".md"
        print(string.format("  %s/%s.md -> %s.md", m.dir, m.old_stem, m.new_stem))
        if not dry_run then
            -- two steps, like the text: a file may move onto a name
            -- another file is leaving
            assert(os.rename(from, to .. ".renumbering"))
        end
    end
    if not dry_run then
        for _, m in pairs(moves_by_old) do
            local to = DIR .. "/" .. m.dir .. "/" .. m.new_stem .. ".md"
            assert(os.rename(to .. ".renumbering", to))
        end
    end

    if #review > 0 then
        print("")
        print("lines still holding an old number near an issue mention (left alone; check by hand):")
        for _, r in ipairs(review) do print(r) end
    end
    return 0
end
-- }}}

os.exit(main())
