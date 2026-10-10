#!/usr/bin/env luajit
-- sort-feedback.lua — file each website note into a folder tree shaped like the site it came from
--
-- For a general audience: a project has one feedback mailbox, and its
-- website's pages send notes into it.  Left alone, every note lands in one
-- flat inbox folder.  This script runs each time a note arrives and moves
-- it into a folder that mirrors where the page sits in the site -- a note
-- about docs/guide/install.html goes to feedback/docs/guide/install/ --
-- with a few lines on top saying when it came and from which site.  Notes
-- that do not say which page they are about, or name a page the site does
-- not have, go to feedback/_refused/ with the reason written in, rather
-- than being guessed at.
--
-- Part of the rmail-integration skill (SKILL.md beside this file); tested
-- by r-mail/scripts/test-feedback-sorter.sh.  Written by hand, 2026-10-09.
--
-- HOW IT IS RUN: as the feedback mailbox's `on_receive` hook.  In that
-- mailbox's config:
--     on_receive = /path/to/sort-feedback.lua
-- rmail runs it in the background after writing each message, with three
-- arguments: the sender's contact name, the subject, and the absolute path
-- of the message in the inbox.  Its DIR -- the mailbox -- is therefore not
-- hard-coded: it is the folder above the inbox, taken from the third
-- argument, so one copy serves any number of mailboxes.
--
-- SETTINGS: <mailbox>/feedback.conf, `key = value` lines:
--     pages = site-pages   a file listing every page of the site, one path
--                          per line, as the pages write it after `page:`
--                          (written by the site's builder: the site knows
--                          its pages, this script only checks against them)
--     tree  = feedback     the folder the sorted notes go into
-- Both paths are relative to the mailbox unless they start with /.  With
-- no feedback.conf, no page list, or no `pages` line, every note is
-- refused, with the reason -- never sorted unchecked.
--
-- WHAT IT SORTS: only messages from a listen-only contact
-- (`name.listen = true` in the mailbox's contacts -- a website).  A
-- message from a person is left in the inbox untouched.  Moving a
-- website's note out of the inbox owes the website nothing: rmail forgets
-- it (rmail issue #420).
--
-- A NOTE'S SHAPE: header lines `key: value` first, ended by a blank line or
-- a line `---`; one of them is `page: <path within the site>`.  The rest is
-- the visitor's words.  The note is kept whole, below the lines this script
-- adds.

-- {{{ local function read_file
local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end
-- }}}

-- {{{ local function shell_quote
local function shell_quote(s)
    return "'" .. s:gsub("'", "'\\''") .. "'"
end
-- }}}

-- {{{ local function read_settings
-- feedback.conf -> {pages = path, tree = path}; paths made absolute against
-- the mailbox.  tree defaults to <mailbox>/feedback; pages has no default.
local function read_settings(mailbox)
    local settings = {tree = "feedback"}
    local text = read_file(mailbox .. "/feedback.conf") or ""
    for line in text:gmatch("[^\n]+") do
        local key, value = line:match("^%s*([%w_]+)%s*=%s*(.-)%s*$")
        if key then settings[key] = value end
    end
    for _, key in ipairs({"pages", "tree"}) do
        local v = settings[key]
        if v and v:sub(1, 1) ~= "/" then settings[key] = mailbox .. "/" .. v end
    end
    return settings
end
-- }}}

-- {{{ local function is_listen_only
-- Whether the contacts file marks `name` listen-only.  The contacts file's
-- lines are `name.field = value`, value optionally in quotes.
local function is_listen_only(mailbox, name)
    local text = read_file(mailbox .. "/contacts") or ""
    for line in text:gmatch("[^\n]+") do
        local who, value = line:match("^%s*([%w_%-]+)%.listen%s*=%s*\"?([%w]+)\"?%s*$")
        if who == name and value == "true" then return true end
    end
    return false
end
-- }}}

-- {{{ local function read_header
-- The note's header lines as a table of lowercased keys, up to the first
-- blank line or `---`.
local function read_header(text)
    local header = {}
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        line = line:gsub("\r$", "")
        if line == "" or line == "---" then break end
        local key, value = line:match("^([%w_%-]+):%s*(.-)%s*$")
        if not key then break end
        header[key:lower()] = header[key:lower()] or value
    end
    return header
end
-- }}}

-- {{{ local function page_refusal
-- False when `page` is a page of the site, else why not.  Checked against
-- the site's own list; the path's shape is checked first so the list is
-- never asked about something that could climb out of the tree.
local function page_refusal(page, settings)
    if not page or page == "" then return "the note names no page (no `page:` line)" end
    if page:find("[%c\\]") then return "the page path holds control characters or backslashes" end
    page = page:gsub("^/+", "")
    for part in page:gmatch("[^/]+") do
        if part == ".." or part == "." then return "the page path climbs (\"..\" or \".\")" end
    end
    if not settings.pages then
        return "feedback.conf names no page list (`pages = ...`), so no page can be checked"
    end
    local list = read_file(settings.pages)
    if not list then return "the page list " .. settings.pages .. " cannot be read" end
    for line in list:gmatch("[^\n]+") do
        if line:gsub("^%s*/*", ""):gsub("%s*$", "") == page then return false end
    end
    return "the site has no page \"" .. page .. "\""
end
-- }}}

-- {{{ local function place
-- Write `text` to folder/name, appearing all at once (written under a
-- hidden name, then renamed), then remove the inbox file.
local function place(folder, name, text, inbox_file)
    os.execute("mkdir -p " .. shell_quote(folder))
    local final = folder .. "/" .. name
    local temp  = folder .. "/." .. name .. ".partial"
    local f = assert(io.open(temp, "wb"))
    f:write(text)
    f:close()
    assert(os.rename(temp, final))
    os.remove(inbox_file)
    return final
end
-- }}}

-- {{{ local function main
local function main(sender, subject, inbox_file)
    if not (sender and subject and inbox_file) then
        io.stderr:write("usage: sort-feedback.lua <sender> <subject> <inbox file>  (run as an on_receive hook)\n")
        os.exit(1)
    end
    local mailbox = inbox_file:match("^(.*)/inbox/[^/]+$")
    if not mailbox then
        io.stderr:write("sort-feedback: " .. inbox_file .. " is not in a mailbox's inbox/\n")
        os.exit(1)
    end
    -- a person's message: not feedback, left where it is
    if not is_listen_only(mailbox, sender) then return end

    local text = read_file(inbox_file)
    if not text then
        io.stderr:write("sort-feedback: cannot read " .. inbox_file .. "\n")
        os.exit(1)
    end
    local settings = read_settings(mailbox)
    local name     = inbox_file:match("([^/]+)$")
    local page     = read_header(text).page
    local refusal  = page_refusal(page, settings)
    local stamp    = os.date("%Y-%m-%d %H:%M:%S")
    local log      = io.open(settings.tree .. "/sort.log", "a")

    -- the lines this script adds on top: what it is and how it got here
    local about = "received: " .. stamp .. "\n" ..
                  "from: " .. sender .. "\n" ..
                  "inbox name: " .. name .. "\n"
    local footer = "sorted by: sort-feedback.lua (rmail-integration skill)\n---\n"

    if refusal then
        local where = place(settings.tree .. "/_refused", name,
            about .. "refused: " .. refusal .. "\n" .. footer .. text, inbox_file)
        io.stderr:write("sort-feedback: refused " .. name .. " from " .. sender .. ": " .. refusal .. "\n")
        if not log then log = io.open(settings.tree .. "/sort.log", "a") end
        if log then log:write(stamp .. " refused " .. name .. " from " .. sender .. ": " .. refusal .. "\n") end
        if log then log:close() end
        return where
    end

    -- docs/guide/install.html -> <tree>/docs/guide/install/
    local folder = settings.tree .. "/" .. page:gsub("^/+", ""):gsub("%.[%w]+$", "")
    local where = place(folder, name, about .. "page: " .. page .. "\n" .. footer .. text, inbox_file)
    if not log then log = io.open(settings.tree .. "/sort.log", "a") end
    if log then
        log:write(stamp .. " sorted " .. name .. " from " .. sender .. " -> " .. where .. "\n")
        log:close()
    end
    return where
end
-- }}}

main(arg[1], arg[2], arg[3])
