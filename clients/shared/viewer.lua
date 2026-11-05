-- viewer.lua — read a mailbox in the terminal (issue #711)
--
-- The thin client keeps a home mailbox mirrored in a folder, and the
-- point of rmail is that any tool reads it.  This is one more such tool,
-- for a terminal: the screen clients/editor-design.md lays out, with its
-- list and read modes.  Its edit and contacts modes are not built; the
-- viewer changes nothing in the mailbox, so a file is still written with
-- the editor the user already has.
--
--   +------------------------------------------------+
--   | mailbox-1   inbox 12  outbox 3   synced 2m ago | status bar
--   | (the list of a folder's files, or one file)    | main area
--   | enter read  tab inbox/outbox  q quit           | hint bar
--   +------------------------------------------------+
--
-- It works on any mailbox folder -- the thin client's mirror or a
-- daemon's own -- since both have inbox/ and outbox/.  Hidden files are
-- the daemon's and the client's bookkeeping, and are not listed.
--
-- The list is read again before every frame, so mail the client syncs
-- in while the viewer is open shows up at the next key.

local Renderer = require("renderer")
local wrap = require("wrap")

local V = {}
V.__index = V

local STATUS_STYLE = "\27[7m"
local HINT_STYLE = "\27[2m"
local HEADER_STYLE = "\27[32m"
local SELECTED_STYLE = "\27[7m"

local function sh_quote(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local s = f:read("*a")
    f:close()
    return s
end

local function is_dir(path)
    local f = io.open(path .. "/.", "r")
    if f then f:close(); return true end
    return false
end

-- {{{ list_folder(path) -> entries, newest first
-- `ls -t` gives the order, so no file-time call is needed from Lua.
-- Each entry is { name, dir = bool }.
local function list_folder(path)
    local entries = {}
    local p = io.popen("ls -t " .. sh_quote(path) .. " 2>/dev/null")
    if p then
        for name in p:lines() do
            if name:sub(1, 1) ~= "." then
                entries[#entries + 1] = { name = name, dir = is_dir(path .. "/" .. name) }
            end
        end
        p:close()
    end
    return entries
end
-- }}}

-- seconds since a file last changed, or nil: GNU stat, then BSD stat
local function age_of(path)
    local p = io.popen("stat -c %Y " .. sh_quote(path) .. " 2>/dev/null || stat -f %m "
        .. sh_quote(path) .. " 2>/dev/null")
    if not p then return nil end
    local t = tonumber((p:read("*a") or ""):match("%d+"))
    p:close()
    return t and (os.time() - t) or nil
end

local function ago(seconds)
    if seconds < 60 then return "just now" end
    if seconds < 3600 then return math.floor(seconds / 60) .. "m ago" end
    if seconds < 86400 then return math.floor(seconds / 3600) .. "h ago" end
    return math.floor(seconds / 86400) .. "d ago"
end

-- {{{ V.new(dir, rows, cols)
function V.new(dir, rows, cols)
    local self = setmetatable({}, V)
    self.dir = dir:gsub("/+$", "")
    self.name = self.dir:match("([^/]+)$") or self.dir
    self.screen = Renderer.new(rows, cols)
    self.box = "inbox"        -- which of the two folders the list shows
    self.path = {}            -- folders opened below it
    self.selected = 1
    self.top = 1              -- first entry shown
    self.mode = "list"
    return self
end
-- }}}

function V:folder()
    local parts = { self.dir, self.box }
    for _, p in ipairs(self.path) do parts[#parts + 1] = p end
    return table.concat(parts, "/")
end

function V:height() return self.screen.rows - 2 end

-- {{{ V:open_file(path)
-- A file is wrapped to the screen when drawn, not here, so a resize
-- reflows it.  A file with a zero byte in its first 4 KB is not text and
-- is described rather than shown.
function V:open_file(path, name)
    local body = read_file(path)
    if not body then return end
    if body:sub(1, 4096):find("\0", 1, true) then
        body = "(" .. name .. " is not text: " .. #body .. " bytes.  Open it with a program for its kind.)"
    end
    self.body = body
    self.body_name = name
    self.scroll = 1
    self.mode = "read"
end
-- }}}

-- the lines of the open file at the current width, and how many of them
-- are the message's header (the lines before its first blank line)
function V:read_lines()
    local width = self.screen.cols
    if self.wrapped_for ~= width or self.wrapped_body ~= self.body then
        self.wrapped = wrap.wrap(self.body, width)
        self.wrapped_for, self.wrapped_body = width, self.body
        local header_end = self.body:find("\n%s*\n") or 0
        local text_before = header_end > 0 and self.body:sub(1, header_end) or ""
        self.header_rows = 0
        if header_end > 0 and text_before:match("^%a[%w_-]*:") then
            self.header_rows = #wrap.wrap(text_before:gsub("\n$", ""), width)
        end
    end
    return self.wrapped
end

-- {{{ V:draw()
function V:draw()
    local s = self.screen
    local rows = s.rows
    -- status bar
    local inbox_n = #list_folder(self.dir .. "/inbox")
    local outbox_n = #list_folder(self.dir .. "/outbox")
    local status = " " .. self.name .. "   inbox " .. inbox_n .. "  outbox " .. outbox_n
    local synced = age_of(self.dir .. "/sync-state.json")
    if synced then status = status .. "   synced " .. ago(synced) end
    s:line(1, status, STATUS_STYLE, { status = true })

    local hint
    if self.mode == "list" then
        self.entries = list_folder(self:folder())
        -- keep the selection on the same file as the list changes under it
        if self.selected_name then
            for i, e in ipairs(self.entries) do
                if e.name == self.selected_name then self.selected = i end
            end
        end
        self.selected = math.max(1, math.min(self.selected, #self.entries))
        local h = self:height()
        if self.selected < self.top then self.top = self.selected end
        if self.selected > self.top + h - 1 then self.top = self.selected - h + 1 end
        local title = "/" .. self.box
        for _, p in ipairs(self.path) do title = title .. "/" .. p end
        for row = 2, rows - 1 do
            local i = self.top + row - 2
            local e = self.entries[i]
            if e then
                local tags = { ["list-row"] = i }
                if i == self.selected then tags.selection = true end
                s:line(row, "  " .. e.name .. (e.dir and "/" or ""), "", tags)
            elseif i == 1 then
                s:line(row, "  (" .. title:sub(2) .. " is empty)", HINT_STYLE)
            else
                s:line(row, "")
            end
        end
        -- the selection is drawn by its tag, not its position
        s:update_tag("selection", { ansi_on = SELECTED_STYLE })
        local e = self.entries[self.selected]
        self.selected_name = e and e.name
        hint = " enter open  tab " .. (self.box == "inbox" and "outbox" or "inbox")
            .. (#self.path > 0 and "  left up" or "") .. "  q quit"
    else
        local lines = self:read_lines()
        local h = self:height()
        self.scroll = math.max(1, math.min(self.scroll, math.max(1, #lines - h + 1)))
        for row = 2, rows - 1 do
            local i = self.scroll + row - 2
            local l = lines[i]
            if l then
                s:line(row, l.text, i <= self.header_rows and HEADER_STYLE or "", { ["read-line"] = i })
            else
                s:line(row, "")
            end
        end
        local last = math.min(#lines, self.scroll + h - 1)
        hint = " " .. self.body_name .. "  " .. self.scroll .. "-" .. last .. " of " .. #lines
            .. "   space down  b up  q back"
    end
    s:line(rows, hint, HINT_STYLE, { hint = true })
end
-- }}}

-- {{{ V:handle(key) -> "quit" or nil
function V:handle(key)
    if key == "ctrl-c" or key == "ctrl-d" then return "quit" end
    if key == "ctrl-l" then self.screen.full = true; return end
    local h = self:height()
    if self.mode == "list" then
        local n = #(self.entries or {})
        if key == "up" or key == "k" then self.selected = self.selected - 1
        elseif key == "down" or key == "j" then self.selected = self.selected + 1
        elseif key == "pageup" then self.selected = self.selected - h
        elseif key == "pagedown" then self.selected = self.selected + h
        elseif key == "home" or key == "g" then self.selected = 1
        elseif key == "end" or key == "G" then self.selected = n
        elseif key == "tab" then
            self.box = self.box == "inbox" and "outbox" or "inbox"
            self.path, self.selected, self.top, self.selected_name = {}, 1, 1, nil
            return
        elseif key == "enter" or key == "right" or key == "l" then
            local e = self.entries and self.entries[self.selected]
            if not e then return end
            if e.dir then
                self.path[#self.path + 1] = e.name
                self.selected, self.top, self.selected_name = 1, 1, nil
            else
                self:open_file(self:folder() .. "/" .. e.name, e.name)
            end
            return
        elseif key == "left" or key == "h" or key == "backspace" then
            if #self.path > 0 then
                self.selected_name = table.remove(self.path)
                self.top = 1
            end
            return
        elseif key == "q" or key == "escape" then
            if #self.path > 0 then
                self.selected_name = table.remove(self.path)
                self.top = 1
                return
            end
            return "quit"
        else
            return
        end
        self.selected = math.max(1, math.min(self.selected, n))
        local e = self.entries and self.entries[self.selected]
        self.selected_name = e and e.name
    else
        if key == "up" or key == "k" then self.scroll = self.scroll - 1
        elseif key == "down" or key == "j" or key == "enter" then self.scroll = self.scroll + 1
        elseif key == "pageup" or key == "b" then self.scroll = self.scroll - h
        elseif key == "pagedown" or key == " " then self.scroll = self.scroll + h
        elseif key == "home" or key == "g" then self.scroll = 1
        elseif key == "end" or key == "G" then self.scroll = #self:read_lines()
        elseif key == "q" or key == "escape" or key == "left" or key == "h" or key == "backspace" then
            self.mode, self.body = "list", nil
        end
    end
end
-- }}}

-- {{{ V:run(term)
-- One frame per key: measure, draw, write what changed, wait for a key.
-- Nothing is drawn while no key comes, so an idle viewer costs nothing.
function V:run(term)
    while true do
        local rows, cols = term.size()
        if rows ~= self.screen.rows or cols ~= self.screen.cols then
            self.screen:resize(rows, cols)
        end
        self:draw()
        term.write(self.screen:flush())
        local key = term.read_key()
        if not key or self:handle(key) == "quit" then return end
    end
end
-- }}}

return V
