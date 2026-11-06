-- viewer.lua — read a mailbox in the terminal (issue #711)
--
-- The thin client keeps a home mailbox mirrored in a folder, and the
-- point of rmail is that any tool reads it.  This is one more such tool,
-- for a terminal: the screen clients/editor-design.md lays out, with its
-- list, read and edit modes.  Its contacts mode is not built.  Reading
-- changes nothing; edit mode writes one outbox file, when told to save,
-- and nothing else: `n` starts a new message in the outbox and `e` opens
-- an outbox file.  The inbox is what arrived and is only read.
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
local EditBuf = require("editbuf")

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
    -- an outbox file that is text can be opened for editing from here
    self.body_path = nil
    if path:sub(1, #self.dir + 8) == self.dir .. "/outbox/" and body == read_file(path) then
        self.body_path = path
    end
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
            .. (#self.path > 0 and "  left up" or "") .. "  n new"
            .. (self.box == "outbox" and e and not e.dir and "  e edit" or "") .. "  q quit"
    elseif self.mode == "edit" then
        hint = self:draw_edit()
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
            .. "   space down  b up" .. (self.body_path and "  e edit" or "") .. "  q back"
    end
    s:line(rows, hint, HINT_STYLE, { hint = true })
end
-- }}}

-- {{{ V:handle(key) -> "quit" or nil
function V:handle(key)
    if self.mode == "edit" then return self:handle_edit(key) end
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
        elseif key == "n" then
            -- a new message goes in the outbox: in the folder shown when
            -- the list is the outbox's (a contact's folder, #214), and at
            -- its top otherwise
            local folder = self.box == "outbox" and self:folder() or (self.dir .. "/outbox")
            self:start_edit(folder, nil)
            return
        elseif key == "e" then
            local e = self.entries and self.entries[self.selected]
            if self.box == "outbox" and e and not e.dir then self:start_edit(self:folder(), e.name) end
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
        elseif key == "e" and self.body_path then
            self:start_edit(self.body_path:match("^(.*)/[^/]*$"), self.body_name)
        elseif key == "q" or key == "escape" or key == "left" or key == "h" or key == "backspace" then
            self.mode, self.body = "list", nil
        end
    end
end
-- }}}

-- ---- edit mode -------------------------------------------------------
--
-- One outbox file at a time, in a buffer (editbuf.lua).  Nothing is
-- written until Ctrl-S, and then the whole file at once: written beside
-- it under a hidden name and moved over it, so the daemon, which skips
-- hidden files, never reads half a message.  A file that changed on disk
-- since it was opened (the daemon marks a file it cannot send, and adds
-- a link's URL line) is not saved over without a second Ctrl-S, and a new
-- message never takes a name already in its folder.

local NEW_MESSAGE = "to: \n\n"

local function write_file(path, text)
    local f = io.open(path, "wb")
    if not f then return false end
    local ok = f:write(text)
    f:close()
    return ok and true or false
end

local function is_text_key(key)
    local b = key:byte(1)
    if #key == 1 then return b >= 32 and b ~= 127 end
    return b >= 0xC0   -- a UTF-8 character; key names are plain ASCII words
end

-- {{{ V:start_edit(folder, name) -- name nil for a new message
function V:start_edit(folder, name)
    local text = NEW_MESSAGE
    if name then
        text = read_file(folder .. "/" .. name)
        if not text then return end
        if text:sub(1, 4096):find("\0", 1, true) then return end
    end
    local buf = EditBuf.new(text)
    -- a new message starts with the cursor where the recipient goes
    buf:move_to(name and 0 or 4)
    buf.undo = {}
    self.edit = { buf = buf, folder = folder, name = name, loaded = name and text or nil,
                  saved = text, top = 1, yank = "" }
    self.mode = "edit"
end
-- }}}

-- {{{ V:save_edit(name) -> true when written
function V:save_edit(name)
    local ed = self.edit
    local path = ed.folder .. "/" .. name
    local text = ed.buf:text()
    if ed.name then
        local now = read_file(path)
        if now ~= ed.loaded and not ed.overwrite then
            ed.overwrite = true
            ed.message = name .. " changed on disk since you opened it; ^S again saves over it"
            return false
        end
    end
    local tmp = ed.folder .. "/." .. name .. ".rmail-view"
    if not write_file(tmp, text) or not os.rename(tmp, path) then
        os.remove(tmp)
        ed.message = "could not write " .. path
        return false
    end
    ed.name, ed.loaded, ed.saved, ed.overwrite = name, text, text, nil
    ed.message = "saved " .. name
    self.selected_name = name
    return true
end
-- }}}

-- {{{ V:handle_prompt(key) -- typing the name of a new message
function V:handle_prompt(key)
    local ed = self.edit
    local p = ed.prompt
    if key == "escape" or key == "ctrl-c" then
        ed.prompt, ed.message = nil, "not saved"
    elseif key == "enter" then
        local name = p.text:gsub("^%s+", ""):gsub("%s+$", "")
        if name == "" then
            ed.message = "a message needs a name"
        elseif name:find("/", 1, true) or name:sub(1, 1) == "." then
            ed.message = "a name has no / and does not start with a dot"
        elseif read_file(ed.folder .. "/" .. name) or is_dir(ed.folder .. "/" .. name) then
            ed.message = name .. " is taken; choose another name"
        else
            ed.prompt = nil
            self:save_edit(name)
        end
    elseif key == "backspace" then
        local chars = {}
        for ch in wrap.chars(p.text) do chars[#chars + 1] = ch end
        chars[#chars] = nil
        p.text = table.concat(chars)
    elseif is_text_key(key) then
        p.text = p.text .. key
        ed.message = nil
    end
end
-- }}}

-- {{{ V:handle_edit(key)
function V:handle_edit(key)
    local ed = self.edit
    if ed.prompt then return self:handle_prompt(key) end
    local buf = ed.buf
    local dirty = buf:text() ~= ed.saved
    -- a warning holds for the very next key only
    local leaving, overwrite = ed.leaving, ed.overwrite
    ed.leaving, ed.overwrite, ed.message = nil, nil, nil
    if key ~= "up" and key ~= "down" and key ~= "pageup" and key ~= "pagedown" then ed.goal = nil end
    if key ~= "ctrl-k" then ed.cutting = false end

    if key == "ctrl-x" then
        if dirty and not leaving then
            ed.leaving = true
            ed.message = "not saved: ^S saves, ^X again leaves without saving"
            return
        end
        -- back to the list, with the file selected, whether it was opened
        -- from the list or while reading it
        self.mode, self.body, self.edit = "list", nil, nil
        return
    elseif key == "ctrl-s" then
        if not ed.name then
            ed.prompt = { text = "" }
            return
        end
        ed.overwrite = overwrite
        self:save_edit(ed.name)
        return
    elseif key == "ctrl-l" then
        self.screen.full = true
        return
    elseif key == "ctrl-z" then
        if not buf:undo_last() then ed.message = "nothing to undo" end
        return
    elseif key == "ctrl-k" then
        local cut = buf:cut_line()
        ed.yank = ed.cutting and (ed.yank .. cut) or cut
        ed.cutting = true
        return
    elseif key == "ctrl-u" then
        if ed.yank ~= "" then buf:insert(ed.yank) end
        return
    end

    local rows = buf:rows(self.screen.cols)
    local r, col = buf:locate(rows)
    local h = self:height()
    if key == "enter" then buf:insert("\n")
    elseif key == "tab" then buf:insert("    ")
    elseif key == "backspace" then buf:backspace()
    elseif key == "delete" then buf:delete()
    elseif key == "left" then buf:left()
    elseif key == "right" then buf:right()
    elseif key == "home" then buf:line_start()
    elseif key == "end" then buf:line_end()
    elseif key == "up" or key == "down" or key == "pageup" or key == "pagedown" then
        ed.goal = ed.goal or col
        local step = (key == "up" and -1) or (key == "down" and 1) or (key == "pageup" and -h) or h
        buf:to_row(rows, r + step, ed.goal)
    elseif is_text_key(key) then
        buf:insert(key)
    end
end
-- }}}

-- {{{ V:draw_edit() -> the hint bar's text
function V:draw_edit()
    local s, ed = self.screen, self.edit
    local buf = ed.buf
    local rows = buf:rows(s.cols)
    local r = buf:locate(rows)
    local h = self:height()
    if r < ed.top then ed.top = r end
    if r > ed.top + h - 1 then ed.top = r - h + 1 end
    ed.top = math.max(1, math.min(ed.top, math.max(1, #rows - h + 1)))
    for row = 2, s.rows - 1 do
        local i = ed.top + row - 2
        local span = rows[i]
        if span then
            local out = {}
            for k = span.first, span.last do
                local ch = buf:at(k)
                if ch == "\t" then out[#out + 1] = "    "
                elseif ch ~= "\n" then out[#out + 1] = ch end
            end
            s:line(row, table.concat(out), "", { ["edit-line"] = i })
        else
            s:line(row, "")
        end
    end
    if ed.prompt then return " save as: " .. ed.prompt.text .. (ed.message and ("   " .. ed.message) or "") end
    if ed.message then return " " .. ed.message end
    local dirty = buf:text() ~= ed.saved
    return " " .. (ed.name or "new message") .. (dirty and " *" or "")
        .. "   ^S save  ^X exit  ^K cut  ^U paste  ^Z undo"
end
-- }}}

-- {{{ V:cursor() -> row, column for the terminal's cursor, or nil to hide it
function V:cursor()
    if self.mode ~= "edit" then return nil end
    local ed, s = self.edit, self.screen
    if ed.prompt then
        return s.rows, math.min(s.cols, 1 + wrap.text_width(" save as: " .. ed.prompt.text))
    end
    local rows = ed.buf:rows(s.cols)
    local r, col = ed.buf:locate(rows)
    return r - ed.top + 2, math.min(col, s.cols)
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
        local row, col = self:cursor()
        term.write(self.screen:flush() .. (row and ("\27[" .. row .. ";" .. col .. "H\27[?25h") or "\27[?25l"))
        local key = term.read_key()
        if not key or self:handle(key) == "quit" then return end
    end
end
-- }}}

return V
