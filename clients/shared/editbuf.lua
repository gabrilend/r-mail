-- editbuf.lua — the text being written: a gap buffer, its screen rows, and undo
--
-- Issue #711; clients/editor-design.md, "Buffer model", "Viewport" and
-- "Line wrapping".  The buffer holds the writer's characters (UTF-8, one
-- table entry per character) with the gap at the cursor: the characters
-- before it in `before`, the ones after it in `after`, nearest last.  A
-- character typed or deleted at the cursor is one push or pop; moving
-- the cursor moves characters across the gap one at a time.
--
-- Only the writer's newlines are stored.  Where a line wraps on screen is
-- worked out from the width at hand (B:rows), so a resize moves the wrap
-- points and never the text.

local wrap = require("wrap")

local B = {}
B.__index = B

B.UNDO_LIMIT = 200

-- {{{ B.new(text) -> a buffer holding text, the cursor at its start
function B.new(text)
    local self = setmetatable({ before = {}, after = {}, undo = {}, last_kind = nil }, B)
    local chars = {}
    for ch in wrap.chars((text or ""):gsub("\r", "")) do chars[#chars + 1] = ch end
    for i = #chars, 1, -1 do self.after[#self.after + 1] = chars[i] end
    return self
end
-- }}}

function B:text()
    local out = {}
    for i = 1, #self.before do out[i] = self.before[i] end
    for i = #self.after, 1, -1 do out[#out + 1] = self.after[i] end
    return table.concat(out)
end

function B:len() return #self.before + #self.after end
function B:offset() return #self.before end

-- the character at 1-based position i, gap or not
function B:at(i)
    local nb = #self.before
    if i <= nb then return self.before[i] end
    return self.after[#self.after - (i - nb) + 1]
end

-- {{{ B:move_to(k) -- the cursor after the k-th character
function B:move_to(k)
    k = math.max(0, math.min(k, self:len()))
    local before, after = self.before, self.after
    while #before > k do after[#after + 1] = table.remove(before) end
    while #before < k do before[#before + 1] = table.remove(after) end
    self.last_kind = nil
end
-- }}}

-- {{{ undo
-- A snapshot of the text and the cursor is taken before an edit of a new
-- kind, so a run of typing or of deleting is undone as one step, as an
-- editor's undo usually goes.  The text of a message is small; a copy
-- per step is cheap and cannot go wrong the way replaying edits can.
function B:remember(kind)
    if kind and kind == self.last_kind then return end
    local undo = self.undo
    undo[#undo + 1] = { text = self:text(), offset = self:offset() }
    if #undo > B.UNDO_LIMIT then table.remove(undo, 1) end
    self.last_kind = kind
end

-- true when there was something to undo
function B:undo_last()
    local snap = table.remove(self.undo)
    if not snap then return false end
    local fresh = B.new(snap.text)
    self.before, self.after = fresh.before, fresh.after
    self:move_to(snap.offset)
    self.last_kind = nil
    return true
end
-- }}}

-- {{{ editing at the cursor
function B:insert(s)
    self:remember("insert")
    for ch in wrap.chars(s) do self.before[#self.before + 1] = ch end
end

function B:backspace()
    if #self.before == 0 then return end
    self:remember("delete")
    table.remove(self.before)
end

function B:delete()
    if #self.after == 0 then return end
    self:remember("delete")
    table.remove(self.after)
end

function B:left()  if #self.before > 0 then self:move_to(#self.before - 1) end end
function B:right() if #self.after > 0 then self:move_to(#self.before + 1) end end
-- }}}

-- {{{ the writer's line around the cursor: first and last offsets
-- first is the offset of its first character's start; last is the offset
-- just before its newline (or the end of the text)
function B:line_bounds()
    local first = #self.before
    while first > 0 and self.before[first] ~= "\n" do first = first - 1 end
    local last, n = #self.before, self:len()
    while last < n and self:at(last + 1) ~= "\n" do last = last + 1 end
    return first, last
end

function B:line_start() self:move_to((self:line_bounds())) end
function B:line_end() self:move_to(select(2, self:line_bounds())) end

-- {{{ B:cut_line() -> the text cut: the writer's line and its newline
function B:cut_line()
    local first, last = self:line_bounds()
    local n = self:len()
    if first == n and last == n then return "" end
    self:remember("cut")
    self:move_to(first)
    local stop = last < n and last + 1 or last   -- its newline goes too
    local out = {}
    for _ = first + 1, stop do out[#out + 1] = table.remove(self.after) end
    self.last_kind = "cut"
    return table.concat(out)
end
-- }}}
-- }}}

-- {{{ B:rows(width) -> the screen rows: { first = i, last = j } per row
-- Characters first..last of the text (1-based; last < first for an empty
-- row).  A row ends at a writer's newline (which is in the row and not
-- drawn) or where the next character would not fit: then at the last
-- space that fits, which stays at the end of its row, or inside a word
-- too long for any row.  Tabs count as four cells, as wrap.lua shows them.
local function cells(ch)
    if ch == "\t" then return 4 end
    return wrap.width(ch)
end
B.cells = cells

function B:rows(width)
    width = math.max(1, width)
    local rows, n = {}, self:len()
    local first, used, last_space = 1, 0, nil
    local i = 1
    while i <= n do
        local ch = self:at(i)
        if ch == "\n" then
            rows[#rows + 1] = { first = first, last = i }
            first, used, last_space = i + 1, 0, nil
            i = i + 1
        else
            local w = cells(ch)
            if used + w > width and i > first then
                if ch == " " then
                    -- a space at the edge ends the row and stays in it
                    rows[#rows + 1] = { first = first, last = i }
                    first, used, last_space = i + 1, 0, nil
                    i = i + 1
                else
                    local cut = last_space or (i - 1)
                    rows[#rows + 1] = { first = first, last = cut }
                    first, used, last_space = cut + 1, 0, nil
                    i = cut + 1
                end
            else
                used = used + w
                if ch == " " then last_space = i end
                i = i + 1
            end
        end
    end
    rows[#rows + 1] = { first = first, last = n }
    return rows
end
-- }}}

-- {{{ B:locate(rows) -> row, column (both 1-based) of the cursor
-- The cursor before character k+1 is in the row that holds k+1; at the
-- very end, in the last row.  A row that ended by wrapping hands the
-- cursor at its end to the next row, where the next character is.
function B:locate(rows)
    local k = self:offset()
    local r = #rows
    for i, row in ipairs(rows) do
        if k + 1 >= row.first and k + 1 <= math.max(row.last, row.first) and k + 1 <= self:len() then
            r = i
            break
        end
    end
    local row, col = rows[r], 1
    for i = row.first, math.min(k, row.last) do
        local ch = self:at(i)
        if ch ~= "\n" then col = col + cells(ch) end
    end
    return r, col
end
-- }}}

-- {{{ B:to_row(rows, r, col) -- the cursor to row r, nearest column col
function B:to_row(rows, r, col)
    r = math.max(1, math.min(r, #rows))
    local row = rows[r]
    local at, k = 1, row.first - 1
    local stop = row.last
    -- a row's newline, or the space that ended it, is not a place to stand
    -- after unless it is the last row
    if r < #rows and stop >= row.first then stop = stop - 1 end
    for i = row.first, stop do
        local w = cells(self:at(i))
        if at + w > col then break end
        at, k = at + w, i
    end
    self:move_to(k)
end
-- }}}

return B
