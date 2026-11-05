-- renderer.lua — a double-buffered grid of character cells for the terminal
--
-- Issue #711, the terminal viewer; the design is clients/editor-design.md,
-- "Rendering: double-buffered cell grid".  Each cell is
--
--   { char = "a", ansi_on = "\27[32m", ansi_off = "\27[0m", tags = {} }
--
-- `back` is what the program is building, `front` is what is on screen.
-- A frame changes cells in `back` in place -- it is never cleared, so a
-- cell's tags last from one frame to the next -- and `flush` writes only
-- the cells that differ from `front`, then copies them across.
--
-- A wide character (CJK, most emoji) takes two cells: the first holds it,
-- the second holds `char = ""` as a continuation and is never written.
--
-- Pure Lua, 5.1 and later, no library: the same file serves every client.

local wrap = require("wrap")

local R = {}
R.__index = R

local function blank(tags)
    return { char = " ", ansi_on = "", ansi_off = "", tags = tags or {} }
end

local function grid(rows, cols)
    local g = {}
    for r = 1, rows do
        local row = {}
        for c = 1, cols do row[c] = blank() end
        g[r] = row
    end
    return g
end

-- {{{ R.new(rows, cols)
function R.new(rows, cols)
    local self = setmetatable({}, R)
    self:resize(rows, cols)
    return self
end
-- }}}

-- {{{ R:resize(rows, cols)
-- Both buffers are made again at the new size and the next flush draws
-- every cell: after a resize nothing on screen can be trusted.
function R:resize(rows, cols)
    self.rows, self.cols = rows, cols
    self.back = grid(rows, cols)
    self.front = grid(rows, cols)
    self.full = true
end
-- }}}

-- {{{ R:put(row, col, text, ansi_on, tags) -> next column
-- Writes text from (row, col) onward, cut at the right edge.  A wide
-- character that would straddle the edge is left out rather than halved.
function R:put(row, col, text, ansi_on, tags)
    local line = self.back[row]
    if not line then return col end
    ansi_on = ansi_on or ""
    local ansi_off = ansi_on ~= "" and "\27[0m" or ""
    for ch in wrap.chars(text) do
        local w = wrap.width(ch)
        if w > 0 then
            if col + w - 1 > self.cols then break end
            local cell = line[col]
            cell.char, cell.ansi_on, cell.ansi_off = ch, ansi_on, ansi_off
            if tags then cell.tags = tags end
            if w == 2 then
                local cont = line[col + 1]
                cont.char, cont.ansi_on, cont.ansi_off = "", ansi_on, ansi_off
                if tags then cont.tags = tags end
            end
            col = col + w
        end
    end
    return col
end
-- }}}

-- {{{ R:fill(row, from_col, ansi_on, tags)
-- Blanks the rest of a row from from_col, so a shorter line replaces a
-- longer one without leaving its tail behind.
function R:fill(row, from_col, ansi_on, tags)
    local line = self.back[row]
    if not line then return end
    ansi_on = ansi_on or ""
    for c = from_col, self.cols do
        local cell = line[c]
        cell.char, cell.ansi_on = " ", ansi_on
        cell.ansi_off = ansi_on ~= "" and "\27[0m" or ""
        cell.tags = tags or {}
    end
end
-- }}}

-- {{{ R:line(row, text, ansi_on, tags)
-- One whole row: the text, then blanks to the edge.
function R:line(row, text, ansi_on, tags)
    self:fill(row, self:put(row, 1, text, ansi_on, tags), ansi_on, tags)
end
-- }}}

-- {{{ R:cells_tagged(tag) -> list of {row, col, cell}
-- Components find their cells by tag rather than by position, so a
-- resize or a scroll can move cells without the component keeping track.
function R:cells_tagged(tag)
    local found = {}
    for r = 1, self.rows do
        for c = 1, self.cols do
            local cell = self.back[r][c]
            if cell.tags[tag] ~= nil then found[#found + 1] = { row = r, col = c, cell = cell } end
        end
    end
    return found
end
-- }}}

-- {{{ R:update_tag(tag, fields) -> how many cells changed
-- The batch update the design left as a TODO: every cell carrying `tag`
-- takes `fields` (ansi_on, char, ...), e.g. reverse video on a selection
-- with update_tag("selection", { ansi_on = "\27[7m" }).
function R:update_tag(tag, fields)
    local n = 0
    for _, hit in ipairs(self:cells_tagged(tag)) do
        for k, v in pairs(fields) do hit.cell[k] = v end
        if fields.ansi_on and fields.ansi_off == nil then
            hit.cell.ansi_off = fields.ansi_on ~= "" and "\27[0m" or ""
        end
        n = n + 1
    end
    return n
end
-- }}}

-- {{{ R:text() -> the back buffer as plain text, one line per row
-- What the screen would read as, for tests and for a terminal that
-- cannot draw.  Trailing blanks are kept off.
function R:text()
    local out = {}
    for r = 1, self.rows do
        local parts = {}
        for c = 1, self.cols do parts[#parts + 1] = self.back[r][c].char end
        out[r] = (table.concat(parts):gsub("%s+$", ""))
    end
    return table.concat(out, "\n")
end
-- }}}

local function same(a, b)
    return a.char == b.char and a.ansi_on == b.ansi_on and a.ansi_off == b.ansi_off
end

-- {{{ R:flush() -> the bytes to write
-- Diff back against front and return the escape codes for the cells that
-- changed, in one string so the caller writes it in one call.  Within a
-- run of changed cells, a cell whose style matches the one before it does
-- not repeat the style: the choice is a lookup indexed 0 or 1, as the
-- design sketches, rather than a branch.  Each run ends with a reset.
function R:flush()
    local out = {}
    local full = self.full
    for r = 1, self.rows do
        local back, front = self.back[r], self.front[r]
        local c = 1
        while c <= self.cols do
            if full or not same(back[c], front[c]) then
                -- a run: from here to the last differing cell before an
                -- unchanged stretch
                out[#out + 1] = "\27[" .. r .. ";" .. c .. "H"
                local prev = nil
                local styled = false
                while c <= self.cols and (full or not same(back[c], front[c])) do
                    local cell = back[c]
                    if cell.char ~= "" then
                        local same_as_prev = (prev == cell.ansi_on) and 1 or 0
                        local reset = (prev ~= nil and prev ~= "" and same_as_prev == 0) and "\27[0m" or ""
                        local codes = { [0] = reset .. cell.ansi_on, [1] = "" }
                        out[#out + 1] = codes[same_as_prev]
                        out[#out + 1] = cell.char
                        prev = cell.ansi_on
                        styled = styled or cell.ansi_on ~= ""
                    end
                    local f = front[c]
                    f.char, f.ansi_on, f.ansi_off = cell.char, cell.ansi_on, cell.ansi_off
                    c = c + 1
                end
                if styled then out[#out + 1] = "\27[0m" end
            else
                c = c + 1
            end
        end
    end
    self.full = false
    return table.concat(out)
end
-- }}}

return R
