-- wrap.lua — characters, their widths on screen, and lines wrapped to fit
--
-- Issue #711; clients/editor-design.md, "Line wrapping" and "Emojis".
-- Text is UTF-8.  Lua before 5.3 has no utf8 library, so characters are
-- read here by their lead byte.
--
-- Wrapping keeps the design's distinction: a newline in the text is the
-- writer's and always breaks; a wrap point is worked out from the width
-- at hand and is never stored, so a resize only works them out again.

local W = {}

-- {{{ W.chars(s) -> iterator over the UTF-8 characters of s
-- A malformed byte is taken as one character on its own, so bad input
-- shows as something rather than swallowing what follows it.
function W.chars(s)
    local i, n = 1, #s
    return function()
        if i > n then return nil end
        local b = s:byte(i)
        local len = (b >= 0xF0 and b < 0xF8) and 4 or (b >= 0xE0) and 3 or (b >= 0xC0) and 2 or 1
        if b >= 0xF8 then len = 1 end
        for k = 1, len - 1 do
            local cb = s:byte(i + k)
            if not cb or cb < 0x80 or cb > 0xBF then len = 1; break end
        end
        local ch = s:sub(i, i + len - 1)
        i = i + len
        return ch
    end
end
-- }}}

local function codepoint(ch)
    local b1, b2, b3, b4 = ch:byte(1, 4)
    if #ch == 1 then return b1 end
    if #ch == 2 then return (b1 % 32) * 64 + (b2 % 64) end
    if #ch == 3 then return ((b1 % 16) * 64 + (b2 % 64)) * 64 + (b3 % 64) end
    return (((b1 % 8) * 64 + (b2 % 64)) * 64 + (b3 % 64)) * 64 + (b4 % 64)
end

-- The ranges a terminal draws two cells wide: East Asian Wide and
-- Fullwidth, and the emoji blocks.  The design's open item asked for an
-- emoji width table; this is it, short because the blocks are few.
local WIDE = {
    { 0x1100, 0x115F }, { 0x231A, 0x231B }, { 0x2329, 0x232A }, { 0x23E9, 0x23EC },
    { 0x23F0, 0x23F0 }, { 0x23F3, 0x23F3 }, { 0x25FD, 0x25FE }, { 0x2614, 0x2615 },
    { 0x2648, 0x2653 }, { 0x267F, 0x267F }, { 0x2693, 0x2693 }, { 0x26A1, 0x26A1 },
    { 0x26AA, 0x26AB }, { 0x26BD, 0x26BE }, { 0x26C4, 0x26C5 }, { 0x26CE, 0x26CE },
    { 0x26D4, 0x26D4 }, { 0x26EA, 0x26EA }, { 0x26F2, 0x26F3 }, { 0x26F5, 0x26F5 },
    { 0x26FA, 0x26FA }, { 0x26FD, 0x26FD }, { 0x2705, 0x2705 }, { 0x270A, 0x270B },
    { 0x2728, 0x2728 }, { 0x274C, 0x274C }, { 0x274E, 0x274E }, { 0x2753, 0x2755 },
    { 0x2757, 0x2757 }, { 0x2795, 0x2797 }, { 0x27B0, 0x27B0 }, { 0x27BF, 0x27BF },
    { 0x2B1B, 0x2B1C }, { 0x2B50, 0x2B50 }, { 0x2B55, 0x2B55 }, { 0x2E80, 0x303E },
    { 0x3041, 0x33FF }, { 0x3400, 0x4DBF }, { 0x4E00, 0x9FFF }, { 0xA000, 0xA4CF },
    { 0xAC00, 0xD7A3 }, { 0xF900, 0xFAFF }, { 0xFE30, 0xFE4F }, { 0xFF00, 0xFF60 },
    { 0xFFE0, 0xFFE6 }, { 0x1F300, 0x1F64F }, { 0x1F680, 0x1F6FF }, { 0x1F900, 0x1F9FF },
    { 0x1FA70, 0x1FAFF }, { 0x20000, 0x3FFFD },
}

-- {{{ W.width(ch) -> 0, 1 or 2 cells
-- Control characters and combining marks take no cell of their own.
function W.width(ch)
    local cp = codepoint(ch)
    if cp < 32 or (cp >= 0x7F and cp < 0xA0) then return 0 end
    if (cp >= 0x0300 and cp <= 0x036F) or cp == 0x200D or (cp >= 0xFE00 and cp <= 0xFE0F) then
        return 0
    end
    if cp < 0x1100 then return 1 end
    for _, r in ipairs(WIDE) do
        if cp >= r[1] and cp <= r[2] then return 2 end
    end
    return 1
end
-- }}}

-- {{{ W.text_width(s)
function W.text_width(s)
    local w = 0
    for ch in W.chars(s) do w = w + W.width(ch) end
    return w
end
-- }}}

-- {{{ W.wrap(text, width) -> list of { text = ..., ends_paragraph = bool }
-- Each writer's line is broken at the last space that fits; a word
-- longer than the width is broken inside itself, since it cannot fit any
-- other way.  `ends_paragraph` marks the screen line that ends one of the
-- writer's lines, which is how the two kinds of break stay told apart.
-- Tabs show as four spaces; carriage returns are dropped.
function W.wrap(text, width)
    width = math.max(1, width)
    local out = {}
    text = text:gsub("\r", ""):gsub("\t", "    ")
    for para in (text .. "\n"):gmatch("(.-)\n") do
        local line, line_w = {}, 0
        local last_space = nil   -- index into line just after the last space
        local function emit(upto)
            local piece = table.concat(line, "", 1, upto)
            out[#out + 1] = { text = (piece:gsub(" +$", "")), ends_paragraph = false }
            local rest = {}
            for k = upto + 1, #line do rest[#rest + 1] = line[k] end
            line = rest
            line_w = 0
            for _, c in ipairs(line) do line_w = line_w + W.width(c) end
            last_space = nil
            for k = #line, 1, -1 do
                if line[k] == " " then last_space = k; break end
            end
        end
        for ch in W.chars(para) do
            local w = W.width(ch)
            if line_w + w > width then
                if ch == " " then
                    emit(#line)
                    ch, w = nil, 0
                elseif last_space and last_space > 0 then
                    emit(last_space)
                else
                    emit(#line)
                end
            end
            if ch and not (ch == " " and #line == 0 and #out > 0 and not out[#out].ends_paragraph) then
                line[#line + 1] = ch
                line_w = line_w + w
                if ch == " " then last_space = #line end
            end
        end
        out[#out + 1] = { text = table.concat(line), ends_paragraph = true }
    end
    -- the text's own last newline makes no empty line of its own
    if #out > 1 and out[#out].text == "" and text:sub(-1) == "\n" then out[#out] = nil end
    return out
end
-- }}}

return W
