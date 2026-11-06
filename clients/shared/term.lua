-- term.lua — the terminal: raw mode, its size, and keys as names
--
-- Issue #711; clients/editor-design.md, "Terminal setup".  The design
-- puts raw mode in a small C module (rmail_term.c).  This uses `stty`
-- instead, which every Linux and macOS terminal has, so the viewer needs
-- nothing compiled.  What that costs: plain Lua cannot catch SIGWINCH, so
-- the size is measured again after every key rather than on the signal --
-- a resize shows at the next key (Ctrl-L redraws without moving).
-- Windows has no stty; the viewer is not offered there yet.
--
-- The viewer talks to a terminal through four functions -- size(),
-- read_key(), write(s), close() -- so a test can hand it a pretend one.

local T = {}

local function sh(cmd)
    local p = io.popen(cmd)
    if not p then return "" end
    local s = p:read("*a") or ""
    p:close()
    return s
end

-- Escape sequences to key names.  Both the CSI (ESC [) and SS3 (ESC O)
-- spellings, since terminals differ in which they send for the same key.
local SEQUENCES = {
    ["[A"] = "up", ["[B"] = "down", ["[C"] = "right", ["[D"] = "left",
    ["OA"] = "up", ["OB"] = "down", ["OC"] = "right", ["OD"] = "left",
    ["[H"] = "home", ["[F"] = "end", ["OH"] = "home", ["OF"] = "end",
    ["[1~"] = "home", ["[4~"] = "end", ["[7~"] = "home", ["[8~"] = "end",
    ["[5~"] = "pageup", ["[6~"] = "pagedown", ["[3~"] = "delete",
}

local NAMES = {
    ["\r"] = "enter", ["\n"] = "enter", ["\t"] = "tab", ["\127"] = "backspace",
    ["\8"] = "backspace", ["\12"] = "ctrl-l", ["\3"] = "ctrl-c", ["\4"] = "ctrl-d",
}

-- {{{ T.parse(read_byte) -> key name, or the character itself
-- read_byte() returns the next byte, or nil when none is waiting; an
-- escape followed by nothing is the Escape key on its own.
function T.parse(read_byte)
    local b = read_byte()
    if not b then return nil end
    if b ~= "\27" then
        if NAMES[b] then return NAMES[b] end
        -- any other control character is ctrl- and its letter (Ctrl-S is
        -- byte 19, "ctrl-s"); raw mode passes them all, flow control too
        if b:byte() >= 1 and b:byte() <= 26 then return "ctrl-" .. string.char(b:byte() + 96) end
        -- a multi-byte character arrives a byte at a time
        local n = b:byte()
        local len = (n >= 0xF0) and 4 or (n >= 0xE0) and 3 or (n >= 0xC0) and 2 or 1
        for _ = 2, len do b = b .. (read_byte() or "") end
        return b
    end
    local seq = ""
    for _ = 1, 6 do
        local nb = read_byte()
        if not nb then break end
        seq = seq .. nb
        if SEQUENCES[seq] then return SEQUENCES[seq] end
        if #seq >= 2 and nb:match("[%a~]") then break end
    end
    if seq == "" then return "escape" end
    return "unknown"
end
-- }}}

-- {{{ T.open() -> a terminal, or nil and why
function T.open()
    local tty = io.open("/dev/tty", "r+")
    if not tty then return nil, "no terminal to draw on (/dev/tty cannot be opened)" end
    local saved = sh("stty -g < /dev/tty 2>/dev/null"):gsub("%s+$", "")
    if saved == "" then
        tty:close()
        return nil, "stty cannot read this terminal's settings"
    end
    -- a key read waits for a key; the bytes after an escape are read with
    -- a tenth of a second's patience (below), so an Escape key on its own
    -- is told apart from the start of an arrow key
    os.execute("stty raw -echo min 1 time 0 < /dev/tty")
    local self = { tty = tty }

    function self.size()
        local rows, cols = sh("stty size < /dev/tty 2>/dev/null"):match("(%d+)%s+(%d+)")
        return tonumber(rows) or 24, tonumber(cols) or 80
    end

    -- Unbuffered, so a byte read is a byte taken and no handle holds
    -- bytes another cannot see.  The bytes after an escape are read with
    -- a short timeout through a handle of their own: a read that times
    -- out marks its handle finished for good (C's end-of-file is sticky),
    -- so that handle is thrown away and the main one stays usable.
    tty:setvbuf("no")
    function self.read_key()
        local first, peek = true, nil
        local key = T.parse(function()
            if first then
                first = false
                return tty:read(1)
            end
            if not peek then
                peek = io.open("/dev/tty", "r")
                if not peek then return nil end
                peek:setvbuf("no")
                os.execute("stty min 0 time 1 < /dev/tty")
            end
            return peek:read(1)
        end)
        if peek then
            os.execute("stty min 1 time 0 < /dev/tty")
            peek:close()
        end
        return key
    end

    function self.write(s)
        tty:write(s)
        tty:flush()
    end

    function self.close()
        tty:write("\27[0m\27[?25h\27[2J\27[H")
        tty:flush()
        os.execute("stty " .. saved .. " < /dev/tty")
        tty:close()
    end

    -- hide the cursor and clear, so the first frame draws on nothing
    self.write("\27[?25l\27[2J")
    return self
end
-- }}}

return T
