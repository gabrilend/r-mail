-- zip-compat.lua — the one place where LuaJIT and Lua 5.3/5.4 differ, for
-- the zip library (my-libs issue 801).
--
-- rao-chat runs on LuaJIT; rmail usually runs on Lua 5.4.  The library's
-- other files use only what this file gives them, so they run unchanged on
-- both:
--   - 32-bit bit operations.  LuaJIT has its `bit` library (results
--     signed); Lua 5.3+ has operators (&, |, ~, <<, >>) that LuaJIT cannot
--     even parse, so they are built here from source text with `load`,
--     and every result is masked to unsigned 32 bits.  Callers compare
--     32-bit values only through `u32` (both sides unsigned).
--   - a byte window: an FFI uint8_t array on LuaJIT (fast), a table
--     elsewhere; `window_string(w, n)` gives its first n bytes.
--   - making a folder, setting permissions and a file's time: direct
--     system calls through FFI on LuaJIT; mkdir, chmod and touch through
--     the shell elsewhere (a process per call: slower, the same result).

local compat = {}

local has_ffi, ffi = pcall(require, "ffi")
local has_bit, bitlib = pcall(require, "bit")

-- {{{ local function quote
local function quote(path)
    return "'" .. path:gsub("'", "'\\''") .. "'"
end
-- }}}
compat.quote = quote

-- Path: LuaJIT's bit library — used as it is.  Lua 5.3+ — operators,
-- from source text.  Neither (plain Lua 5.1/5.2) — cannot run.
if has_bit then
    compat.band, compat.bor, compat.bxor = bitlib.band, bitlib.bor, bitlib.bxor
    compat.lshift, compat.rshift, compat.bnot = bitlib.lshift, bitlib.rshift, bitlib.bnot
elseif _VERSION == "Lua 5.3" or _VERSION == "Lua 5.4" then
    local make = load([[
        local M = 0xFFFFFFFF
        return {
            band = function(a, b) return (a & b) & M end,
            bor = function(a, b) return (a | b) & M end,
            bxor = function(a, b) return (a ~ b) & M end,
            lshift = function(a, n) return (a << n) & M end,
            rshift = function(a, n) return (a & M) >> n end,
            bnot = function(a) return (~a) & M end,
        }
    ]])
    local ops = make()
    compat.band, compat.bor, compat.bxor = ops.band, ops.bor, ops.bxor
    compat.lshift, compat.rshift, compat.bnot = ops.lshift, ops.rshift, ops.bnot
else
    error("zip-compat: needs LuaJIT or Lua 5.3/5.4 (this is " .. _VERSION .. ")", 0)
end

-- {{{ function compat.u32
-- Any 32-bit result, signed (LuaJIT) or not, as a number 0 .. 2^32-1.
function compat.u32(n)
    return n % 4294967296
end
-- }}}

-- {{{ function compat.int
-- A whole number as an integer (Lua 5.3+ keeps integers and floats apart;
-- a float key or argument can surprise).  LuaJIT: the number itself.
local math_tointeger = math.tointeger
function compat.int(n)
    if math_tointeger then return math_tointeger(n) end
    return n
end
-- }}}

-- Byte windows.
if has_ffi then
    -- {{{ function compat.new_window
    function compat.new_window(size)
        return ffi.new("uint8_t[?]", size)
    end
    -- }}}
    -- {{{ function compat.window_string
    function compat.window_string(window, length)
        return ffi.string(window, length)
    end
    -- }}}
else
    -- {{{ function compat.new_window
    function compat.new_window(size)
        local window = {}
        for i = 0, size - 1 do window[i] = 0 end
        return window
    end
    -- }}}
    -- {{{ function compat.window_string
    -- string.char takes its bytes as arguments: in runs of 4096, well
    -- under any interpreter's limit on arguments.
    local char, unpack = string.char, table.unpack
    function compat.window_string(window, length)
        local parts = {}
        for from = 0, length - 1, 4096 do
            local to = math.min(from + 4095, length - 1)
            parts[#parts + 1] = char(unpack(window, from, to))
        end
        return table.concat(parts)
    end
    -- }}}
end

-- Folders, permissions and times.
if has_ffi then
    -- {{{ local function declare
    local function declare(declaration)
        local ok, problem = pcall(ffi.cdef, declaration)
        -- ok: newly declared.  "redefine": declared elsewhere, usable.
        -- anything else: a real problem, stop the load.
        if not ok and not tostring(problem):match("redefine") then
            error(problem)
        end
    end
    -- }}}
    declare("int mkdir(const char *path, unsigned int mode);")
    declare("int chmod(const char *path, unsigned int mode);")
    declare("struct zip_compat_timeval { long tv_sec; long tv_usec; };")
    declare("int utimes(const char *path, const struct zip_compat_timeval times[2]);")
    -- {{{ function compat.mkdir
    -- Gives true when made, false when it could not be (e.g. it exists).
    function compat.mkdir(path, mode)
        return ffi.C.mkdir(path, mode) == 0
    end
    -- }}}
    -- {{{ function compat.chmod
    function compat.chmod(path, mode)
        if ffi.C.chmod(path, mode) ~= 0 then
            error("zip-compat: cannot set the permissions of " .. path, 0)
        end
    end
    -- }}}
    -- {{{ function compat.set_time
    -- Sets a file's access and modification time to `seconds` (any whole
    -- number, before 1970 or after 2038 alike: time_t is 64 bits).
    function compat.set_time(path, seconds)
        local times = ffi.new("struct zip_compat_timeval[2]", { { seconds, 0 }, { seconds, 0 } })
        if ffi.C.utimes(path, times) ~= 0 then
            error("zip-compat: cannot set the time of " .. path, 0)
        end
    end
    -- }}}
else
    -- {{{ local function succeeds
    local function succeeds(command)
        local a, b, c = os.execute(command)
        return a == true or a == 0 or (b == "exit" and c == 0)
    end
    -- }}}
    -- {{{ function compat.mkdir
    -- Gives true when made, false when it is already there; any other
    -- failure is mkdir's to report, on its own error stream.
    function compat.mkdir(path, mode)
        if compat.exists(path .. "/.") then return false end
        return succeeds("mkdir -m " .. string.format("%o", mode) .. " " .. quote(path))
    end
    -- }}}
    -- {{{ function compat.chmod
    function compat.chmod(path, mode)
        if not succeeds("chmod " .. string.format("%o", mode) .. " " .. quote(path)) then
            error("zip-compat: cannot set the permissions of " .. path, 0)
        end
    end
    -- }}}
    -- {{{ function compat.set_time
    function compat.set_time(path, seconds)
        if not succeeds("touch -h -d @" .. string.format("%d", seconds) .. " " .. quote(path)) then
            error("zip-compat: cannot set the time of " .. path, 0)
        end
    end
    -- }}}
end

-- {{{ function compat.exists
-- Does the path name a file or a folder?  (io.open opens folders on Linux.)
function compat.exists(path)
    local handle = io.open(path, "rb")
    if handle then
        handle:close()
        return true
    end
    return false
end
-- }}}

return compat
