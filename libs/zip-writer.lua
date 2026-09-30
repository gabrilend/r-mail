-- zip-writer.lua — packing a file or folder into a zip of our own
-- (my-libs issue 801; built for rao-chat issue 216e, shared with rmail
-- #405).  Neither side calls the zip program any more (owner:
-- "yes use our own packer in all cases").
--
-- It writes what zip-reader.lua accepts and nothing else, so one
-- rulebook covers both sides:
--   - every entry stored (method 0) for now; byte-perfect compression is
--     rao-chat issue 217, and the reader already follows it;
--   - names relative to the packed thing's parent, UTF-8 flag always set,
--     never `..` or a leading `/` (a name holding one was made elsewhere);
--   - sizes and CRC in the local header, no data descriptor: the CRC is
--     written as 0 first and patched once the bytes have been read;
--   - Unix permission bits and file type in the external attributes
--     ("made by" Unix), the modified time as Unix time in the extended-
--     timestamp field (0x5455), taken modulo 2^32 so dates past 2038 loop
--     (owner: "in 2038 let's expect to loop around to 0 again");
--   - a symbolic link stored as a link (its target as the entry's bytes),
--     never followed — except the packed path itself, which is followed
--     once (owner: "yes that").  The receiver makes a note of each link
--     (owner: "we can't trust what the sender would do").
--   - empty folders as `name/` entries.
--
-- A file changing while it is packed would be sent torn (rmail did): the
-- tree is listed before and after packing, and any file whose size or time
-- moved, or whose bytes read did not match its listed size, fails the
-- pack.  The caller packs again later.
--
-- Not yet (volumes and pieces, rao-chat 216f): files of 4 GiB or more, zips
-- reaching 4 GiB, or 65,535 entries or more are refused here, loudly.

local compat = require("zip-compat")
local inflate = require("zip-inflate")

local writer = {}

local LAP = 4294967296
local LIMIT_32 = 4294967295
local MAX_ENTRIES = 65535
local TYPE_FILE, TYPE_FOLDER, TYPE_LINK = 0x8000, 0x4000, 0xA000
local PIECE = 65536

-- {{{ local function quote
local function quote(path)
    return "'" .. path:gsub("'", "'\\''") .. "'"
end
-- }}}

-- {{{ local function le16
local function le16(n)
    return string.char(n % 256, math.floor(n / 256) % 256)
end
-- }}}

-- {{{ local function le32
-- Unsigned, from arithmetic (a value over 2^31 stays whole).
local function le32(n)
    return string.char(n % 256, math.floor(n / 256) % 256, math.floor(n / 65536) % 256,
                       math.floor(n / 16777216) % 256)
end
-- }}}

-- {{{ local function dos_time
-- The DOS date and time the format requires beside every entry (2-second
-- steps, no time zone, 1980 to 2107).  Written from UTC and never read by
-- our reader; dates outside its range are written as 1980-01-01.
local function dos_time(seconds)
    local t = os.date("!*t", seconds)
    if t.year < 1980 or t.year > 2107 then
        return 0, compat.bor(compat.lshift(0, 9), compat.lshift(1, 5), 1)
    end
    local time = compat.bor(compat.lshift(t.hour, 11), compat.lshift(t.min, 5), math.floor(t.sec / 2))
    local date = compat.bor(compat.lshift(t.year - 1980, 9), compat.lshift(t.month, 5), t.day)
    return time, date
end
-- }}}

-- {{{ local function listing
-- The tree under path, parents before children: find -H follows path
-- itself when it is a link and no link below it.  Each item: { type
-- ("f" | "d" | "l" | other), mode (permission bits), time (whole
-- seconds), stamp (the modified time as find wrote it, to the fraction of
-- a second: what the changed-while-packing check compares), size,
-- relative (path below the top, "" for the top), target (a link's
-- target) }.  Fields travel NUL-separated, so any name is safe.
local function listing(path)
    local pipe = io.popen("find -H " .. quote(path) .. " -printf '%y\\0%m\\0%T@\\0%s\\0%P\\0%l\\0'")
    local all = pipe:read("*a")
    pipe:close()
    -- Nothing listed: the path is gone or unreadable (find says why on its
    -- error stream).  Checked by what was printed, since LuaJIT's close
    -- of a pipe does not report the program's exit status.
    if all == "" then
        error("zip-writer: could not list " .. path, 0)
    end
    local fields = {}
    local from = 1
    while from <= #all do
        local stop = all:find("\0", from, true)
        fields[#fields + 1] = all:sub(from, stop - 1)
        from = stop + 1
    end
    local items = {}
    for at = 1, #fields, 6 do
        items[#items + 1] = { type = fields[at], mode = tonumber(fields[at + 1], 8),
                              time = math.floor(tonumber(fields[at + 2])), stamp = fields[at + 2], size = tonumber(fields[at + 3]),
                              relative = fields[at + 4], target = fields[at + 5] }
    end
    return items
end
-- }}}

-- {{{ function writer.pack
-- Packs path into zip_path.  Gives { size = the exact unpacked total (every
-- file's bytes plus every link target's), entries = how many }.
function writer.pack(path, zip_path)
    local top = path:match("([^/]+)/*$")
    local before = listing(path)
    if #before >= MAX_ENTRIES then
        error("zip-writer: " .. path .. " holds " .. #before .. " entries; volumes (rao-chat 216f) are not built yet", 0)
    end
    local out = io.open(zip_path, "wb")
    if out == nil then error("zip-writer: cannot write " .. zip_path, 0) end
    local directory = {}
    local offset, total = 0, 0
    local ok, problem = pcall(function()
        for _, item in ipairs(before) do
            local name = item.relative == "" and top or (top .. "/" .. item.relative)
            local file_type, bytes_of
            -- Path: by type — a folder (named with a trailing slash), a
            -- file, a link (its target is its bytes); anything else cannot
            -- be sent and fails the pack, naming it.
            if item.type == "d" then
                file_type, name = TYPE_FOLDER, name .. "/"
            elseif item.type == "f" then
                file_type = TYPE_FILE
            elseif item.type == "l" then
                file_type = TYPE_LINK
            else
                error("zip-writer: " .. name .. " is a device, pipe or socket and cannot be sent", 0)
            end
            if item.type == "f" and item.size > LIMIT_32 then
                error("zip-writer: " .. name .. " is 4 GiB or more; pieces (rao-chat 216f) are not built yet", 0)
            end
            local time, date = dos_time(item.time)
            local extra = le16(0x5455) .. le16(5) .. string.char(1) .. le32(item.time % LAP)
            local size = item.type == "f" and item.size or (item.type == "l" and #item.target or 0)
            local header_at = offset
            local header = "PK\3\4" .. le16(10) .. le16(0x0800) .. le16(0) .. le16(time) .. le16(date)
                .. le32(0) .. le32(size) .. le32(size) .. le16(#name) .. le16(#extra) .. name .. extra
            out:write(header)
            offset = offset + #header
            local crc, written = 0, 0
            -- Path: a file — its bytes, read in pieces; a link — its
            -- target; a folder — nothing.
            if item.type == "f" then
                local source = io.open(path .. (item.relative == "" and "" or ("/" .. item.relative)), "rb")
                if source == nil then error("zip-writer: cannot read " .. name, 0) end
                while true do
                    local piece = source:read(PIECE)
                    if piece == nil then break end
                    crc = inflate.crc32_string(crc, piece)
                    written = written + #piece
                    out:write(piece)
                end
                source:close()
            elseif item.type == "l" then
                crc = inflate.crc32_string(0, item.target)
                written = #item.target
                out:write(item.target)
            end
            if written ~= size then
                error("zip-writer: " .. name .. " changed while it was packed (" .. written .. " bytes read, "
                    .. size .. " listed)", 0)
            end
            offset = offset + written
            if offset > LIMIT_32 then
                error("zip-writer: the zip passes 4 GiB; volumes (rao-chat 216f) are not built yet", 0)
            end
            -- the CRC, now known, patched into the local header
            out:seek("set", header_at + 14)
            out:write(le32(crc % LAP))
            out:seek("set", offset)
            total = total + size
            local attributes = (file_type + item.mode % 4096) * 65536 + (item.type == "d" and 0x10 or 0)
            directory[#directory + 1] = "PK\1\2" .. le16(0x031E) .. le16(10) .. le16(0x0800) .. le16(0)
                .. le16(time) .. le16(date) .. le32(crc % LAP) .. le32(size) .. le32(size)
                .. le16(#name) .. le16(#extra) .. le16(0) .. le16(0) .. le16(0) .. le32(attributes)
                .. le32(header_at) .. name .. extra
        end
        local directory_bytes = table.concat(directory)
        out:write(directory_bytes)
        out:write("PK\5\6" .. le16(0) .. le16(0) .. le16(#directory) .. le16(#directory)
            .. le32(#directory_bytes) .. le32(offset) .. le16(0))
        out:close()
        out = nil
        -- Listed again: a size or time that moved means a torn copy.
        local after = listing(path)
        local same = #after == #before
        for index = 1, #before do
            local a, b = before[index], after[index]
            if not same or a.relative ~= b.relative or a.size ~= b.size or a.stamp ~= b.stamp
                    or a.type ~= b.type or a.target ~= b.target then
                same = false
                break
            end
        end
        if not same then
            error("zip-writer: " .. path .. " changed while it was packed; it will be packed again", 0)
        end
    end)
    -- Path: failed — the half-made zip is removed, the reason raised again.
    if not ok then
        -- still open when the failure came before the end record
        if out ~= nil then out:close() end
        os.remove(zip_path)
        error(problem, 0)
    end
    return { size = total, entries = #directory }
end
-- }}}

return writer
