-- zip-reader.lua — reading a received zip: every structural rule checked
-- before a byte is made, then each entry made under the meter (my-libs
-- issue 801; built for rao-chat issue 216e, shared with rmail #405).
--
-- A zip is read from its end: the end record points at the central
-- directory (one header per entry: name, sizes, CRC, where its data
-- starts), and each entry's data sits behind its own local header.  The
-- sender writes all of it, so every number here is a claim until checked.
-- The rules, in the order they are applied (each refusal is an error
-- "refused <reason>: <detail>", the reason one word the receiving side
-- records):
--
--   damaged         no end record, sizes or offsets that point outside
--                   the file, a local header that disagrees with its
--                   directory entry, extra fields running past their
--                   header, a CRC that does not match
--   zip64 / multi-disk / encrypted / unsupported
--                   formats our packer never writes (only a foreign tool
--                   makes them)
--   bad-name        an absolute name, a `.` or `..` piece, an empty piece,
--                   a backslash, NUL or a control character, a piece over
--                   241 bytes, a whole name over 4096 bytes, or a name
--                   outside ASCII without the UTF-8 flag
--   duplicate       two entries on one path, or a path used as both a
--                   file and a folder
--   overlap         two entries whose bytes share any part of the file
--                   (the overlapping bomb: many entries, one kernel)
--   special-file    devices, pipes, sockets
--   unpacks-larger / unpacks-smaller
--                   the entries' sizes pass the agreed size (or, when it is
--                   exact, fall short of it), or an entry makes more or fewer bytes than
--                   its own size says.  Checked with the meter while
--                   making: the moment output would pass, it stops.
--
-- On a refusal everything made in the destination is removed (owner:
-- "if it does pass it, then stop unzipping and remove the file").
--
-- What is made: regular files with the sender's permission bits (owner:
-- "Keep both, as unzip did") less set-user-id, set-group-id and sticky,
-- plus owner read and write; folders; and for every symbolic link, a
-- note `<name>.symlink.txt` saying where it pointed, never a link (owner:
-- "make a .txt file in the place of symlinks ... Forcing a recognition
-- check").  Times come from the extended-timestamp field as Unix time,
-- read in laps past 2038 (owner: "in 2038 let's expect to loop around to
-- 0 again"): the lap is the one that puts the date at or before arrival.

local compat = require("zip-compat")
local inflate = require("zip-inflate")

local reader = {}

local NAME_PIECE_BYTES = 241     -- the same limit as a message file's name
local NAME_BYTES = 4096          -- a whole path, as Linux's PATH_MAX
local LINK_TARGET_BYTES = 4096   -- a link's target is a path too
local LAP = 4294967296           -- 2^32 seconds, one turn of the clock face
local NOTE_SUFFIX = ".symlink.txt"

-- File types in the high 16 bits of a Unix entry's external attributes.
local TYPE_MASK, TYPE_FILE, TYPE_FOLDER, TYPE_LINK = 0xF000, 0x8000, 0x4000, 0xA000

-- {{{ local function refuse
local function refuse(reason, detail)
    error("refused " .. reason .. ": " .. detail, 0)
end
-- }}}

-- {{{ local function u16
local function u16(text, at)
    local a, b = text:byte(at, at + 1)
    return a + b * 256
end
-- }}}

-- {{{ local function u32
-- Unsigned: built from bytes with arithmetic, never bit operations, so a
-- value with the top bit set stays positive.
local function u32(text, at)
    local a, b, c, d = text:byte(at, at + 3)
    return a + b * 256 + c * 65536 + d * 16777216
end
-- }}}

-- {{{ local function read_at
local function read_at(handle, offset, length, file_size, what)
    if offset < 0 or length < 0 or offset + length > file_size then
        refuse("damaged", what .. " points outside the file")
    end
    handle:seek("set", offset)
    local bytes = handle:read(length) or ""
    if #bytes ~= length then
        refuse("damaged", what .. " could not be read whole")
    end
    return bytes
end
-- }}}

-- {{{ local function quote
local function quote(path)
    return "'" .. path:gsub("'", "'\\''") .. "'"
end
-- }}}

-- {{{ function reader.lap_time
-- The 32 bits of a Unix time, read on the lap that puts it at or before
-- `now` and within one lap of it.  1960 is stored as a large number whose
-- earlier lap is 1960; a date past 2038 is stored wrapped and found on
-- the next lap.  Only a date in the future (a wrong clock) is misread: it
-- drops back one lap, visibly wrong rather than quietly wrong.
function reader.lap_time(stored, now)
    return now - ((now - stored) % LAP)
end
-- }}}

-- {{{ local function check_name
-- Gives the pieces of a name and whether it names a folder (a trailing /).
local function check_name(name, utf8_flag)
    if #name == 0 then refuse("bad-name", "an entry with no name") end
    if #name > NAME_BYTES then refuse("bad-name", "a name of " .. #name .. " bytes") end
    -- Path: outside ASCII without the UTF-8 flag — its bytes would be read
    -- as the old DOS code page, so what it says is uncertain.
    if not utf8_flag and name:find("[\128-\255]") then
        refuse("bad-name", "a name outside ASCII without the UTF-8 flag")
    end
    if name:find("[%z\1-\31\127]") then refuse("bad-name", "a name with a control character") end
    if name:find("\\", 1, true) then refuse("bad-name", "a name with a backslash") end
    if name:sub(1, 1) == "/" then refuse("bad-name", "an absolute name") end
    local is_folder = name:sub(-1) == "/"
    local body = is_folder and name:sub(1, -2) or name
    local pieces = {}
    for piece in (body .. "/"):gmatch("([^/]*)/") do
        -- Path: an empty, current or parent piece, or one too long — refused.
        if piece == "" or piece == "." or piece == ".." then
            refuse("bad-name", "a name with an empty, '.' or '..' piece: " .. string.format("%q", name))
        end
        if #piece > NAME_PIECE_BYTES then
            refuse("bad-name", "a name piece of " .. #piece .. " bytes")
        end
        pieces[#pieces + 1] = piece
    end
    return pieces, is_folder
end
-- }}}

-- {{{ local function read_extras
-- Walks an extra-field block: id (2), size (2), data.  Gives the Unix time
-- from the extended-timestamp field (0x5455) when it carries one, and
-- whether a ZIP64 field (0x0001) is present.
local function read_extras(block)
    local at, unix_time, has_zip64 = 1, nil, false
    while at <= #block do
        if at + 3 > #block then refuse("damaged", "an extra field cut short") end
        local id, size = u16(block, at), u16(block, at + 2)
        local data_at = at + 4
        if data_at + size - 1 > #block then refuse("damaged", "an extra field runs past its header") end
        -- Path: by field — the timestamp (its first flag bit says a
        -- modification time follows), ZIP64, or any other: skipped by length.
        if id == 0x5455 then
            if size >= 5 and compat.band(block:byte(data_at), 1) ~= 0 then
                unix_time = u32(block, data_at + 1)
            end
        elseif id == 0x0001 then
            has_zip64 = true
        end
        at = data_at + size
    end
    return unix_time, has_zip64
end
-- }}}

-- {{{ local function find_end
-- The end-of-central-directory record: searched backwards through the
-- last 64 KiB + 22 bytes (a comment may follow it).  The one whose comment
-- length reaches exactly to the end of the file is the real one.
local function find_end(handle, file_size)
    local span = math.min(file_size, 65535 + 22)
    local tail = read_at(handle, file_size - span, span, file_size, "the end of the zip")
    for at = span - 21, 1, -1 do
        if tail:sub(at, at + 3) == "PK\5\6" and at + 21 + u16(tail, at + 20) == span then
            return tail:sub(at, at + 21), file_size - span + at - 1
        end
    end
    refuse("damaged", "no end record (not a zip, or cut short)")
end
-- }}}

-- {{{ function reader.list
-- Reads and checks the whole structure of the zip at path.  Gives the
-- entries in directory order: { name, pieces, kind ("file" | "folder" |
-- "link"), method, crc, compressed, size, data_at (where its data
-- starts), mode (permission bits), unix_time (32 bits, or nil) }, and the
-- total of their sizes.  Makes nothing.
function reader.list(path)
    local handle = io.open(path, "rb")
    if handle == nil then error("zip-reader: cannot open " .. path, 0) end
    local ok, entries, total = pcall(function()
        local file_size = handle:seek("end")
        local record, record_at = find_end(handle, file_size)
        local disk, dir_disk = u16(record, 5), u16(record, 7)
        local here, count = u16(record, 9), u16(record, 11)
        local dir_size, dir_at = u32(record, 13), u32(record, 17)
        if disk ~= 0 or dir_disk ~= 0 or here ~= count then
            refuse("multi-disk", "a zip split across disks")
        end
        if count == 0xFFFF or dir_size == 0xFFFFFFFF or dir_at == 0xFFFFFFFF then
            refuse("zip64", "a ZIP64 archive")
        end
        -- our packer always writes at least the packed thing itself
        if count == 0 then
            refuse("damaged", "a zip with no entries")
        end
        if dir_at + dir_size > record_at then
            refuse("damaged", "the directory runs into the end record")
        end
        local directory = read_at(handle, dir_at, dir_size, file_size, "the directory")
        local list, at, sum = {}, 1, 0
        local taken = {}       -- path → "file" | "folder"
        for _ = 1, count do
            if at + 45 > #directory or directory:sub(at, at + 3) ~= "PK\1\2" then
                refuse("damaged", "a directory entry is missing or cut short")
            end
            local made_by_host = directory:byte(at + 5)
            local flags, method = u16(directory, at + 8), u16(directory, at + 10)
            local crc, compressed, size = u32(directory, at + 16), u32(directory, at + 20), u32(directory, at + 24)
            local name_len, extra_len, comment_len = u16(directory, at + 28), u16(directory, at + 30), u16(directory, at + 32)
            local start_disk = u16(directory, at + 34)
            local attributes, local_at = u32(directory, at + 38), u32(directory, at + 42)
            local name_at = at + 46
            if name_at + name_len + extra_len + comment_len - 1 > #directory then
                refuse("damaged", "a directory entry runs past the directory")
            end
            local name = directory:sub(name_at, name_at + name_len - 1)
            local unix_time, has_zip64 = read_extras(directory:sub(name_at + name_len, name_at + name_len + extra_len - 1))
            at = name_at + name_len + extra_len + comment_len
            -- formats our packer never writes
            if has_zip64 or compressed == 0xFFFFFFFF or size == 0xFFFFFFFF or local_at == 0xFFFFFFFF then
                refuse("zip64", "a ZIP64 entry")
            end
            if start_disk ~= 0 then refuse("multi-disk", "an entry on another disk") end
            if compat.band(flags, 0x41) ~= 0 then refuse("encrypted", "an encrypted entry") end
            if method ~= 0 and method ~= 8 then
                refuse("unsupported", "compression method " .. method)
            end
            local pieces, named_folder = check_name(name, compat.band(flags, 0x800) ~= 0)
            -- The kind: from the Unix file type when a Unix system made
            -- the entry (host 3), else from the trailing slash alone.
            local kind, mode
            if made_by_host == 3 then
                local unix_mode = math.floor(attributes / 65536)
                local file_type = compat.band(unix_mode, TYPE_MASK)
                mode = compat.band(unix_mode, 0x1FF)
                -- Path: by file type — file, folder, link; anything else refused.
                if file_type == TYPE_FILE then
                    kind = "file"
                elseif file_type == TYPE_FOLDER then
                    kind = "folder"
                elseif file_type == TYPE_LINK then
                    kind = "link"
                else
                    refuse("special-file", string.format("%q is a device, pipe or socket", name))
                end
            else
                -- A foreign zip without Unix modes: owner read and write
                -- (and enter, for a folder) are all it is given.
                kind = named_folder and "folder" or "file"
                mode = named_folder and 0x1C0 or 0x180
            end
            if (kind == "folder") ~= named_folder then
                refuse("damaged", string.format("%q: its type and its trailing slash disagree", name))
            end
            if kind == "folder" and size ~= 0 then
                refuse("damaged", string.format("folder %q claims %d bytes", name, size))
            end
            if kind == "link" and size > LINK_TARGET_BYTES then
                refuse("damaged", string.format("link %q claims a %d-byte target", name, size))
            end
            -- A link's note is its name plus the suffix: that whole name
            -- must fit the piece limit too.
            if kind == "link" and #pieces[#pieces] + #NOTE_SUFFIX > NAME_PIECE_BYTES then
                refuse("bad-name", string.format("link %q is too long a name to hold its note's suffix", name))
            end
            -- One path, one entry; a path is a file or a folder, never both:
            -- every folder above an entry is taken as a folder.
            -- taken[path]: "file" (a file or link), "folder" (a folder
            -- entry), or "implied" (a folder only seen above other entries).
            local walked = ""
            for index, piece in ipairs(pieces) do
                walked = walked .. (index > 1 and "/" or "") .. piece
                local already = taken[walked]
                if index < #pieces then
                    -- Path: a folder above the entry — it must not be a file.
                    if already == "file" then
                        refuse("duplicate", string.format("%q sits under a file", name))
                    end
                    if already == nil then taken[walked] = "implied" end
                elseif already == nil then
                    -- Path: the entry's own path, new — taken.
                    taken[walked] = kind == "folder" and "folder" or "file"
                elseif already == "implied" and kind == "folder" then
                    -- Path: a folder entry for a folder already seen above
                    -- others — the same folder, now with its own entry.
                    taken[walked] = "folder"
                else
                    -- Path: seen before as anything else — refused.
                    refuse("duplicate", string.format("%q appears twice, or as a file and a folder", name))
                end
            end
            -- Kept with its local header's place for the next pass.
            list[#list + 1] = { name = name, pieces = pieces, kind = kind, method = method, flags = flags,
                                crc = crc, compressed = compressed, size = size, local_at = local_at,
                                mode = mode, unix_time = unix_time }
            sum = sum + size
        end
        if at ~= #directory + 1 then
            refuse("damaged", "the directory holds more than its entries")
        end
        -- Each local header: present, agreeing, and its bytes ours alone.
        local spans = {}
        for _, entry in ipairs(list) do
            local header = read_at(handle, entry.local_at, 30, file_size, "a local header")
            if header:sub(1, 4) ~= "PK\3\4" then refuse("damaged", "a local header is missing") end
            local local_flags, local_method = u16(header, 7), u16(header, 9)
            local name_len, extra_len = u16(header, 27), u16(header, 29)
            local local_name = read_at(handle, entry.local_at + 30, name_len, file_size, "a local name")
            if local_name ~= entry.name or local_method ~= entry.method
                    or compat.band(local_flags, 0x809) ~= compat.band(entry.flags, 0x809) then
                refuse("damaged", string.format("%q: its local header and directory entry disagree", entry.name))
            end
            -- Sizes after the data (flag bit 3): the header's are zero and
            -- the directory's are used; else the header must agree.
            if compat.band(entry.flags, 8) == 0 then
                if u32(header, 15) ~= entry.crc or u32(header, 19) ~= entry.compressed
                        or u32(header, 23) ~= entry.size then
                    refuse("damaged", string.format("%q: its local sizes disagree with the directory", entry.name))
                end
            end
            entry.data_at = entry.local_at + 30 + name_len + extra_len
            local finish = entry.data_at + entry.compressed
            -- Path: sizes after the data — a descriptor follows, with or
            -- without its own signature (12 or 16 bytes).
            if compat.band(entry.flags, 8) ~= 0 then
                local signature = read_at(handle, finish, 4, file_size, "a data descriptor")
                finish = finish + (signature == "PK\7\8" and 16 or 12)
            end
            if finish > dir_at then refuse("damaged", string.format("%q runs into the directory", entry.name)) end
            spans[#spans + 1] = { from = entry.local_at, to = finish, name = entry.name }
        end
        table.sort(spans, function(a, b) return a.from < b.from end)
        for index = 2, #spans do
            if spans[index].from < spans[index - 1].to then
                refuse("overlap", string.format("%q and %q share bytes", spans[index - 1].name, spans[index].name))
            end
        end
        return list, sum
    end)
    handle:close()
    if not ok then error(entries, 0) end
    return entries, total
end
-- }}}

-- {{{ local function note_text
-- A link's note, two lines, word for word as rmail #404a first wrote it:
-- where it pointed, as one readable line (control bytes and backslashes
-- shown as \xNN in capitals), then why it was not made.
local function note_text(target)
    local shown = target:gsub("[%z\1-\31\127\\]", function(c)
        return string.format("\\x%02X", c:byte())
    end)
    return "This was a symbolic link to: " .. shown .. "\n"
        .. "It was not recreated, because a link can point at any file on this "
        .. "computer. If it is valid here, make it by hand.\n"
end
-- }}}

-- {{{ function reader.extract
-- Makes every entry of the zip at path inside folder (which must exist and
-- be empty: the private extract folder).  options:
--   size      whole number: the agreed unpacked total
--   exact     true: the entries must add up to size exactly (rao-chat,
--             whose packer counts it exactly); false: size is only the
--             most they may add up to (rmail, whose senders declare
--             `du -sb` sizes, which are not exact).  Either way every
--             entry is held by the meter to its own claimed size.
--   now       whole number: the moment of arrival (for the time laps)
--   progress  function(stats) or nil: called at most once a second while
--             making, and once at the end with done = true.  stats =
--             { entry, entries_done, entries_total, bytes_in, bytes_out,
--             budget, started, done }
-- Gives the list of top-level names made.  On any refusal everything made
-- in folder is removed and the refusal is raised again.
function reader.extract(path, folder, options)
    if type(options.exact) ~= "boolean" then
        error("zip-reader: options.exact must be true or false", 0)
    end
    if type(options.size) ~= "number" or options.size ~= math.floor(options.size) or options.size < 0 then
        error("zip-reader: options.size must be a whole number of bytes", 0)
    end
    local entries, total = reader.list(path)
    -- Path: more than agreed — refused before anything is made; less than
    -- agreed — refused only when the size is exact.
    if total > options.size then
        refuse("unpacks-larger", string.format("the entries add up to %d bytes, %d were agreed", total, options.size))
    elseif total < options.size and options.exact then
        refuse("unpacks-smaller", string.format("the entries add up to %d bytes, %d were agreed", total, options.size))
    end
    local handle = io.open(path, "rb")
    if handle == nil then error("zip-reader: cannot open " .. path, 0) end
    local stats = { entry = "", entries_done = 0, entries_total = #entries, bytes_in = 0, bytes_out = 0,
                    budget = options.size, started = os.time(), done = false }
    local last_report = -1
    local tops, seen_top = {}, {}
    local folders = {}
    local ok, problem = pcall(function()
        for index, entry in ipairs(entries) do
            stats.entry = entry.name
            local target = folder .. "/" .. table.concat(entry.pieces, "/")
            -- every folder above it, made as needed (owner-only until done)
            local walked = folder
            for piece_index = 1, #entry.pieces - 1 do
                walked = walked .. "/" .. entry.pieces[piece_index]
                compat.mkdir(walked, 0x1C0)
            end
            local top = entry.pieces[1] .. ((#entry.pieces == 1 and entry.kind == "link") and NOTE_SUFFIX or "")
            if not seen_top[top] then
                seen_top[top] = true
                tops[#tops + 1] = top
            end
            handle:seek("set", entry.data_at)
            local remaining = entry.compressed
            -- {{{ local function read
            local function read(n)
                if remaining == 0 then return nil end
                local piece = handle:read(math.min(n, remaining))
                if piece == nil then return nil end
                remaining = remaining - #piece
                stats.bytes_in = stats.bytes_in + #piece
                return piece
            end
            -- }}}
            -- Path: by kind — a folder is made; a link's target is read
            -- into memory for its note; a file is made through a temporary.
            if entry.kind == "folder" then
                if not compat.mkdir(target, 0x1C0) and not compat.exists(target .. "/.") then
                    error("zip-reader: cannot make folder " .. target, 0)
                end
                folders[#folders + 1] = { path = target, entry = entry }
            elseif entry.kind == "link" then
                local parts = {}
                local made, crc = inflate.run(entry.method, read,
                    function(bytes) parts[#parts + 1] = bytes end, entry.size)
                if made ~= entry.size then
                    refuse("unpacks-smaller", string.format("%q made %d of its %d bytes", entry.name, made, entry.size))
                end
                if not inflate.same_crc(crc, entry.crc) then
                    refuse("damaged", string.format("%q does not match its CRC", entry.name))
                end
                stats.bytes_out = stats.bytes_out + made
                local note = target .. NOTE_SUFFIX
                if compat.exists(note) then
                    refuse("duplicate", string.format("%q's note collides with another entry", entry.name))
                end
                local out = assert(io.open(note, "wb"))
                out:write(note_text(table.concat(parts)))
                out:close()
            else
                local temporary = folder .. "/.writing-" .. index
                local out = io.open(temporary, "wb")
                if out == nil then error("zip-reader: cannot write " .. temporary, 0) end
                local made, crc = inflate.run(entry.method, read, function(bytes)
                    out:write(bytes)
                    stats.bytes_out = stats.bytes_out + #bytes
                    -- a report at most once a second
                    if options.progress ~= nil and os.time() ~= last_report then
                        last_report = os.time()
                        options.progress(stats)
                    end
                end, entry.size)
                out:close()
                if made ~= entry.size then
                    refuse("unpacks-smaller", string.format("%q made %d of its %d bytes", entry.name, made, entry.size))
                end
                if not inflate.same_crc(crc, entry.crc) then
                    refuse("damaged", string.format("%q does not match its CRC", entry.name))
                end
                if compat.exists(target) then
                    refuse("duplicate", string.format("%q collides with a link's note", entry.name))
                end
                os.rename(temporary, target)
                -- the sender's bits, never set-id or sticky, always owner rw
                compat.chmod(target, compat.bor(compat.band(entry.mode, 0x1FF), 0x180))
                -- Path: a Unix time sent — its lap; none (a foreign zip) —
                -- the file keeps the moment it was made here.
                if entry.unix_time ~= nil then
                    compat.set_time(target, reader.lap_time(entry.unix_time, options.now))
                end
            end
            stats.entries_done = index
        end
        -- Folders last, deepest first: making things inside a folder
        -- changes its time, and a folder closed to its owner could not be
        -- filled.  Owner read, write and enter always.
        table.sort(folders, function(a, b) return #a.path > #b.path end)
        for _, made in ipairs(folders) do
            compat.chmod(made.path, compat.bor(compat.band(made.entry.mode, 0x1FF), 0x1C0))
            if made.entry.unix_time ~= nil then
                compat.set_time(made.path, reader.lap_time(made.entry.unix_time, options.now))
            end
        end
    end)
    handle:close()
    stats.done = true
    -- Path: refused or failed — everything made here is removed, then the
    -- reason is raised again.  Made — the last report.
    if not ok then
        os.execute("find " .. quote(folder) .. " -mindepth 1 -delete")
        if options.progress ~= nil then options.progress(stats) end
        error(problem, 0)
    end
    if options.progress ~= nil then options.progress(stats) end
    return tops
end
-- }}}

return reader
