-- zip-inflate.lua — following a zip entry's recipe, one instruction at a
-- time, under a meter (my-libs issue 801; built for rao-chat issue 216e).
--
-- A zip entry is stored (method 0: its bytes as they are) or deflated
-- (method 8, RFC 1951).  A deflated stream is a recipe of two kinds of
-- instruction: "write these literal bytes" and "copy N bytes (3 to 258)
-- from D bytes back (1 to 32768)".  A zip bomb is a recipe that says
-- "copy 258 bytes from 1 back" over and over.  This file follows the
-- recipe itself and counts every byte it is about to make: the moment one
-- more instruction would pass the budget, it stops with a refusal, before
-- that instruction's bytes exist.  (Owner, 2026-09-29: "It won't expand if
-- we don't let it, and we set size limits accordingly".)
--
-- Built after Mark Adler's puff.c, the reference inflater written to be
-- read rather than to be fast: codes are decoded a bit at a time with
-- canonical Huffman counts, and every malformed table puff refuses is
-- refused here, by name.  A faster table decoder can replace `decode`
-- later without changing anything else.  Runs on LuaJIT and Lua 5.3/5.4
-- (every interpreter difference is in zip-compat.lua).
--
-- Data shapes:
--   read(n)  -> string of 1..n bytes, or nil at the end of the entry's
--               compressed bytes (the caller hands over exactly the
--               entry's compressed size, never more).
--   sink(bytes)  receives made bytes as a string, up to 32 KiB at a time.
--   budget   whole number: the most bytes this call may make.
--   Returns: bytes made (number), CRC-32 of them (number, 0 .. 2^32-1),
--   bytes read (number).
--   Refusals are errors whose text starts "refused <reason>: ", where
--   <reason> is one word the receiving side records (see zip-reader.lua).

local compat = require("zip-compat")
local band, bor, bxor, lshift, rshift, bnot = compat.band, compat.bor, compat.bxor,
    compat.lshift, compat.rshift, compat.bnot
local byte = string.byte

local inflate = {}

local WINDOW = 32768

-- {{{ local function refuse
-- Every refusal names its reason first, so the caller can record it.
local function refuse(reason, detail)
    error("refused " .. reason .. ": " .. detail, 0)
end
-- }}}

-- CRC-32 (the zip polynomial, reflected), one table of 256 entries.
local CRC_TABLE = {}
for n = 0, 255 do
    local c = n
    for _ = 1, 8 do
        -- low bit set: shift and fold in the polynomial; clear: shift only
        if band(c, 1) ~= 0 then
            c = bxor(rshift(c, 1), 0xEDB88320)
        else
            c = rshift(c, 1)
        end
    end
    CRC_TABLE[n] = c
end

-- {{{ function inflate.crc32_string
-- Continues a CRC-32 over the bytes of text.  Start with crc = 0; the pre-
-- and post-inversion are done here, so calls chain.  Gives 0 .. 2^32-1.
function inflate.crc32_string(crc, text)
    local c = bnot(crc)
    for i = 1, #text do
        c = bxor(CRC_TABLE[band(bxor(c, byte(text, i)), 0xff)], rshift(c, 8))
    end
    return compat.u32(bnot(c))
end
-- }}}

-- {{{ function inflate.same_crc
-- Two CRCs, however each was held (signed or not), as the same 32 bits.
function inflate.same_crc(a, b)
    return compat.u32(a) == compat.u32(b)
end
-- }}}


-- Lengths and distances: a base plus some extra bits (RFC 1951, 3.2.5).
local LBASE = { [0] = 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 }
local LEXT  = { [0] = 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 }
local DBASE = { [0] = 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
                257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
                8193, 12289, 16385, 24577 }
local DEXT  = { [0] = 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 }
-- The order code-length code lengths arrive in (RFC 1951, 3.2.7).
local ORDER = { [0] = 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 }

local MAXBITS = 15

-- {{{ local function new_code
-- A canonical Huffman code: count[len] = how many symbols have that code
-- length (1..15), symbol[] = the symbols ordered by code.
local function new_code(symbols)
    -- plain tables, not byte windows: counts and symbols reach 287
    local count, symbol = {}, {}
    for i = 0, 15 do count[i] = 0 end
    for i = 0, symbols - 1 do symbol[i] = 0 end
    return { count = count, symbol = symbol }
end
-- }}}

-- {{{ local function construct
-- Fills code from lengths[first .. first+n-1].  Gives 0 for a complete
-- code, a negative number for an over-subscribed one (more codes than the
-- bit lengths allow: always refused), a positive number for an incomplete
-- one (some bit patterns mean nothing: refused unless it is the single
-- one-bit code RFC 1951 allows).
local function construct(code, lengths, first, n)
    local count, symbol = code.count, code.symbol
    for len = 0, MAXBITS do count[len] = 0 end
    for s = 0, n - 1 do count[lengths[first + s]] = count[lengths[first + s]] + 1 end
    -- Path: no codes at all — complete in the sense that nothing can be decoded.
    if count[0] == n then return 0 end
    local left = 1
    for len = 1, MAXBITS do
        left = left * 2 - count[len]
        -- Path: over-subscribed — stop counting.
        if left < 0 then return left end
    end
    local offs = {}
    offs[1] = 0
    for len = 1, MAXBITS - 1 do offs[len + 1] = offs[len] + count[len] end
    for s = 0, n - 1 do
        local len = lengths[first + s]
        -- Path: a used symbol takes the next slot of its length; unused skipped.
        if len ~= 0 then
            symbol[offs[len]] = s
            offs[len] = offs[len] + 1
        end
    end
    return left
end
-- }}}

-- The fixed codes (block type 1) are the same every time: built once.
local FIXED_LEN, FIXED_DIST
do
    local lengths = compat.new_window(320)
    for s = 0, 143 do lengths[s] = 8 end
    for s = 144, 255 do lengths[s] = 9 end
    for s = 256, 279 do lengths[s] = 7 end
    for s = 280, 287 do lengths[s] = 8 end
    for s = 288, 317 do lengths[s] = 5 end
    FIXED_LEN, FIXED_DIST = new_code(288), new_code(30)
    construct(FIXED_LEN, lengths, 0, 288)
    construct(FIXED_DIST, lengths, 288, 30)
end

-- {{{ function inflate.run
-- method: 0 (stored) or 8 (deflated).  See the top of the file for read,
-- sink, budget and what is given back.
function inflate.run(method, read, sink, budget)
    local window = compat.new_window(WINDOW)
    local pos = 0          -- next free place in the window
    local made = 0         -- bytes made so far
    local crc = 0
    local buffer, buffer_len, buffer_at = "", 0, 1
    local bytes_in = 0
    local bitbuf, bitcnt = 0, 0

    -- {{{ local function flush
    -- Hands the window's filled part to the sink (a full window, or at the
    -- end what is left).  The bytes stay in the window for copies.
    local function flush()
        if pos > 0 then
            local bytes = compat.window_string(window, pos)
            crc = inflate.crc32_string(crc, bytes)
            sink(bytes)
        end
    end
    -- }}}

    -- {{{ local function put
    local function put(value)
        window[pos] = value
        pos = pos + 1
        -- Path: the window is full — handed over, and filling starts again.
        if pos == WINDOW then
            flush()
            pos = 0
        end
    end
    -- }}}

    -- {{{ local function meter
    -- Called before n more bytes are made: the moment they would pass the
    -- budget, nothing of them is made.
    local function meter(n)
        if made + n > budget then
            refuse("unpacks-larger", string.format("the entry would make more than its %d bytes", budget))
        end
        made = made + n
    end
    -- }}}

    -- {{{ local function next_byte
    local function next_byte()
        -- Path: the piece in hand is used up — ask for more; none left
        -- means the recipe wanted more than the entry holds.
        if buffer_at > buffer_len then
            buffer = read(65536)
            if buffer == nil or #buffer == 0 then
                refuse("damaged", "the compressed data ends before its last instruction")
            end
            buffer_len, buffer_at = #buffer, 1
        end
        local value = byte(buffer, buffer_at)
        buffer_at = buffer_at + 1
        bytes_in = bytes_in + 1
        return value
    end
    -- }}}

    -- {{{ local function bits
    -- The next n bits (0..16), least significant first.
    local function bits(n)
        local value = bitbuf
        while bitcnt < n do
            value = bor(value, lshift(next_byte(), bitcnt))
            bitcnt = bitcnt + 8
        end
        bitbuf = rshift(value, n)
        bitcnt = bitcnt - n
        return band(value, lshift(1, n) - 1)
    end
    -- }}}

    -- {{{ local function decode
    -- One symbol, read a bit at a time: a canonical code's first code of
    -- each length is known from the counts alone.
    local function decode(code)
        local count, symbol = code.count, code.symbol
        local value, first, index = 0, 0, 0
        for len = 1, MAXBITS do
            value = bor(value, bits(1))
            local here = count[len]
            -- Path: the bits so far are a code of this length — its symbol.
            if value - here < first then
                return symbol[index + (value - first)]
            end
            index = index + here
            first = lshift(first + here, 1)
            value = lshift(value, 1)
        end
        refuse("damaged", "a code longer than 15 bits (the code table is incomplete there)")
    end
    -- }}}

    -- {{{ local function stored_block
    local function stored_block()
        -- a stored block starts on a byte: the rest of this one is dropped
        bitbuf, bitcnt = 0, 0
        local len = next_byte() + next_byte() * 256
        local nlen = next_byte() + next_byte() * 256
        if len ~= band(bnot(nlen), 0xffff) then
            refuse("damaged", "a stored block's length and its check disagree")
        end
        meter(len)
        for _ = 1, len do put(next_byte()) end
    end
    -- }}}

    -- {{{ local function codes
    -- The instructions of one Huffman block, up to its end-of-block code.
    local function codes(lencode, distcode)
        while true do
            local symbol = decode(lencode)
            -- Path: a literal — one byte.
            if symbol < 256 then
                meter(1)
                put(symbol)
            -- Path: end of block.
            elseif symbol == 256 then
                return
            -- Path: a copy — a length, then a distance.
            else
                symbol = symbol - 257
                if symbol >= 29 then
                    refuse("damaged", "length code " .. (symbol + 257) .. " does not exist")
                end
                local len = LBASE[symbol] + bits(LEXT[symbol])
                symbol = decode(distcode)
                if symbol >= 30 then
                    refuse("damaged", "distance code " .. symbol .. " does not exist")
                end
                local dist = DBASE[symbol] + bits(DEXT[symbol])
                if dist > made then
                    refuse("damaged", "a copy from " .. dist .. " bytes back, before anything was made")
                end
                meter(len)
                -- byte by byte: a copy may overlap what it is making
                -- (distance 1, length 258 repeats one byte)
                for _ = 1, len do
                    put(window[band(pos - dist, WINDOW - 1)])
                end
            end
        end
    end
    -- }}}

    -- {{{ local function dynamic_block
    local function dynamic_block()
        local nlen = bits(5) + 257
        local ndist = bits(5) + 1
        local ncode = bits(4) + 4
        if nlen > 286 or ndist > 30 then
            refuse("damaged", "a block with too many length or distance codes")
        end
        local lengths = compat.new_window(320)
        for index = 0, ncode - 1 do lengths[ORDER[index]] = bits(3) end
        for index = ncode, 18 do lengths[ORDER[index]] = 0 end
        local lencode, distcode = new_code(288), new_code(30)
        -- the code-length code must be complete
        if construct(lencode, lengths, 0, 19) ~= 0 then
            refuse("damaged", "the code-length code is over-full or incomplete")
        end
        local index = 0
        while index < nlen + ndist do
            local symbol = decode(lencode)
            -- Path: a length 0..15 — written as it is.
            if symbol < 16 then
                lengths[index] = symbol
                index = index + 1
            else
                -- Path: a repeat — of the last length (16), or of zero (17, 18).
                local len, times = 0, 0
                if symbol == 16 then
                    if index == 0 then
                        refuse("damaged", "a repeat of the last length with no length before it")
                    end
                    len = lengths[index - 1]
                    times = 3 + bits(2)
                elseif symbol == 17 then
                    times = 3 + bits(3)
                else
                    times = 11 + bits(7)
                end
                if index + times > nlen + ndist then
                    refuse("damaged", "code lengths repeated past the end of the list")
                end
                for _ = 1, times do
                    lengths[index] = len
                    index = index + 1
                end
            end
        end
        if lengths[256] == 0 then
            refuse("damaged", "a block with no end-of-block code")
        end
        -- incomplete is allowed only for a single code of one bit (RFC 1951)
        local left = construct(lencode, lengths, 0, nlen)
        if left < 0 or (left > 0 and nlen - lencode.count[0] ~= 1) then
            refuse("damaged", "the literal/length code is over-full or incomplete")
        end
        left = construct(distcode, lengths, nlen, ndist)
        if left < 0 or (left > 0 and ndist - distcode.count[0] ~= 1) then
            refuse("damaged", "the distance code is over-full or incomplete")
        end
        codes(lencode, distcode)
    end
    -- }}}

    -- Path: stored — the bytes as they are, through the same meter.
    if method == 0 then
        while true do
            local piece = read(65536)
            if piece == nil or #piece == 0 then break end
            bytes_in = bytes_in + #piece
            meter(#piece)
            for i = 1, #piece do put(byte(piece, i)) end
        end
        flush()
        return made, crc, bytes_in
    end
    -- Path: anything but stored or deflated — not ours to follow.
    if method ~= 8 then
        refuse("unsupported", "compression method " .. tostring(method))
    end
    local last = 0
    while last == 0 do
        last = bits(1)
        local kind = bits(2)
        -- Path: by block kind — stored, fixed codes, codes sent with the
        -- block; 3 is reserved and never valid.
        if kind == 0 then
            stored_block()
        elseif kind == 1 then
            codes(FIXED_LEN, FIXED_DIST)
        elseif kind == 2 then
            dynamic_block()
        else
            refuse("damaged", "block type 3, which is reserved")
        end
    end
    flush()
    -- The recipe is over: any whole byte still unread in the entry was
    -- never part of it, whether it is in the piece in hand or still to
    -- be read.
    local left_in_hand = buffer_at <= buffer_len
    local more = read(1)
    local left_to_read = more ~= nil and #more > 0
    if left_in_hand or left_to_read then
        refuse("damaged", "bytes left in the entry after its last block")
    end
    return made, crc, bytes_in
end
-- }}}

return inflate
