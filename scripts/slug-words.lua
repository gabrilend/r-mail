#!/usr/bin/env luajit
-- slug-words.lua — hand-alternating word tooling for #376 URL slugs.
--
-- Hand split (standard touch-typing):
--   Left:  q w e r t  a s d f g  z x c v b
--   Right: y u i o p  h j k l  n m
--
-- A word "alternates" if every consecutive letter switches hands.  Slug
-- generation uses one RIGHT-starting word first, then LEFT-starting
-- words (the dash "goes to the left hand"), so we keep two dictionaries:
--   data/slug-words-left.txt   (words that start on the left hand)
--   data/slug-words-right.txt  (words that start on the right hand)
-- Each is one lowercase word per line, sorted.
--
-- Subcommands:
--   classify <word>       report start hand + whether it alternates
--   gen <source-dict>     (re)build both dictionaries from a word list
--                         (honours MIN= / MAX= env vars, default 3..9)
--   add <word>            add a word to the correct dictionary; errors if
--                         it doesn't alternate or is already present

local script_dir = (arg[0] or "."):match("^(.*)/") or "."
local DATA_DIR   = script_dir .. "/../data"
local DICT = { L = DATA_DIR .. "/slug-words-left.txt",
               R = DATA_DIR .. "/slug-words-right.txt" }

local LEFT, RIGHT = "qwertasdfgzxcvb", "yuiophjklnm"
local hand_of = {}
for c in LEFT:gmatch(".")  do hand_of[c] = "L" end
for c in RIGHT:gmatch(".") do hand_of[c] = "R" end

-- Returns (start_hand "L"/"R"/nil, alternates bool).  nil start means the
-- word contains a character that isn't a-z.
local function classify(word)
    word = word:lower()
    if #word == 0 then return nil, false end
    local start, prev
    for i = 1, #word do
        local h = hand_of[word:sub(i, i)]
        if not h then return nil, false end          -- non a-z
        if i == 1 then start = h
        elseif h == prev then return start, false end  -- two on one hand
        prev = h
    end
    return start, true
end

local function die(msg) io.stderr:write(msg .. "\n"); os.exit(1) end
local function hand_name(h) return h == "L" and "left" or "right" end

local function read_words(path)
    local set, list = {}, {}
    local f = io.open(path, "r")
    if f then
        for line in f:lines() do
            local w = line:gsub("%s+$", "")
            if w ~= "" and not set[w] then set[w] = true; list[#list + 1] = w end
        end
        f:close()
    end
    return set, list
end

local function write_words(path, list)
    table.sort(list)
    local f = io.open(path, "w") or die("cannot write " .. path)
    for _, w in ipairs(list) do f:write(w, "\n") end
    f:close()
end

local function cmd_classify(word)
    if not word then die("usage: slug-words.lua classify <word>") end
    local start, alt = classify(word)
    if not start then print(word .. ": rejected (contains a non-letter)"); return end
    print(string.format("%s: starts on the %s hand; %s",
        word:lower(), hand_name(start),
        alt and "ALTERNATES" or "does not alternate"))
end

local function cmd_gen(src)
    if not src then die("usage: slug-words.lua gen <source-dict>") end
    local min_len = tonumber(os.getenv("MIN")) or 3
    local max_len = tonumber(os.getenv("MAX")) or 9
    local f = io.open(src, "r") or die("cannot open " .. src)
    local seen, buckets, total = {}, { L = {}, R = {} }, 0
    for line in f:lines() do
        total = total + 1
        local w = line:gsub("%s+$", ""):lower()
        if #w >= min_len and #w <= max_len and not seen[w] then
            local start, alt = classify(w)
            if start and alt then
                seen[w] = true
                buckets[start][#buckets[start] + 1] = w
            end
        end
    end
    f:close()
    os.execute("mkdir -p '" .. DATA_DIR .. "'")
    write_words(DICT.L, buckets.L)
    write_words(DICT.R, buckets.R)
    io.stderr:write(string.format(
        "read %d words (len %d-%d)\n  left-start:  %d -> %s\n  right-start: %d -> %s\n",
        total, min_len, max_len, #buckets.L, DICT.L, #buckets.R, DICT.R))
end

local function cmd_add(word)
    if not word then die("usage: slug-words.lua add <word>") end
    local w = word:lower()
    local start, alt = classify(w)
    if not start then die("error: '" .. word .. "' contains a non-letter (a-z only)") end
    if not alt then die("error: '" .. w .. "' does not alternate hands \xe2\x80\x94 not added") end
    local path = DICT[start]
    local set, list = read_words(path)
    if set[w] then
        die("error: '" .. w .. "' is already in the " .. hand_name(start) .. "-hand dictionary")
    end
    list[#list + 1] = w
    write_words(path, list)
    print(string.format("added '%s' to the %s-hand dictionary (now %d words)",
        w, hand_name(start), #list))
end

local dispatch = { classify = cmd_classify, gen = cmd_gen, add = cmd_add }
local fn = dispatch[arg[1]]
if not fn then
    io.stderr:write("usage: slug-words.lua <classify|gen|add> <arg>\n")
    os.exit(1)
end
fn(arg[2])
