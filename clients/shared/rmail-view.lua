#!/usr/bin/env lua
-- rmail-view.lua — read a mailbox in the terminal (issue #711)
--
-- Usage:
--   lua rmail-view.lua [MAILBOX-FOLDER]
--
-- With no folder, the thin client's mirror is used when there is exactly
-- one: ~/mail-remote/mailbox-<id>/.  Any mailbox folder works, the
-- daemon's own included, since the viewer only reads inbox/ and outbox/.
-- See viewer.lua for the keys, or the hint bar at the bottom of the
-- screen.

local script_dir = arg[0]:match("(.*/)") or "./"
package.path = script_dir .. "?.lua;" .. package.path

local term_lib = require("term")
local Viewer = require("viewer")

local function is_dir(path)
    local f = io.open(path .. "/.", "r")
    if f then f:close(); return true end
    return false
end

local function fail(msg)
    io.stderr:write("rmail-view: " .. msg .. "\n")
    os.exit(1)
end

local dir = arg[1]
if dir == "-h" or dir == "--help" then
    print("usage: rmail-view.lua [MAILBOX-FOLDER]")
    print("  reads a mailbox's inbox/ and outbox/; changes nothing")
    os.exit(0)
end
if not dir then
    local home = (os.getenv("HOME") or ".") .. "/mail-remote"
    local found = {}
    local p = io.popen("ls -d '" .. home:gsub("'", "'\\''") .. "'/mailbox-* 2>/dev/null")
    if p then
        for line in p:lines() do found[#found + 1] = line end
        p:close()
    end
    if #found == 1 then
        dir = found[1]
    elseif #found == 0 then
        fail("no mailbox under " .. home .. "; name the folder: rmail-view.lua FOLDER")
    else
        fail(#found .. " mailboxes under " .. home .. "; name one: rmail-view.lua FOLDER")
    end
end
if not (is_dir(dir .. "/inbox") or is_dir(dir .. "/outbox")) then
    fail(dir .. " has neither inbox/ nor outbox/, so it is not a mailbox")
end

local term, why = term_lib.open()
if not term then fail(why) end
local rows, cols = term.size()
local viewer = Viewer.new(dir, rows, cols)
local ok, err = pcall(viewer.run, viewer, term)
term.close()
if not ok then fail(tostring(err)) end
