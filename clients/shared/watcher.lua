-- watcher.lua — cross-platform file watcher abstraction
--
-- Tries to load the platform-appropriate file watcher:
--   Linux:  rmail_inotify  (kernel inotify)
--   macOS:  rmail_fswatch  (kqueue)
--   Windows: rmail_fswatch  (ReadDirectoryChangesW)
--
-- Falls back to interval-only sync if none are available.
-- All watchers expose the same API:
--   watcher.init()                    -> fd
--   watcher.add_watch(fd, path, mask) -> wd
--   watcher.read(fd)                  -> events or nil
--   watcher.close(fd)
--   watcher.IN_CREATE, IN_DELETE, IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_TO

local watcher = {}

local mod = nil
local ok

-- Try each platform module in order
ok, mod = pcall(require, "rmail_inotify")    -- Linux
if not ok then ok, mod = pcall(require, "rmail_fswatch") end  -- macOS / Windows

if ok and mod then
    -- Re-export everything from the loaded module
    watcher.available = true
    watcher.init      = mod.init
    watcher.add_watch = mod.add_watch
    watcher.read      = mod.read
    watcher.close     = mod.close
    watcher.IN_CREATE      = mod.IN_CREATE
    watcher.IN_DELETE      = mod.IN_DELETE
    watcher.IN_MODIFY      = mod.IN_MODIFY
    watcher.IN_CLOSE_WRITE = mod.IN_CLOSE_WRITE
    watcher.IN_MOVED_TO    = mod.IN_MOVED_TO
else
    -- No file watcher available — stubs that do nothing
    watcher.available = false
    watcher.init      = function() return nil end
    watcher.add_watch = function() return nil end
    watcher.read      = function() return nil end
    watcher.close     = function() end
    watcher.IN_CREATE      = 256
    watcher.IN_DELETE      = 512
    watcher.IN_MODIFY      = 2
    watcher.IN_CLOSE_WRITE = 8
    watcher.IN_MOVED_TO    = 128
end

return watcher
