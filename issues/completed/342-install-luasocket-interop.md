# #342 — Install script: luasocket installed silently; system lua + project luasocket don't inter-operate

## Problem

When the user selects system Lua, the installer still installs a
project-local `luasocket` automatically. System Lua then cannot find
luasocket (because it's only installed into the project tree), and the
daemon fails to start on a system that has no system-wide luasocket.

Two things are wrong:

1. luasocket installation is automatic — the user is not asked about it.
2. The system-lua + project-luasocket combination is not wired up: the
   project's package path is not extended to include the project-local
   luasocket install.

## Fix

- Prompt the user before installing luasocket (or surface it clearly in
  the dependency summary).
- When the user runs with system Lua but a project-local luasocket,
  ensure `LUA_PATH` / `LUA_CPATH` (or the daemon's entrypoint) includes
  the project-local install so that `require("socket")` resolves.

## Source

From `issues/new-issue-please-sort`.
