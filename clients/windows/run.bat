@echo off
REM run.bat — launch the rmail thin client on Windows
set DIR=%~dp0
set LUA_PATH=%DIR%..\shared\?.lua;%DIR%..\..\libs\?.lua
set LUA_CPATH=%DIR%..\..\libs\?.dll;%DIR%..\shared\?.dll
lua "%DIR%..\shared\rmail-client.lua" %*
