@echo off
REM install-thin-client-windows.bat — build rmail thin client dependencies on Windows
REM
REM Usage: install-thin-client-windows.bat [--force]
REM
REM Requires MinGW (provides gcc) or Visual Studio Build Tools (provides cl).
REM MinGW: https://www.mingw-w64.org/ or via: winget install mingw
REM
REM Builds into:
REM   libs\    — Lua modules (.lua + .dll)
REM   deps\    — locally compiled Lua and/or OpenSSL

setlocal enabledelayedexpansion

set FORCE=0
if "%1"=="--force" set FORCE=1

set SCRIPT_DIR=%~dp0
set CLIENT_ROOT=%SCRIPT_DIR%
for %%i in ("%SCRIPT_DIR%\..\..\") do set PROJECT_ROOT=%%~fi
set LIBS=%PROJECT_ROOT%libs
set DEPS=%PROJECT_ROOT%deps
set BUILD=%PROJECT_ROOT%.build-tmp

set LUA_VERSION=5.4.7
set DKJSON_VERSION=2.8

echo.
echo rmail thin client installer (Windows)
echo ======================================
echo.

if not exist "%LIBS%" mkdir "%LIBS%"
if not exist "%DEPS%" mkdir "%DEPS%"
if not exist "%BUILD%" mkdir "%BUILD%"

REM ── 1. C compiler ────────────────────────────────────────────────────

echo Checking for C compiler...
where gcc >nul 2>&1
if %ERRORLEVEL%==0 (
    set CC=gcc
    echo   found: gcc (MinGW^)
    goto :found_cc
)
where cl >nul 2>&1
if %ERRORLEVEL%==0 (
    set CC=cl
    echo   found: cl (MSVC^)
    goto :found_cc
)
echo   error: no C compiler found
echo.
echo   Install MinGW: https://www.mingw-w64.org/
echo   Or install via: winget install mingw
echo   Or install Visual Studio Build Tools
echo.
exit /b 1

:found_cc

REM ── 2. curl or wget ──────────────────────────────────────────────────

set DOWNLOAD_CMD=
where curl >nul 2>&1
if %ERRORLEVEL%==0 (
    set DOWNLOAD_CMD=curl -sL -o
    goto :found_dl
)
where wget >nul 2>&1
if %ERRORLEVEL%==0 (
    set DOWNLOAD_CMD=wget -q -O
    goto :found_dl
)
REM Windows 10+ has curl built in, but check certutil as last resort
where certutil >nul 2>&1
if %ERRORLEVEL%==0 (
    echo   using certutil for downloads (slow but works^)
    REM certutil needs different syntax — handled inline
    set DOWNLOAD_CMD=certutil
    goto :found_dl
)
echo   error: no download tool found (curl, wget, or certutil^)
exit /b 1

:found_dl

REM ── 3. Lua ───────────────────────────────────────────────────────────

echo.
echo Checking for Lua...
if exist "%DEPS%\lua\lua.exe" if %FORCE%==0 (
    echo   found locally compiled: deps\lua\
    set LUA_INC=-I%DEPS%\lua\include
    goto :done_lua
)
where lua >nul 2>&1
if %ERRORLEVEL%==0 (
    echo   found system Lua
    REM Try to find headers — common locations on Windows
    if exist "C:\lua\include\lua.h" (
        set LUA_INC=-IC:\lua\include
        goto :done_lua
    )
    if exist "%DEPS%\lua\include\lua.h" (
        set LUA_INC=-I%DEPS%\lua\include
        goto :done_lua
    )
)

echo   Lua not found — building from source...
echo   Downloading lua-%LUA_VERSION%...
if not exist "%BUILD%" mkdir "%BUILD%"
%DOWNLOAD_CMD% "%BUILD%\lua.tar.gz" "https://www.lua.org/ftp/lua-%LUA_VERSION%.tar.gz"
cd /d "%BUILD%"
tar xzf lua.tar.gz 2>nul
if not exist "lua-%LUA_VERSION%" (
    echo   error: failed to extract Lua archive
    echo   you may need to install tar or extract manually
    exit /b 1
)
cd "lua-%LUA_VERSION%"
echo   Compiling...
if "%CC%"=="gcc" (
    make -s mingw CC=gcc 2>nul
    if not exist "%DEPS%\lua" mkdir "%DEPS%\lua"
    copy /y src\lua.exe "%DEPS%\lua\" >nul 2>&1
    copy /y src\luac.exe "%DEPS%\lua\" >nul 2>&1
    if not exist "%DEPS%\lua\include" mkdir "%DEPS%\lua\include"
    copy /y src\lua.h "%DEPS%\lua\include\" >nul 2>&1
    copy /y src\luaconf.h "%DEPS%\lua\include\" >nul 2>&1
    copy /y src\lauxlib.h "%DEPS%\lua\include\" >nul 2>&1
    copy /y src\lualib.h "%DEPS%\lua\include\" >nul 2>&1
) else (
    echo   MSVC Lua build not yet automated — install Lua manually
    echo   or install MinGW for gcc
    exit /b 1
)
cd /d "%PROJECT_ROOT%"
set LUA_INC=-I%DEPS%\lua\include
echo   compiled lua-%LUA_VERSION%

:done_lua

REM ── 4. dkjson.lua ───────────────────────────────────────────────────

echo.
echo Checking for dkjson.lua...
if exist "%LIBS%\dkjson.lua" if %FORCE%==0 (
    echo   found
    goto :done_dkjson
)
echo   Downloading dkjson.lua...
%DOWNLOAD_CMD% "%LIBS%\dkjson.lua" "http://dkolf.de/dkjson-lua/dkjson-%DKJSON_VERSION%.lua"
echo   done

:done_dkjson

REM ── 5. rmail_crypto ─────────────────────────────────────────────────

echo.
echo Checking for rmail_crypto...
REM On Windows, OpenSSL detection and crypto compilation are more complex.
REM For now, check if pre-built exists.
if exist "%LIBS%\rmail_crypto.dll" if %FORCE%==0 (
    echo   found
    goto :done_crypto
)
echo   OpenSSL is required to build rmail_crypto.
echo   Install via: winget install OpenSSL
echo   Or download from: https://slproweb.com/products/Win32OpenSSL.html
echo.
echo   After installing, re-run this script.
echo   If OpenSSL is installed but not found, set OPENSSL_DIR:
echo     set OPENSSL_DIR=C:\Program Files\OpenSSL-Win64
echo     install-thin-client-windows.bat

if defined OPENSSL_DIR (
    echo   Found OPENSSL_DIR=%OPENSSL_DIR%
    echo   Compiling rmail_crypto...
    if "%CC%"=="gcc" (
        gcc -shared -O2 -Wall %LUA_INC% -I"%OPENSSL_DIR%\include" ^
            -o "%LIBS%\rmail_crypto.dll" ^
            "%PROJECT_ROOT%\rmail_crypto.c" ^
            -L"%OPENSSL_DIR%\lib" -lcrypto
        echo   done
    )
) else (
    echo   skipping rmail_crypto build (set OPENSSL_DIR and re-run^)
)

:done_crypto

REM ── 6. rmail_fswatch (ReadDirectoryChangesW) ────────────────────────

echo.
echo Checking for rmail_fswatch...
if exist "%LIBS%\rmail_fswatch.dll" if %FORCE%==0 (
    echo   found
    goto :done_fswatch
)
echo   Compiling rmail_fswatch...
if "%CC%"=="gcc" (
    gcc -shared -O2 -Wall %LUA_INC% ^
        -o "%LIBS%\rmail_fswatch.dll" ^
        "%CLIENT_ROOT%\rmail_fswatch_win.c"
    echo   done
) else (
    echo   MSVC build not yet automated
)

:done_fswatch

REM ── Done ────────────────────────────────────────────────────────────

echo.
echo =======================================
echo   rmail thin client ready
echo =======================================
echo.
echo Run with:
echo   %CLIENT_ROOT%run.bat --host YOUR_HOME_IP --port 8025 --token YOUR_TOKEN
echo.
echo Your mailbox will sync to %%USERPROFILE%%\mail-remote\
echo.

if exist "%BUILD%" rmdir /s /q "%BUILD%"
endlocal
