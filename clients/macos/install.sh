#!/bin/sh
# install.sh — build rmail thin client dependencies on macOS
#
# Usage: ./install.sh [--force]
#
# Requires Xcode Command Line Tools (provides clang):
#   xcode-select --install

set -e

FORCE=false
[ "$1" = "--force" ] && FORCE=true

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLIENT_ROOT="$SCRIPT_DIR"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LIBS="$PROJECT_ROOT/libs"
DEPS="$PROJECT_ROOT/deps"
BUILD="$PROJECT_ROOT/.build-tmp"

LUA_VERSION="5.4.7"
LUASOCKET_VERSION="3.1.0"
OPENSSL_VERSION="3.2.1"
DKJSON_VERSION="2.8"

err()   { printf "  \033[31merror: %s\033[0m\n" "$*"; }
info()  { printf "  %s\n" "$*"; }
ok()    { printf "  \033[32m%s\033[0m\n" "$*"; }
warn()  { printf "  \033[33m%s\033[0m\n" "$*"; }

ask_yn() {
    printf "  %s [y/N] " "$1"
    read -r ans
    case "$ans" in [Yy]*) return 0 ;; *) return 1 ;; esac
}

download() {
    if command -v curl >/dev/null 2>&1; then
        curl -sL -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        err "neither curl nor wget found"
        exit 1
    fi
}

echo ""
echo "rmail thin client installer (macOS)"
echo "====================================="
echo ""

mkdir -p "$LIBS" "$DEPS" "$BUILD"

# ── 1. C compiler ──────────────────────────────────────────────────────

echo "Checking for C compiler..."
if command -v clang >/dev/null 2>&1; then
    CC=clang; ok "found: clang"
elif command -v cc >/dev/null 2>&1; then
    CC=cc; ok "found: cc"
elif command -v gcc >/dev/null 2>&1; then
    CC=gcc; ok "found: gcc"
else
    err "no C compiler found"
    info "install Xcode Command Line Tools: xcode-select --install"
    exit 1
fi

# ── 2. Lua ─────────────────────────────────────────────────────────────

echo ""
echo "Checking for Lua..."

LUA_INC=""

find_lua_headers() {
    for cmd in lua5.4 lua luajit; do
        local ver
        ver=$($cmd -v 2>&1 || true)
        case "$ver" in *"Lua 5."*|*"LuaJIT"*)
            # Homebrew paths
            for prefix in /opt/homebrew /usr/local; do
                for sub in include include/lua include/lua5.4; do
                    [ -f "$prefix/$sub/lua.h" ] && { LUA_INC="-I$prefix/$sub"; return 0; }
                done
            done
            # pkg-config
            if command -v pkg-config >/dev/null 2>&1; then
                for name in lua5.4 lua-5.4 lua54 luajit lua; do
                    if pkg-config --exists "$name" 2>/dev/null; then
                        LUA_INC=$(pkg-config --cflags "$name" 2>/dev/null)
                        return 0
                    fi
                done
            fi
            ;;
        esac
    done
    return 1
}

compile_lua() {
    info "Downloading lua-$LUA_VERSION..."
    mkdir -p "$BUILD"
    download "https://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz" "$BUILD/lua.tar.gz"
    cd "$BUILD" && tar xzf lua.tar.gz && cd "lua-$LUA_VERSION"
    info "Compiling..."
    make -s macosx CC="$CC" 2>/dev/null
    make -s install INSTALL_TOP="$DEPS/lua" 2>/dev/null
    cd "$PROJECT_ROOT"
    LUA_INC="-I$DEPS/lua/include"
    ok "compiled lua-$LUA_VERSION"
}

if [ -x "$DEPS/lua/bin/lua" ] && ! $FORCE; then
    ok "found locally compiled: deps/lua/"
    LUA_INC="-I$DEPS/lua/include"
elif find_lua_headers; then
    ok "found system Lua (headers: $LUA_INC)"
else
    warn "Lua not found"
    if ask_yn "Build Lua $LUA_VERSION from source?"; then
        compile_lua
    else
        err "Lua is required — install via: brew install lua"
        exit 1
    fi
fi

# ── 3. OpenSSL ─────────────────────────────────────────────────────────

echo ""
echo "Checking for OpenSSL..."

OPENSSL_INC=""
OPENSSL_LIB=""
SSL_RPATH=""

find_openssl() {
    # Homebrew OpenSSL (not in default path on macOS)
    for prefix in /opt/homebrew/opt/openssl@3 /opt/homebrew/opt/openssl \
                  /usr/local/opt/openssl@3 /usr/local/opt/openssl; do
        if [ -f "$prefix/include/openssl/evp.h" ]; then
            OPENSSL_INC="-I$prefix/include"
            OPENSSL_LIB="-L$prefix/lib"
            SSL_RPATH="$prefix/lib"
            return 0
        fi
    done
    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl 2>/dev/null; then
        OPENSSL_INC=$(pkg-config --cflags openssl 2>/dev/null)
        OPENSSL_LIB=$(pkg-config --libs openssl 2>/dev/null)
        return 0
    fi
    return 1
}

compile_openssl() {
    info "Downloading openssl-$OPENSSL_VERSION..."
    download "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz" "$BUILD/openssl.tar.gz"
    cd "$BUILD" && tar xzf openssl.tar.gz && cd "openssl-$OPENSSL_VERSION"
    info "Compiling (this may take a few minutes)..."
    ./config --prefix="$DEPS/openssl" --openssldir="$DEPS/openssl/ssl" no-shared 2>/dev/null
    make -s -j"$(sysctl -n hw.ncpu 2>/dev/null || echo 2)" 2>/dev/null
    make -s install_sw 2>/dev/null
    cd "$PROJECT_ROOT"
    OPENSSL_INC="-I$DEPS/openssl/include"
    OPENSSL_LIB="-L$DEPS/openssl/lib"
    SSL_RPATH="$DEPS/openssl/lib"
    ok "compiled openssl-$OPENSSL_VERSION"
}

if [ -d "$DEPS/openssl" ] && ! $FORCE; then
    ok "found locally compiled: deps/openssl/"
    OPENSSL_INC="-I$DEPS/openssl/include"
    OPENSSL_LIB="-L$DEPS/openssl/lib"
    SSL_RPATH="$DEPS/openssl/lib"
elif find_openssl; then
    ok "found system OpenSSL"
else
    warn "OpenSSL not found"
    info "macOS ships LibreSSL, not OpenSSL — headers may be missing"
    if ask_yn "Build OpenSSL $OPENSSL_VERSION from source?"; then
        compile_openssl
    else
        err "OpenSSL is required — install via: brew install openssl"
        exit 1
    fi
fi

# ── 4. dkjson.lua ──────────────────────────────────────────────────────

echo ""
echo "Checking for dkjson.lua..."
if [ -f "$LIBS/dkjson.lua" ] && ! $FORCE; then
    ok "found"
else
    info "Downloading dkjson.lua..."
    download "http://dkolf.de/dkjson-lua/dkjson-$DKJSON_VERSION.lua" "$LIBS/dkjson.lua"
    ok "done"
fi

# ── 5. luasocket ───────────────────────────────────────────────────────

echo ""
echo "Checking for luasocket..."
if [ -f "$LIBS/socket/core.so" ] && ! $FORCE; then
    ok "found"
else
    info "Downloading luasocket-$LUASOCKET_VERSION..."
    download "https://github.com/lunarmodules/luasocket/archive/refs/tags/v$LUASOCKET_VERSION.tar.gz" \
             "$BUILD/luasocket.tar.gz"
    cd "$BUILD" && tar xzf luasocket.tar.gz && cd "luasocket-$LUASOCKET_VERSION"
    info "Compiling..."
    make -s LUAINC_macosx="$LUA_INC" \
         PLAT=macosx \
         CC_macosx="$CC" \
         clean all 2>/dev/null
    mkdir -p "$LIBS/socket" "$LIBS/mime"
    cp src/socket.lua src/mime.lua src/ltn12.lua "$LIBS/"
    cp src/socket/*.lua "$LIBS/socket/"
    cp src/socket-3.0.0.so "$LIBS/socket/core.so" 2>/dev/null || \
    cp src/socket.so "$LIBS/socket/core.so" 2>/dev/null
    cp src/mime-1.0.3.so "$LIBS/mime/core.so" 2>/dev/null || \
    cp src/mime.so "$LIBS/mime/core.so" 2>/dev/null
    cd "$PROJECT_ROOT"
    ok "done"
fi

# ── 6. rmail_crypto.so ─────────────────────────────────────────────────

echo ""
echo "Checking for rmail_crypto.so..."
if [ -f "$LIBS/rmail_crypto.so" ] && ! $FORCE; then
    ok "found"
else
    info "Compiling rmail_crypto.so..."
    $CC -shared -fPIC -O2 -Wall \
        $LUA_INC $OPENSSL_INC \
        ${SSL_RPATH:+-Wl,-rpath,"$SSL_RPATH"} \
        -o "$LIBS/rmail_crypto.so" \
        "$PROJECT_ROOT/rmail_crypto.c" \
        $OPENSSL_LIB -lcrypto
    ok "done"
fi

# ── 7. rmail_fswatch.so (kqueue) ──────────────────────────────────────

echo ""
echo "Checking for rmail_fswatch.so..."
if [ -f "$LIBS/rmail_fswatch.so" ] && ! $FORCE; then
    ok "found"
else
    info "Compiling rmail_fswatch.so..."
    $CC -shared -fPIC -O2 -Wall \
        $LUA_INC \
        -o "$LIBS/rmail_fswatch.so" \
        "$CLIENT_ROOT/rmail_fswatch.c"
    ok "done"
fi

# ── Done ───────────────────────────────────────────────────────────────

echo ""
echo "======================================="
echo "  rmail thin client ready"
echo "======================================="
echo ""
echo "Run with:"
echo "  $CLIENT_ROOT/run.sh --host YOUR_HOME_IP --port 8025 --token YOUR_TOKEN"
echo ""
echo "Your mailbox will sync to ~/mail-remote/"
echo ""

rm -rf "$BUILD"
