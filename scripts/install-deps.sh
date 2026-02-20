#!/bin/sh
# install-deps.sh — compile rmail dependencies from source
#
# Usage: ./scripts/install-deps.sh [--force]
#
# Installs into:
#   libs/    — Lua modules (.lua + .so)
#   deps/    — locally compiled Lua 5.4 and/or OpenSSL (if needed)

set -e

FORCE=false
if [ "$1" = "--force" ]; then
    FORCE=true
fi

# resolve project root (parent of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIBS="$ROOT/libs"
DEPS="$ROOT/deps"
BUILD="$ROOT/.build-tmp"

# versions
LUA_VERSION="5.4.7"
LUASOCKET_VERSION="3.1.0"
LUASEC_VERSION="1.3.2"
OPENSSL_VERSION="3.2.1"
DKJSON_VERSION="2.8"

LUA_INC=""
LUA_LIB=""
OPENSSL_INC=""
OPENSSL_LIB=""
CC=""

# ============================================================
# Helpers
# ============================================================

info()  { printf "  %s\n" "$*"; }
warn()  { printf "  \033[33m%s\033[0m\n" "$*"; }
err()   { printf "  \033[31merror: %s\033[0m\n" "$*"; }
ok()    { printf "  \033[32m%s\033[0m\n" "$*"; }

ask_yn() {
    # ask_yn "prompt" — returns 0 for yes, 1 for no
    if $FORCE; then return 0; fi
    printf "  %s [y/N] " "$1"
    read -r ans
    case "$ans" in
        [Yy]*) return 0 ;;
        *) return 1 ;;
    esac
}

download() {
    # download URL OUTFILE
    if command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    elif command -v curl >/dev/null 2>&1; then
        curl -sL -o "$2" "$1"
    else
        err "neither wget nor curl found"
        exit 1
    fi
}

# ============================================================
# 1. C compiler
# ============================================================

echo "Checking for C compiler..."
if command -v cc >/dev/null 2>&1; then
    CC=cc
    ok "found: cc"
elif command -v gcc >/dev/null 2>&1; then
    CC=gcc
    ok "found: gcc"
else
    err "no C compiler found (cc or gcc required)"
    info "install one with your system package manager"
    exit 1
fi

# ============================================================
# 2. Lua (need headers to compile C extensions)
# ============================================================

echo "Checking for Lua..."

find_lua_system() {
    # find any lua binary in PATH (5.1+ or LuaJIT)
    local lua_bin=""
    local lua_ver=""
    for cmd in lua5.4 lua5.3 lua5.2 lua5.1 luajit lua; do
        local ver
        ver=$($cmd -v 2>&1 || true)
        case "$ver" in
            *"Lua 5."*|*"LuaJIT"*)
                lua_bin=$(command -v "$cmd" 2>/dev/null)
                lua_ver="$ver"
                break
                ;;
        esac
    done

    if [ -z "$lua_bin" ]; then
        return 1
    fi

    LUA_VER_STR="$lua_ver"

    # resolve symlinks to find the real prefix (works on NixOS)
    local real_bin
    real_bin=$(readlink -f "$lua_bin" 2>/dev/null || echo "$lua_bin")
    local prefix
    prefix=$(dirname "$(dirname "$real_bin")")

    # check for headers at the resolved prefix
    if [ -f "$prefix/include/lua.h" ]; then
        LUA_INC="-I$prefix/include"
        return 0
    fi

    # try pkg-config with various names
    if command -v pkg-config >/dev/null 2>&1; then
        for name in lua5.4 lua-5.4 lua54 lua5.3 lua-5.3 lua53 luajit lua; do
            if pkg-config --exists "$name" 2>/dev/null; then
                LUA_INC=$(pkg-config --cflags "$name" 2>/dev/null)
                LUA_LIB=$(pkg-config --libs "$name" 2>/dev/null)
                return 0
            fi
        done
    fi

    # try common header paths
    for dir in /usr/include/lua5.4 /usr/include/lua/5.4 /usr/include/lua54 \
               /usr/include/lua5.3 /usr/include/lua/5.3 /usr/include/luajit-2.1 \
               /usr/local/include/lua5.4 /usr/local/include /usr/include; do
        if [ -f "$dir/lua.h" ]; then
            LUA_INC="-I$dir"
            return 0
        fi
    done

    return 1
}

LUA_VER_STR=""

if [ -d "$DEPS/lua" ] && [ -f "$DEPS/lua/include/lua.h" ] && ! $FORCE; then
    LUA_INC="-I$DEPS/lua/include"
    LUA_LIB="-L$DEPS/lua/lib"
    ok "found locally compiled: deps/lua/"
elif find_lua_system; then
    ok "found: $LUA_VER_STR"
else
    warn "Lua not found in PATH."
    if ask_yn "Compile Lua 5.4 locally for this project? (~5MB disk)"; then
        echo "  Downloading lua-$LUA_VERSION..."
        mkdir -p "$BUILD"
        download "https://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz" "$BUILD/lua.tar.gz"
        cd "$BUILD"
        tar xzf lua.tar.gz
        cd "lua-$LUA_VERSION"
        info "Compiling..."
        make -s linux-readline CC="$CC" 2>/dev/null || make -s linux CC="$CC" 2>/dev/null
        make -s install INSTALL_TOP="$DEPS/lua" 2>/dev/null
        cd "$ROOT"
        LUA_INC="-I$DEPS/lua/include"
        LUA_LIB="-L$DEPS/lua/lib"
        ok "done (deps/lua/)"
    else
        err "Lua headers required to compile C extensions (luasocket, luasec)"
        exit 1
    fi
fi

# ============================================================
# 3. OpenSSL
# ============================================================

echo "Checking for OpenSSL..."

find_openssl_system() {
    # try the openssl binary to find its prefix
    local ssl_bin
    ssl_bin=$(command -v openssl 2>/dev/null)
    if [ -n "$ssl_bin" ]; then
        local real_bin
        real_bin=$(readlink -f "$ssl_bin" 2>/dev/null || echo "$ssl_bin")
        local prefix
        prefix=$(dirname "$(dirname "$real_bin")")
        if [ -f "$prefix/include/openssl/ssl.h" ]; then
            OPENSSL_INC="-I$prefix/include"
            OPENSSL_LIB="-L$prefix/lib"
            return 0
        fi
    fi

    # try pkg-config
    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl 2>/dev/null; then
        OPENSSL_INC=$(pkg-config --cflags openssl 2>/dev/null)
        OPENSSL_LIB=$(pkg-config --libs-only-L openssl 2>/dev/null)
        if [ -z "$OPENSSL_LIB" ]; then
            OPENSSL_LIB=""
        fi
        return 0
    fi

    # try common paths
    for dir in /usr/include /usr/local/include; do
        if [ -f "$dir/openssl/ssl.h" ]; then
            OPENSSL_INC="-I$dir"
            return 0
        fi
    done

    return 1
}

openssl_libdir() {
    # return the directory containing libssl.so for RPATH
    # try deriving from binary location first (NixOS)
    local ssl_bin
    ssl_bin=$(command -v openssl 2>/dev/null)
    if [ -n "$ssl_bin" ]; then
        local real_bin
        real_bin=$(readlink -f "$ssl_bin" 2>/dev/null || echo "$ssl_bin")
        local prefix
        prefix=$(dirname "$(dirname "$real_bin")")
        if [ -f "$prefix/lib/libssl.so" ] || [ -f "$prefix/lib/libssl.a" ]; then
            echo "$prefix/lib"
            return 0
        fi
    fi
    if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists openssl 2>/dev/null; then
        pkg-config --variable=libdir openssl 2>/dev/null && return 0
    fi
    for dir in /usr/lib /usr/lib64 /usr/local/lib /usr/lib/x86_64-linux-gnu; do
        if [ -f "$dir/libssl.so" ] || [ -f "$dir/libssl.a" ]; then
            echo "$dir"
            return 0
        fi
    done
    echo "/usr/lib"
}

if [ -d "$DEPS/openssl" ] && [ -f "$DEPS/openssl/include/openssl/ssl.h" ] && ! $FORCE; then
    OPENSSL_INC="-I$DEPS/openssl/include"
    OPENSSL_LIB="-L$DEPS/openssl/lib"
    ok "found locally compiled: deps/openssl/"
elif find_openssl_system; then
    ok "found system-wide (headers: ${OPENSSL_INC:-default paths})"
else
    warn "OpenSSL not found system-wide."
    if ask_yn "Compile OpenSSL locally for this project? (~80MB disk, takes a few minutes)"; then
        echo "  Downloading openssl-$OPENSSL_VERSION..."
        mkdir -p "$BUILD"
        download "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" "$BUILD/openssl.tar.gz"
        cd "$BUILD"
        tar xzf openssl.tar.gz
        cd "openssl-$OPENSSL_VERSION"
        info "Configuring..."
        ./Configure --prefix="$DEPS/openssl" no-shared no-tests -fPIC >/dev/null 2>&1
        info "Compiling (this takes a few minutes)..."
        make -s -j"$(nproc 2>/dev/null || echo 2)" >/dev/null 2>&1
        make -s install_sw >/dev/null 2>&1
        cd "$ROOT"
        OPENSSL_INC="-I$DEPS/openssl/include"
        OPENSSL_LIB="-L$DEPS/openssl/lib -L$DEPS/openssl/lib64"
        ok "done (deps/openssl/)"
    else
        err "OpenSSL headers required to compile luasec"
        exit 1
    fi
fi

# ============================================================
# 4. dkjson
# ============================================================

echo "Checking for dkjson..."

if [ -f "$LIBS/dkjson.lua" ] && ! $FORCE; then
    ok "found in libs/dkjson.lua"
else
    if $FORCE || [ ! -f "$LIBS/dkjson.lua" ]; then
        info "Downloading dkjson..."
        mkdir -p "$LIBS"
        download "http://dkolf.de/dkjson-lua/dkjson-$DKJSON_VERSION.lua" "$LIBS/dkjson.lua"
        ok "done (libs/dkjson.lua)"
    fi
fi

# ============================================================
# 5. luasocket
# ============================================================

echo "Checking for luasocket..."

install_luasocket() {
    info "Downloading luasocket v$LUASOCKET_VERSION..."
    mkdir -p "$BUILD"
    download "https://github.com/lunarmodules/luasocket/archive/refs/tags/v$LUASOCKET_VERSION.tar.gz" "$BUILD/luasocket.tar.gz"
    cd "$BUILD"
    tar xzf luasocket.tar.gz
    cd "luasocket-$LUASOCKET_VERSION/src"

    info "Compiling socket/core.so..."
    SOCKET_SRCS="luasocket.c timeout.c buffer.c io.c auxiliar.c compat.c options.c inet.c usocket.c except.c select.c tcp.c udp.c"
    for src in $SOCKET_SRCS; do
        $CC $LUA_INC -DLUASOCKET_NODEBUG -Wall -O2 -fPIC -c -o "${src%.c}.o" "$src"
    done
    $CC -shared -fPIC -O -o socket-core.so \
        luasocket.o timeout.o buffer.o io.o auxiliar.o compat.o \
        options.o inet.o usocket.o except.o select.o tcp.o udp.o

    info "Compiling mime/core.so..."
    $CC $LUA_INC -DLUASOCKET_NODEBUG -Wall -O2 -fPIC -c -o mime.o mime.c
    # compat.o already built
    $CC -shared -fPIC -O -o mime-core.so mime.o compat.o

    info "Installing to libs/..."
    mkdir -p "$LIBS/socket" "$LIBS/mime"

    # C modules
    cp socket-core.so "$LIBS/socket/core.so"
    cp mime-core.so "$LIBS/mime/core.so"

    # Lua modules
    cp socket.lua "$LIBS/socket.lua"
    cp mime.lua "$LIBS/mime.lua"
    cp ltn12.lua "$LIBS/ltn12.lua"
    cp socket/http.lua "$LIBS/socket/http.lua"
    cp socket/url.lua "$LIBS/socket/url.lua"
    cp socket/tp.lua "$LIBS/socket/tp.lua"
    cp socket/ftp.lua "$LIBS/socket/ftp.lua"
    cp socket/smtp.lua "$LIBS/socket/smtp.lua"
    cp socket/headers.lua "$LIBS/socket/headers.lua"

    cd "$ROOT"
    ok "done (libs/socket/core.so, libs/mime/core.so)"
}

if [ -f "$LIBS/socket/core.so" ] && ! $FORCE; then
    ok "found in libs/socket/core.so"
    if ask_yn "luasocket already installed. Reinstall?"; then
        install_luasocket
    else
        info "Skipped."
    fi
else
    install_luasocket
fi

# ============================================================
# 6. luasec (with PSK support)
# ============================================================

echo "Checking for luasec..."

# determine OpenSSL libdir for RPATH
if [ -d "$DEPS/openssl" ]; then
    SSL_RPATH="$DEPS/openssl/lib"
    if [ -d "$DEPS/openssl/lib64" ]; then
        SSL_RPATH="$DEPS/openssl/lib64"
    fi
else
    SSL_RPATH="$(openssl_libdir)"
fi

install_luasec() {
    info "Downloading luasec v$LUASEC_VERSION..."
    mkdir -p "$BUILD"
    download "https://github.com/lunarmodules/luasec/archive/refs/tags/v$LUASEC_VERSION.tar.gz" "$BUILD/luasec.tar.gz"
    cd "$BUILD"
    tar xzf luasec.tar.gz
    cd "luasec-$LUASEC_VERSION/src"

    info "Building luasocket helper library..."
    cd luasocket
    for src in io.c buffer.c timeout.c usocket.c; do
        $CC $LUA_INC -Wall -O2 -fPIC -c -o "${src%.c}.o" "$src"
    done
    ar rcu libluasocket.a io.o buffer.o timeout.o usocket.o
    ranlib libluasocket.a
    cd ..

    info "Compiling ssl.so (with PSK support)..."
    LUASEC_DEFS="-DWITH_LUASOCKET -DLSEC_ENABLE_PSK"
    LUASEC_SRCS="options.c x509.c context.c ssl.c config.c ec.c"
    for src in $LUASEC_SRCS; do
        $CC -O2 -fPIC -Wall \
            -I. $LUA_INC $OPENSSL_INC \
            $LUASEC_DEFS \
            -c -o "${src%.c}.o" "$src"
    done
    $CC -shared -fPIC -O \
        -L./luasocket $OPENSSL_LIB \
        -Wl,-rpath,"$SSL_RPATH" \
        -o ssl.so \
        options.o x509.o context.o ssl.o config.o ec.o \
        -lluasocket -lssl -lcrypto

    info "Installing to libs/..."
    mkdir -p "$LIBS/ssl"
    cp ssl.so "$LIBS/ssl.so"
    cp ssl.lua "$LIBS/ssl.lua"
    cp ssl/https.lua "$LIBS/ssl/https.lua"

    cd "$ROOT"
    ok "done (libs/ssl.so with PSK support)"
}

if [ -f "$LIBS/ssl.so" ] && ! $FORCE; then
    ok "found in libs/ssl.so"
    if ask_yn "luasec already installed. Reinstall?"; then
        install_luasec
    else
        info "Skipped."
    fi
else
    install_luasec
fi

# ============================================================
# 7. NAT traversal tools (optional, for auto_port_forward)
# ============================================================

MINIUPNPC_TAG="miniupnpc_2_3_3"
LIBNATPMP_COMMIT="134fc89e2781e154e40042641f4d8bcbe42579f1"

echo ""
echo "Checking for NAT traversal tools (optional)..."

HAVE_UPNPC=false
HAVE_NATPMPC=false

BIN="$ROOT/deps/bin"

# --- upnpc (miniupnpc) ---

if [ -x "$BIN/upnpc" ] && ! $FORCE; then
    ok "found locally compiled: deps/bin/upnpc"
    HAVE_UPNPC=true
elif command -v upnpc >/dev/null 2>&1 && ! $FORCE; then
    ok "found: upnpc (system)"
    HAVE_UPNPC=true
else
    info "upnpc not found (used for automatic UPnP port forwarding)"
    if ask_yn "Compile miniupnpc locally? (small, no extra dependencies)"; then
        mkdir -p "$BUILD" "$BIN"
        info "Downloading miniupnpc..."
        download "https://github.com/miniupnp/miniupnp/archive/refs/tags/$MINIUPNPC_TAG.tar.gz" "$BUILD/miniupnpc.tar.gz"
        cd "$BUILD"
        tar xzf miniupnpc.tar.gz
        cd "miniupnp-$MINIUPNPC_TAG/miniupnpc"
        info "Compiling..."
        make -s upnpc-static CC="$CC" 2>/dev/null
        cp build/upnpc-static "$BIN/upnpc"
        chmod +x "$BIN/upnpc"
        cd "$ROOT"
        ok "done (deps/bin/upnpc)"
        HAVE_UPNPC=true
    fi
fi

# --- natpmpc (libnatpmp) ---

if [ -x "$BIN/natpmpc" ] && ! $FORCE; then
    ok "found locally compiled: deps/bin/natpmpc"
    HAVE_NATPMPC=true
elif command -v natpmpc >/dev/null 2>&1 && ! $FORCE; then
    ok "found: natpmpc (system)"
    HAVE_NATPMPC=true
else
    info "natpmpc not found (used for automatic NAT-PMP port forwarding)"
    if ask_yn "Compile libnatpmp locally? (small, no extra dependencies)"; then
        mkdir -p "$BUILD" "$BIN"
        info "Downloading libnatpmp..."
        download "https://github.com/miniupnp/libnatpmp/archive/$LIBNATPMP_COMMIT.tar.gz" "$BUILD/libnatpmp.tar.gz"
        cd "$BUILD"
        tar xzf libnatpmp.tar.gz
        cd "libnatpmp-$LIBNATPMP_COMMIT"
        info "Compiling..."
        make -s natpmpc-static CC="$CC" 2>/dev/null
        cp natpmpc-static "$BIN/natpmpc"
        chmod +x "$BIN/natpmpc"
        cd "$ROOT"
        ok "done (deps/bin/natpmpc)"
        HAVE_NATPMPC=true
    fi
fi

if ! $HAVE_UPNPC || ! $HAVE_NATPMPC; then
    echo ""
    info "NAT traversal tools are optional — only needed if auto_port_forward = true"
fi

# ============================================================
# 8. Security probe (check for insecure NAT protocols)
# ============================================================

echo ""
echo "Checking router for insecure NAT protocols..."

NAT_INSECURE=false

# resolve to local binary if available
UPNPC_CMD="upnpc"
NATPMPC_CMD="natpmpc"
[ -x "$BIN/upnpc" ] && UPNPC_CMD="$BIN/upnpc"
[ -x "$BIN/natpmpc" ] && NATPMPC_CMD="$BIN/natpmpc"

if $HAVE_UPNPC; then
    if "$UPNPC_CMD" -s 2>/dev/null | grep -q "Found valid IGD"; then
        echo ""
        warn "================================================================"
        warn "WARNING: Your router has UPnP enabled!"
        warn "================================================================"
        warn ""
        warn "Any device on your network can open ports on your router without"
        warn "authentication. Malware commonly exploits this to bypass firewalls."
        warn ""
        warn "Strongly consider disabling UPnP in your router's admin panel."
        warn "================================================================"
        echo ""
        NAT_INSECURE=true
    else
        ok "UPnP IGD not detected (good)"
    fi
fi

if $HAVE_NATPMPC; then
    if "$NATPMPC_CMD" 2>/dev/null | grep -q "Public IP"; then
        echo ""
        warn "================================================================"
        warn "WARNING: Your router has NAT-PMP enabled!"
        warn "================================================================"
        warn ""
        warn "Any device on your network can create port mappings without"
        warn "authentication. Consider disabling NAT-PMP in your router settings."
        warn ""
        warn "================================================================"
        echo ""
        NAT_INSECURE=true
    else
        ok "NAT-PMP not detected (good)"
    fi
fi

if ! $HAVE_UPNPC && ! $HAVE_NATPMPC; then
    info "skipped (no NAT tools installed to probe with)"
fi

# ============================================================
# Clean up
# ============================================================

if [ -d "$BUILD" ]; then
    info "Cleaning up build files..."
    rm -rf "$BUILD"
fi

# ============================================================
# 9. Initial setup (contacts file with random port)
# ============================================================

echo ""
MAIL_DIR="${HOME}/mail"
CONTACTS_FILE="$MAIL_DIR/contacts"

if [ ! -f "$CONTACTS_FILE" ]; then
    echo "Setting up initial contacts file..."

    # generate random port in 50000-65000
    gen_random_port() {
        while true; do
            RAW=$(od -An -tu2 -N2 /dev/urandom | tr -d ' ')
            PORT=$(( (RAW % 15001) + 50000 ))
            # blacklist: known services in this range
            case "$PORT" in
                50000|51413|54321|55553|60000) continue ;;  # SAP, BitTorrent, common test ports
                *) echo "$PORT"; return ;;
            esac
        done
    }

    RANDOM_PORT=$(gen_random_port)

    mkdir -p "$MAIL_DIR"
    cat > "$CONTACTS_FILE" <<CONTACTS
{
  "me": {
    "name": "$(whoami)",
    "port": $RANDOM_PORT
  }
}
CONTACTS

    ok "created contacts file: $CONTACTS_FILE"
    echo ""
    echo "  your rmail port: $RANDOM_PORT"
    echo "  share this port (and your public IP) with contacts"
    echo "  to find your public IP: curl ifconfig.me"
    echo ""
else
    info "contacts file already exists, keeping it"
fi

# ============================================================
# Summary
# ============================================================

echo ""
echo "All dependencies installed."
echo ""
echo "  libs/dkjson.lua        — JSON library"
echo "  libs/socket/core.so    — luasocket"
echo "  libs/mime/core.so      — luasocket mime"
echo "  libs/ssl.so            — luasec (PSK enabled)"
echo ""
echo "To enable encryption, set encrypt = true in ~/.config/rmail/config"
if $NAT_INSECURE; then
    echo ""
    warn "NOTE: insecure NAT protocols detected on your router (see warnings above)"
fi
