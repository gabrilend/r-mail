#!/bin/sh
# install.sh — compile rmail dependencies from source
#
# Usage: ./scripts/install.sh [--force] [--version dep=x.y.z ...]
#
# Examples:
#   ./scripts/install.sh --version lua=5.3.6
#   ./scripts/install.sh --version luasocket=3.0.0 --version openssl=3.0.0
#   ./scripts/install.sh --force --version lua=5.3.6
#
# Installs into:
#   libs/    — Lua modules (.lua + .so)
#   deps/    — locally compiled Lua 5.4 and/or OpenSSL (if needed)

set -e

FORCE=false

# resolve project root (parent of scripts/)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LIBS="$ROOT/libs"
DEPS="$ROOT/deps"
BUILD="$ROOT/.build-tmp"

# default versions
LUA_VERSION="5.4.7"
LUASOCKET_VERSION="3.1.0"
OPENSSL_VERSION="3.2.1"
DKJSON_VERSION="2.8"

# version ranges (min max) for validation
LUA_MIN="5.1"; LUA_MAX="5.4.7"
LUASOCKET_MIN="3.0.0"; LUASOCKET_MAX="3.1.0"
OPENSSL_MIN="1.1.1"; OPENSSL_MAX="3.2.1"
DKJSON_MIN="2.5"; DKJSON_MAX="2.8"

# ============================================================
# Helpers (defined early for argument parsing)
# ============================================================

err()   { printf "  \033[31merror: %s\033[0m\n" "$*"; }

# version_to_num "5.4.7" -> numeric value for comparison
# pads to 3 components: major * 1000000 + minor * 1000 + patch
version_to_num() {
    echo "$1" | awk -F. '{printf "%d\n", ($1+0)*1000000 + ($2+0)*1000 + ($3+0)}'
}

# validate_version dep_name version min max
# exits with error if version is outside [min, max]
validate_version() {
    _dep="$1"; _ver="$2"; _min="$3"; _max="$4"
    _ver_n=$(version_to_num "$_ver")
    _min_n=$(version_to_num "$_min")
    _max_n=$(version_to_num "$_max")
    if [ "$_ver_n" -lt "$_min_n" ] || [ "$_ver_n" -gt "$_max_n" ]; then
        err "$_dep version $_ver is out of range [$_min, $_max]"
        exit 1
    fi
}

# parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --force)
            FORCE=true
            shift
            ;;
        --version)
            if [ -z "$2" ]; then
                err "--version requires an argument (e.g., --version lua=5.3.6)"
                exit 1
            fi
            _key="${2%%=*}"
            _val="${2#*=}"
            if [ "$_key" = "$2" ] || [ -z "$_val" ]; then
                err "invalid --version format: $2 (expected dep=x.y.z)"
                exit 1
            fi
            case "$_key" in
                lua)
                    validate_version lua "$_val" "$LUA_MIN" "$LUA_MAX"
                    LUA_VERSION="$_val"
                    ;;
                luasocket)
                    validate_version luasocket "$_val" "$LUASOCKET_MIN" "$LUASOCKET_MAX"
                    LUASOCKET_VERSION="$_val"
                    ;;
                openssl)
                    validate_version openssl "$_val" "$OPENSSL_MIN" "$OPENSSL_MAX"
                    OPENSSL_VERSION="$_val"
                    ;;
                dkjson)
                    validate_version dkjson "$_val" "$DKJSON_MIN" "$DKJSON_MAX"
                    DKJSON_VERSION="$_val"
                    ;;
                *)
                    err "unknown dependency: $_key"
                    err "valid dependencies: lua, luasocket, openssl, dkjson"
                    exit 1
                    ;;
            esac
            shift 2
            ;;
        *)
            err "unknown argument: $1"
            exit 1
            ;;
    esac
done

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
ok()    { printf "  \033[32m%s\033[0m\n" "$*"; }

ask_yn() {
    # ask_yn "prompt" — returns 0 for yes, 1 for no
    printf "  %s [y/N] " "$1"
    read -r ans
    case "$ans" in
        [Yy]*) return 0 ;;
        *) return 1 ;;
    esac
}

ask_value() {
    # ask_value "prompt" "default" — prints prompt with default, reads input, echos result
    # If user presses enter without input, returns the default.
    # Prompt goes to /dev/tty so it is visible even when stdout is captured via $(...).
    printf "  %s [%s]: " "$1" "$2" >/dev/tty
    read -r _val </dev/tty
    if [ -z "$_val" ]; then
        echo "$2"
    else
        echo "$_val"
    fi
}

read_config_value() {
    # read_config_value FILE KEY — returns current value or ""
    grep "^${2}[[:space:]]*=" "$1" 2>/dev/null | sed 's/^[^=]*=[[:space:]]*//' | head -1
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
# 1. Configuration (ask first, before dependency checks)
# ============================================================

echo ""
echo "Setting up your rmail identity..."
echo "  (Press Enter to keep the default shown in [brackets])"

CONFIG_DIR="${HOME}/.config/rmail"
mkdir -p "$CONFIG_DIR"

gen_random_port() {
    while true; do
        RAW=$(od -An -tu2 -N2 /dev/urandom | tr -d ' ')
        PORT=$(( (RAW % 15001) + 50000 ))
        case "$PORT" in
            50000|51413|54321|55553|60000) continue ;;
            *) echo "$PORT"; return ;;
        esac
    done
}

# Mail directory first — everything derives from this
DEFAULT_MAIL="${HOME}/mail"

# Check for any existing config to pre-fill from (try the old location too)
_find_existing_config() {
    # try old-style config first for migration
    if [ -f "${HOME}/.config/rmail/config" ]; then
        echo "${HOME}/.config/rmail/config"
        return
    fi
    # try any config-* file in the config dir
    for f in "$CONFIG_DIR"/config-*; do
        if [ -f "$f" ]; then echo "$f"; return; fi
    done
}
EXISTING_CONFIG=$(_find_existing_config)


RMAIL_MAIL=$(ask_value "Mail directory" "$DEFAULT_MAIL")
RMAIL_MAIL=$(echo "$RMAIL_MAIL" | sed "s|^~|$HOME|")
RMAIL_MAIL=$(echo "$RMAIL_MAIL" | sed 's|/*$||')  # strip trailing slashes
MAIL_DIR="$RMAIL_MAIL"

# Derive config filename from mail path: /home/ritz/mail -> config-home-ritz-mail
CONFIG_SLUG=$(echo "$RMAIL_MAIL" | sed 's|^/||; s|/|-|g')
CONFIG_FILE="$CONFIG_DIR/config-$CONFIG_SLUG"

# If migrating from old config, use it as the source for defaults
if [ -n "$EXISTING_CONFIG" ] && [ "$EXISTING_CONFIG" != "$CONFIG_FILE" ]; then
    # Pre-fill from existing config
    _existing_name=$(read_config_value "$EXISTING_CONFIG" "name")
    _existing_port=$(read_config_value "$EXISTING_CONFIG" "port")
elif [ -f "$CONFIG_FILE" ]; then
    _existing_name=$(read_config_value "$CONFIG_FILE" "name")
    _existing_port=$(read_config_value "$CONFIG_FILE" "port")
fi

DEFAULT_NAME=$(whoami)
DEFAULT_PORT=$(gen_random_port)
[ -n "${_existing_name:-}" ] && DEFAULT_NAME="$_existing_name"
[ -n "${_existing_port:-}" ] && DEFAULT_PORT="$_existing_port"

# prompt for name
while true; do
    RMAIL_NAME=$(ask_value "Your name (shown to contacts)" "$DEFAULT_NAME")
    if echo "$RMAIL_NAME" | grep -qE '^[a-zA-Z0-9_-]+$'; then
        break
    fi
    warn "Name must contain only letters, numbers, hyphens, and underscores."
done

# prompt for port
while true; do
    RMAIL_PORT=$(ask_value "Port to listen on" "$DEFAULT_PORT")
    if echo "$RMAIL_PORT" | grep -qE '^[0-9]+$' && [ "$RMAIL_PORT" -ge 1 ] && [ "$RMAIL_PORT" -le 65535 ]; then
        break
    fi
    warn "Port must be a number between 1 and 65535."
done

# Write or update config file
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Creating config file..."
    cat > "$CONFIG_FILE" <<CONFIG
# rmail configuration
# see README.md for full documentation

# ---- identity ----

# your name as it appears to contacts (must match your key in the contacts file)
name = $RMAIL_NAME

# port rmail listens on for incoming messages
port = $RMAIL_PORT

# extra lua module path — searched before the bundled libs/ directory.
# use this if you installed luasocket/luasec/dkjson somewhere non-standard.
# libs = /path/to/lua-libs

# ---- networking ----

# on startup, rmail checks your public IP using multiple services.
# if a change is detected and confirmed, all contacts are notified
# and their contacts file is updated automatically.
notify_ip_change = true

# ---- NAT / port forwarding ----

# attempt automatic port forwarding via UPnP or NAT-PMP on startup.
# WARNING: these protocols are insecure — any device on your LAN can open ports
# on your router without authentication. malware commonly exploits this.
# prefer manual port forwarding through your router's admin panel.
# requires upnpc and/or natpmpc — run scripts/install.sh to compile them.
# auto_port_forward = false

# ---- hooks ----
# hooks let you run scripts in response to message events.

# on_receive_raw: runs before a received message is written to inbox/.
# \$1 is the raw message body. stdout REPLACES the body that gets saved.
# use for content filtering or transformation.
# on_receive_raw = /path/to/script.sh

# on_receive: runs after a message is written to inbox/.
# \$1 is the path to the saved inbox file.
# on_receive = /path/to/script.sh

# on_package: runs after an attachment is saved.
# \$1 is the path to the saved attachment.
# on_package = /path/to/script.sh

# on_send: runs once per recipient before a message is sent.
# \$1 is the message body, \$2 is the recipient name.
# stdout REPLACES the body sent to that recipient.
# use for per-recipient transformation.
# on_send = /path/to/script.sh

# on_delete: runs when a message is deleted. \$1 is the name of the other
# party (sender if inbox, recipient if outbox).
# on_delete = /path/to/script.sh
CONFIG
    ok "created config: $CONFIG_FILE"
else
    sed -i "s|^name = .*|name = $RMAIL_NAME|" "$CONFIG_FILE"
    sed -i "s|^port = .*|port = $RMAIL_PORT|" "$CONFIG_FILE"
    ok "updated config: $CONFIG_FILE"
fi

# Create mailbox directories and config symlink
mkdir -p "$MAIL_DIR/inbox" "$MAIL_DIR/outbox" "$MAIL_DIR/attachments" "$MAIL_DIR/.state"
ln -sf "$CONFIG_FILE" "$MAIL_DIR/config"
ln -sf "$CONFIG_FILE" "$ROOT/config"

echo ""
echo "  your rmail port: $RMAIL_PORT"
echo "  config: $CONFIG_FILE"
echo "  mailbox: $MAIL_DIR"
IPV6_ADDR=$(ip -6 addr show scope global 2>/dev/null | grep -v "temporary\|deprecated" | sed -n 's/.*inet6 \([0-9a-f:]*\)\/.*/\1/p' | head -1)
if [ -n "$IPV6_ADDR" ]; then
    echo ""
    ok "IPv6 available: $IPV6_ADDR"
    info "Contacts can reach you at [$IPV6_ADDR]:$RMAIL_PORT"
    info "No port forwarding needed for IPv6 — just open the port in your firewall."
else
    echo "  forward port $RMAIL_PORT on your router to this machine"
fi
echo ""

# Contacts file
CONTACTS_FILE="$MAIL_DIR/contacts"
if [ ! -f "$CONTACTS_FILE" ]; then
    cat > "$CONTACTS_FILE" <<CONTACTS
// rmail contacts
// Lines starting with // or # are comments.
//
// Add a contact like this:
//
//   alice.ip    = 203.0.113.1
//   alice.port  = 54321
//   alice.token = "your-shared-secret"
//
// Both sides must use the same token.
CONTACTS
    ok "created contacts file: $CONTACTS_FILE"
else
    info "contacts file already exists, keeping it"
fi

echo ""

# ============================================================
# 2. C compiler
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
    for cmd in lua5.4 luajit lua5.3 lua5.2 lua5.1 lua; do
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

compile_lua() {
    echo "  Downloading lua-$LUA_VERSION..."
    mkdir -p "$BUILD"
    download "https://www.lua.org/ftp/lua-$LUA_VERSION.tar.gz" "$BUILD/lua.tar.gz"
    cd "$BUILD"
    tar xzf lua.tar.gz
    cd "lua-$LUA_VERSION"
    info "Compiling..."
    LUA_MAJOR_MINOR=$(echo "$LUA_VERSION" | awk -F. '{print $1 "." $2}')
    case "$LUA_MAJOR_MINOR" in
        5.1|5.2)
            make -s linux CC="$CC" 2>/dev/null
            ;;
        *)
            make -s linux-readline CC="$CC" 2>/dev/null || make -s linux CC="$CC" 2>/dev/null
            ;;
    esac
    make -s install INSTALL_TOP="$DEPS/lua" 2>/dev/null
    cd "$ROOT"
    LUA_INC="-I$DEPS/lua/include"
    LUA_LIB="-L$DEPS/lua/lib"
    ok "done (deps/lua/)"
}

if [ -d "$DEPS/lua" ] && [ -f "$DEPS/lua/include/lua.h" ] && ! $FORCE; then
    LUA_INC="-I$DEPS/lua/include"
    LUA_LIB="-L$DEPS/lua/lib"
    ok "found locally compiled: deps/lua/"
elif find_lua_system; then
    ok "found system: $LUA_VER_STR"
    if ask_yn "Compile a local version instead? (recommended for reproducibility)"; then
        compile_lua
    fi
else
    if ask_yn "Lua not found in PATH. Compile locally?"; then
        compile_lua
    else
        err "Lua is required — cannot continue without it"
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

compile_openssl() {
    info "Downloading openssl-$OPENSSL_VERSION (this takes a few minutes)..."
    mkdir -p "$BUILD"
    OPENSSL_MAJOR=$(echo "$OPENSSL_VERSION" | awk -F. '{print $1}')
    if [ "$OPENSSL_MAJOR" -ge 3 ]; then
        download "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" "$BUILD/openssl.tar.gz"
    else
        download "https://github.com/openssl/openssl/releases/download/OpenSSL_$(echo "$OPENSSL_VERSION" | tr '.' '_')/openssl-$OPENSSL_VERSION.tar.gz" "$BUILD/openssl.tar.gz"
    fi
    cd "$BUILD"
    tar xzf openssl.tar.gz
    cd "openssl-$OPENSSL_VERSION"
    info "Configuring..."
    if [ "$OPENSSL_MAJOR" -ge 3 ]; then
        ./Configure --prefix="$DEPS/openssl" no-shared no-tests -fPIC >/dev/null 2>&1
    else
        ./config --prefix="$DEPS/openssl" no-shared -fPIC >/dev/null 2>&1
    fi
    info "Compiling..."
    make -s -j"$(nproc 2>/dev/null || echo 2)" >/dev/null 2>&1
    make -s install_sw >/dev/null 2>&1
    cd "$ROOT"
    OPENSSL_INC="-I$DEPS/openssl/include"
    OPENSSL_LIB="-L$DEPS/openssl/lib -L$DEPS/openssl/lib64"
    ok "done (deps/openssl/)"
}

if [ -d "$DEPS/openssl" ] && [ -f "$DEPS/openssl/include/openssl/ssl.h" ] && ! $FORCE; then
    OPENSSL_INC="-I$DEPS/openssl/include"
    OPENSSL_LIB="-L$DEPS/openssl/lib -L$DEPS/openssl/lib64"
    ok "found locally compiled: deps/openssl/"
elif find_openssl_system; then
    ok "found system-wide (headers: ${OPENSSL_INC:-default paths})"
    if ask_yn "Compile a local version instead? (recommended for reproducibility)"; then
        compile_openssl
    fi
else
    warn "OpenSSL not found — required for AES-256-GCM encryption"
    if ask_yn "Compile OpenSSL locally? (takes a few minutes)"; then
        compile_openssl
    else
        err "OpenSSL is required — cannot continue without it"
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
    cp http.lua "$LIBS/socket/http.lua"
    cp url.lua "$LIBS/socket/url.lua"
    cp tp.lua "$LIBS/socket/tp.lua"
    cp ftp.lua "$LIBS/socket/ftp.lua"
    cp smtp.lua "$LIBS/socket/smtp.lua"
    cp headers.lua "$LIBS/socket/headers.lua"

    cd "$ROOT"
    ok "done (libs/socket/core.so, libs/mime/core.so)"
}

if [ -f "$LIBS/socket/core.so" ] && ! $FORCE; then
    ok "found in libs/socket/core.so"
else
    install_luasocket
fi

# ============================================================
# 6. rmail_crypto.so (AES-256-GCM + SHA-256)
# ============================================================

echo "Checking for rmail_crypto.so..."

# determine OpenSSL libdir for RPATH
if [ -d "$DEPS/openssl" ]; then
    SSL_RPATH="$DEPS/openssl/lib"
    if [ -d "$DEPS/openssl/lib64" ]; then
        SSL_RPATH="$DEPS/openssl/lib64"
    fi
else
    SSL_RPATH="$(openssl_libdir)"
fi

install_rmail_crypto() {
    info "Compiling rmail_crypto.so..."
    $CC -shared -fPIC -O2 -Wall \
        $LUA_INC $OPENSSL_INC \
        -Wl,-rpath,"$SSL_RPATH" \
        -o "$LIBS/rmail_crypto.so" \
        "$ROOT/rmail_crypto.c" \
        $OPENSSL_LIB -lcrypto
    cd "$ROOT"
    ok "done (libs/rmail_crypto.so)"
}

if [ -f "$LIBS/rmail_crypto.so" ] && ! $FORCE; then
    ok "found in libs/rmail_crypto.so"
else
    install_rmail_crypto
fi

# ============================================================
# 7. NAT traversal tools (optional, for auto_port_forward)
# ============================================================

MINIUPNPC_TAG="miniupnpc_2_3_3"
LIBNATPMP_COMMIT="134fc89e2781e154e40042641f4d8bcbe42579f1"

echo ""
echo "Checking for NAT traversal tools (optional)..."
echo ""
warn "NOTE: UPnP and NAT-PMP are insecure protocols — any device on your LAN"
warn "can open ports on your router without authentication. Installing these"
warn "tools does NOT make your system vulnerable. You would only be at risk if"
warn "you enable auto_port_forward in ~/.config/rmail/config, which is disabled"
warn "by default. Manual port forwarding through your router is recommended."
echo ""

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
        make -s build/upnpc-static CC="$CC"
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
        make -s natpmpc-static CC="$CC" CFLAGS="-Wno-parentheses"
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
# 8. zip / unzip (Info-ZIP, required for attachment transfer)
# ============================================================

echo ""
BIN="$DEPS/bin"
mkdir -p "$BIN"

_compile_zip() {
    echo "Compiling zip ${ZIP_VERSION}..."
    mkdir -p "$BUILD"
    cd "$BUILD"
    ZIP_SRC="zip${ZIP_VERSION//./}"  # "30" for "3.0"
    if [ ! -f "${ZIP_SRC}.tar.gz" ]; then
        curl -fsSL "https://sourceforge.net/projects/infozip/files/Zip%203.x%20(latest)/3.0/${ZIP_SRC}.tar.gz/download" \
            -o "${ZIP_SRC}.tar.gz" || { err "failed to download zip source"; return 1; }
    fi
    tar xf "${ZIP_SRC}.tar.gz"
    cd "${ZIP_SRC}"
    make -f unix/Makefile generic >/dev/null 2>&1 || { err "zip compile failed"; return 1; }
    cp zip "$BIN/zip"
    ok "compiled: deps/bin/zip"
    cd "$ROOT"
}

_compile_unzip() {
    echo "Compiling unzip ${UNZIP_VERSION}..."
    mkdir -p "$BUILD"
    cd "$BUILD"
    UNZIP_SRC="unzip${UNZIP_VERSION//./}"  # "60" for "6.0"
    if [ ! -f "${UNZIP_SRC}.tar.gz" ]; then
        curl -fsSL "https://sourceforge.net/projects/infozip/files/UnZip%206.x%20(latest)/UnZip%206.0/${UNZIP_SRC}.tar.gz/download" \
            -o "${UNZIP_SRC}.tar.gz" || { err "failed to download unzip source"; return 1; }
    fi
    tar xf "${UNZIP_SRC}.tar.gz"
    cd "${UNZIP_SRC}"
    make -f unix/Makefile generic >/dev/null 2>&1 || { err "unzip compile failed"; return 1; }
    cp unzip "$BIN/unzip"
    ok "compiled: deps/bin/unzip"
    cd "$ROOT"
}

ZIP_VERSION="3.0"
UNZIP_VERSION="6.0"

if [ -x "$BIN/zip" ] && [ -x "$BIN/unzip" ] && ! $FORCE; then
    ok "found locally compiled: deps/bin/zip, deps/bin/unzip"
elif command -v zip >/dev/null 2>&1 && command -v unzip >/dev/null 2>&1; then
    ok "found system: zip/unzip"
    if ask_yn "Compile local versions instead? (recommended for reproducibility)"; then
        _compile_zip && _compile_unzip
    fi
else
    warn "zip/unzip not found — required for attachment transfer"
    if ask_yn "Compile Info-ZIP locally? (zip ${ZIP_VERSION} / unzip ${UNZIP_VERSION})"; then
        _compile_zip && _compile_unzip
    else
        err "zip and unzip are required — cannot continue without them"
        exit 1
    fi
fi

# ============================================================
# 9. Security probe (check for insecure NAT protocols)
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

# (config and contacts setup moved to section 1, before dependency checks)
# ============================================================
# Service setup
# ============================================================

echo ""

# find the lua binary that was selected/compiled
LUA_BIN=""
if [ -f "$DEPS/lua/bin/lua" ]; then
    LUA_BIN="$DEPS/lua/bin/lua"
else
    for cmd in lua5.4 luajit lua5.3 lua5.2 lua5.1 lua; do
        if command -v "$cmd" >/dev/null 2>&1; then
            LUA_BIN=$(command -v "$cmd")
            break
        fi
    done
fi

# detect NixOS first — it uses systemd internally but service files
# are overwritten on rebuild, so it needs its own handling
NIXOS=false
[ -f /etc/NIXOS ] && NIXOS=true

# detect init system via PID 1, fall back to tool detection
INIT_SYSTEM="unknown"
if $NIXOS; then
    INIT_SYSTEM="nixos"
elif [ -f /proc/1/comm ]; then
    case "$(cat /proc/1/comm 2>/dev/null)" in
        systemd)     INIT_SYSTEM="systemd" ;;
        runit)       INIT_SYSTEM="runit"   ;;
        openrc-init) INIT_SYSTEM="openrc"  ;;
    esac
fi
if [ "$INIT_SYSTEM" = "unknown" ]; then
    if   command -v systemctl  >/dev/null 2>&1; then INIT_SYSTEM="systemd"
    elif command -v sv         >/dev/null 2>&1; then INIT_SYSTEM="runit"
    elif command -v rc-service >/dev/null 2>&1; then INIT_SYSTEM="openrc"
    fi
fi

if [ "$INIT_SYSTEM" = "unknown" ]; then
    info "Could not detect init system — skipping service setup"
    info "See README.md for service file examples"
elif ask_yn "Set up rmail to run as a service?"; then
    case "$INIT_SYSTEM" in
        nixos)
            NIX_PORT=$(grep '^port' "$CONFIG_FILE" | sed 's/.*=[[:space:]]*//' | tr -d '[:space:]')

            NIX_FILE="$ROOT/rmail.nix"

            # nix store paths change on every update, so if the user chose the
            # system lua (LUA_BIN is under /nix/store/), use the stable
            # pkgs.lua5_4 reference instead of the raw store path.
            # if they compiled local lua, use that literal path directly.
            # NixOS service logs to /tmp (RAM-backed) to avoid disk wear
            if echo "$LUA_BIN" | grep -q '^/nix/store/'; then
                cat > "$NIX_FILE" <<NIX
{ config, pkgs, ... }:
# rmail NixOS service - logs to RAM-backed /tmp

let
  rmailPort = $NIX_PORT;
in {
  networking.firewall.allowedTCPPorts = [ rmailPort ];

  systemd.services.rmail = {
    description = "rmail messaging daemon";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "$(whoami)";
      Group = "users";
      ExecStart = "\${pkgs.lua5_4}/bin/lua $ROOT/rmail.lua $MAIL_DIR";
      Restart = "on-failure";
      RestartSec = 5;
      StandardOutput = "append:/tmp/rmail.log";
      StandardError = "append:/tmp/rmail.log";
    };
  };
}
NIX
            else
                cat > "$NIX_FILE" <<NIX
{ config, ... }:
# rmail NixOS service - logs to RAM-backed /tmp

let
  rmailPort = $NIX_PORT;
in {
  networking.firewall.allowedTCPPorts = [ rmailPort ];

  systemd.services.rmail = {
    description = "rmail messaging daemon";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "$(whoami)";
      Group = "users";
      ExecStart = "$LUA_BIN $ROOT/rmail.lua $MAIL_DIR";
      Restart = "on-failure";
      RestartSec = 5;
      StandardOutput = "append:/tmp/rmail.log";
      StandardError = "append:/tmp/rmail.log";
    };
  };
}
NIX
            fi
            ok "generated $NIX_FILE"
            echo ""
            echo "  Run these commands to install:"
            echo "    sudo cp $NIX_FILE /etc/nixos/rmail.nix"
            echo "    # add this line to /etc/nixos/configuration.nix:"
            echo "    #   imports = [ ./rmail.nix ];"
            echo "    sudo nixos-rebuild switch"
            echo "  Logs: tail -f /tmp/rmail.log"
            echo "  Or use: ./scripts/view-logs.sh"
            ;;
        systemd)
            if ask_yn "Set up as a user service? (no root required, starts on login)"; then
                SERVICE_DIR="$HOME/.config/systemd/user"
                SERVICE_FILE="$SERVICE_DIR/rmail.service"
                mkdir -p "$SERVICE_DIR"
                # systemd user service logs to /tmp (RAM-backed)
                cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=rmail messaging daemon
After=network.target

[Service]
Type=simple
ExecStart=$LUA_BIN $ROOT/rmail.lua $MAIL_DIR
Restart=on-failure
RestartSec=5
StandardOutput=append:/tmp/rmail.log
StandardError=append:/tmp/rmail.log

[Install]
WantedBy=default.target
SERVICE
                ok "created $SERVICE_FILE"
                systemctl --user daemon-reload
                systemctl --user enable rmail
                systemctl --user start rmail
                ok "service enabled and started"
                echo ""
                info "Logs: tail -f /tmp/rmail.log"
                info "Or use: ./scripts/view-logs.sh"
                info "To keep running after logout: loginctl enable-linger"
            else
                SERVICE_FILE="$ROOT/rmail.service"
                # systemd system service logs to /tmp (RAM-backed)
                cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=rmail messaging daemon
After=network.target

[Service]
Type=simple
User=$(whoami)
ExecStart=$LUA_BIN $ROOT/rmail.lua $MAIL_DIR
Restart=on-failure
RestartSec=5
StandardOutput=append:/tmp/rmail.log
StandardError=append:/tmp/rmail.log

[Install]
WantedBy=multi-user.target
SERVICE
                ok "generated $SERVICE_FILE"
                echo ""
                echo "  Run these commands to install the system service:"
                echo "    sudo mv $SERVICE_FILE /etc/systemd/system/rmail.service"
                echo "    sudo systemctl daemon-reload"
                echo "    sudo systemctl enable --now rmail"
                echo "  Logs: tail -f /tmp/rmail.log"
                echo "  Or use: ./scripts/view-logs.sh"
            fi
            ;;
        runit)
            SERVICE_FILE="$ROOT/rmail-run"
            # runit service logs to /tmp (RAM-backed) to avoid disk wear
            # and prevent output from appearing on pre-login TTY
            cat > "$SERVICE_FILE" <<SERVICE
#!/bin/sh
# rmail runit service - redirects logs to RAM-backed /tmp
# Logs don't persist across reboots and don't cause disk wear.
export HOME=$HOME
exec chpst -u $(whoami) $LUA_BIN $ROOT/rmail.lua $MAIL_DIR >>/tmp/rmail.log 2>&1
SERVICE
            chmod +x "$SERVICE_FILE"
            ok "generated $SERVICE_FILE"
            echo ""
            echo "  Run these commands to install the service:"
            echo "    sudo mkdir -p /etc/sv/rmail"
            echo "    sudo mv $SERVICE_FILE /etc/sv/rmail/run"
            echo "    sudo ln -s /etc/sv/rmail /var/service/"
            echo "  Logs: tail -f /tmp/rmail.log"
            echo "  Or use: ./scripts/view-logs.sh"
            ;;
        openrc)
            SERVICE_FILE="$ROOT/rmail-init"
            # openrc service logs to /tmp (RAM-backed) to avoid disk wear
            cat > "$SERVICE_FILE" <<SERVICE
#!/sbin/openrc-run
# rmail openrc service - logs to RAM-backed /tmp

description="rmail messaging daemon"
command="$LUA_BIN"
command_args="$ROOT/rmail.lua $MAIL_DIR"
command_user="$(whoami)"
command_background=true
pidfile="/run/rmail.pid"
output_log="/tmp/rmail.log"
error_log="/tmp/rmail.log"
SERVICE
            ok "generated $SERVICE_FILE"
            echo ""
            echo "  Run these commands to install the service:"
            echo "    sudo mv $SERVICE_FILE /etc/init.d/rmail"
            echo "    sudo chmod +x /etc/init.d/rmail"
            echo "    sudo rc-update add rmail default"
            echo "    sudo rc-service rmail start"
            echo "  Logs: tail -f /tmp/rmail.log"
            echo "  Or use: ./scripts/view-logs.sh"
            ;;
    esac
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
echo "  libs/rmail_crypto.so   — AES-256-GCM encryption"
echo ""
echo "AES-256-GCM encryption is active — no configuration needed."
if $NAT_INSECURE; then
    echo ""
    warn "NOTE: insecure NAT protocols detected on your router (see warnings above)"
fi
