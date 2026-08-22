#!/bin/sh
# install.sh — compile rmail dependencies from source
#
# Usage:
#   ./scripts/install.sh [--force] [--yes | --silent]
#                        [--version <dep>=<x.y.z> ...]
#                        [--<option> <value> | --<flag> | --no-<flag> ...]
#
# Examples:
#   ./scripts/install.sh --version lua=5.3.6
#   ./scripts/install.sh --version luasocket=3.0.0 --version openssl=3.0.0
#   ./scripts/install.sh --force --version lua=5.3.6
#   ./scripts/install.sh --silent --name alice --port 8025 --mail ~/mail
#
# Installs into:
#   libs/    — Lua modules (.lua + .so)
#   deps/    — locally compiled Lua and/or OpenSSL (if needed)
#
# ---------------------------------------------------------------------------
# What this script does, top to bottom:
#
#   PHASE 1 — Configuration (prompts run first, before any compilation)
#     • Ask for mail directory, your name, and the port to listen on.
#     • Write ~/.config/rmail/config-<mail-slug> with those values.
#     • Symlink <mail-dir>/config → the config file for easy access.
#
#   PHASE 2 — Build toolchain
#     • Verify a C compiler exists.
#     • Find or compile Lua (with headers, for building C extensions).
#
#   PHASE 3 — OpenSSL
#     • Used by rmail_crypto.so.  Skipped if libcrypto >= 1.1.1 is
#       already on the system; otherwise compiled into deps/openssl/.
#
#   PHASES 4 / 5 — Pure-Lua and Lua/C libraries
#     • dkjson (pure-Lua JSON parser).
#     • luasocket (C extension — TCP, DNS, MIME).
#
#   PHASE 6 — Rmail-specific C extensions
#     • libs/rmail_crypto.so   AES-256-GCM + SHA-256, linked to OpenSSL.
#     • libs/rmail_inotify.so  Outbox file-change watcher (Linux).
#
#   PHASE 7 — NAT traversal tools (optional)
#     • Compile miniupnpc and libnatpmp for the auto_port_forward config
#       flag.  Probes the user's router and warns if either protocol is
#       reachable — they're known-insecure.
#
#   PHASE 8 — Info-ZIP (zip / unzip)
#     • Required for attachment transfer.  zip and unzip are detected
#       independently; only the missing tool is compiled.
#
#   PHASE 9 — Security probe
#     • Confirm router-side insecure-NAT findings from phase 7 and
#       produce a consolidated end-of-run warning.
#
#   SERVICE SETUP
#     • Detect the init system (systemd, runit, openrc, NixOS) and
#       generate a service unit that launches the daemon pointing at
#       the config file.
#
#   DOCS GENERATION
#     • Expand docs/.templates/*.md with the user's real install paths
#       and write results to docs/.
#
#   SUMMARY
#     • Print the installed files and any next-step instructions.
#
# Every phase is reentrant: re-running the script skips work that's
# already been done (libs present, deps built, config written) unless
# --force is passed.  All interactive prompts can be satisfied from
# command-line flags or env vars (see --silent and --yes above) so the
# script runs unattended under a configuration-management system.
# ---------------------------------------------------------------------------

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

err()   { printf "  \033[31merror: %s\033[0m\n" "$*" >&2; }

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

# ---- Install-time option store --------------------------------------------
#
# Every interactive prompt has a stable "key" (e.g. mail_dir, compile_lua).
# A CLI flag (--mail-dir=PATH, --compile-lua, --no-compile-lua) can preset
# the key and skip the prompt.  --silent refuses to prompt at all; --yes
# answers every boolean prompt as yes unless an explicit --no-<flag>
# overrides.  Values come from CLI only — environment variables are
# intentionally ignored, since stale exports from earlier sessions tend
# to produce surprising installs.  Precedence: CLI > prompt > default.

SILENT=false
ALL_YES=false

# Lookup/store presets via dynamic RMAIL_OPT_<KEY> variable names (POSIX
# sh has no associative arrays).  The internal variables are prefixed
# with __ to avoid clobbering callers' locals — POSIX sh has no real
# lexical scoping, so anything starting with a plain _ might collide
# with ask_value / ask_yn's own bookkeeping.
_get_opt() {
    __opt_k=$(echo "$1" | tr 'a-z' 'A-Z')
    eval "printf '%s' \"\${RMAIL_OPT_${__opt_k}:-}\""
}

_set_opt() {
    __opt_k=$(echo "$1" | tr 'a-z' 'A-Z')
    eval "RMAIL_OPT_${__opt_k}=\"\$2\""
    eval "RMAIL_OPT_${__opt_k}_SET=1"
}

_has_opt() {
    __opt_k=$(echo "$1" | tr 'a-z' 'A-Z')
    eval "[ \"\${RMAIL_OPT_${__opt_k}_SET:-0}\" = 1 ]"
}

_parse_bool() {
    # _parse_bool STR — returns 0 for yes/true/1, 1 for no/false/0.  Exits
    # on anything else so a mistyped "--compile-lua=maybe" is caught early.
    case "$1" in
        [Yy]|[Yy][Ee][Ss]|[Tt]|[Tt][Rr][Uu][Ee]|1) return 0 ;;
        [Nn]|[Nn][Oo]|[Ff]|[Ff][Aa][Ll][Ss][Ee]|0) return 1 ;;
        *) err "invalid boolean value: '$1' (use yes/no/true/false/1/0)"; exit 1 ;;
    esac
}

# Option keys the installer recognises.  Value keys need a string, yn keys
# take a boolean.  Used by show_help and the CLI parser.
OPT_VALUE_KEYS="mail_dir name port"
OPT_YN_KEYS="compile_lua compile_openssl compile_luasocket compile_upnp compile_natpmp compile_zip setup_service user_service"

show_help() {
    cat <<'HELP'
Usage: install.sh [options]

Generic:
  -h, --help              Show this help and exit
  --force                 Force recompile of all locally-built dependencies
  --silent                Fail instead of prompting.  Every required value
                          must be supplied via a CLI flag.
  --yes, -y               Answer yes to every boolean prompt unless the
                          matching --no-<flag> is also given
  --version dep=x.y.z     Pin a dependency version (lua, luasocket, openssl,
                          dkjson).  Can be repeated.

Required values (supplying --flag skips the matching prompt):
  --mail-dir=PATH         Mailbox directory
  --name=STR              Local identity (used only on this machine)
  --port=NUM              TCP port the daemon listens on

Boolean prompts (--flag = yes, --no-flag = no, --flag=yes|no|1|0 also work):
  --compile-lua           Compile a project-local Lua
  --compile-openssl       Compile a project-local OpenSSL
  --compile-luasocket     Compile a project-local luasocket
  --compile-upnp          Compile miniupnpc (UPnP port forwarding)
  --compile-natpmp        Compile libnatpmp (NAT-PMP port forwarding)
  --compile-zip           Compile Info-ZIP zip and unzip
  --setup-service         Set up rmail to start automatically
  --user-service          When setting up a service, use a user-level one
                          (no root required)

Fully unattended example:
  scripts/install.sh --silent --yes \
      --mail-dir=/srv/rmail/alice --name=alice --port=54321

Values are only read from CLI flags.  Environment variables are
intentionally ignored — a stale RMAIL_* export from an earlier session
shouldn't silently change what the installer does.
HELP
}

# Extract "key" and "value" from a --key=value or --key-with-dashes flag.
# Populates _cli_key (underscore form) and _cli_val.  For --no-* flags,
# _cli_val is "no" and _cli_key strips the "no-" prefix.
_parse_flag() {
    case "$1" in
        --no-*=*)
            err "$1: cannot combine --no- with =value"; exit 1 ;;
        --no-*)
            _cli_key=$(echo "${1#--no-}" | tr '-' '_')
            _cli_val="no"
            _cli_takes_next=0
            ;;
        *=*)
            _cli_key=$(echo "${1%%=*}" | sed 's|^--||' | tr '-' '_')
            _cli_val="${1#*=}"
            _cli_takes_next=0
            ;;
        *)
            _cli_key=$(echo "${1#--}" | tr '-' '_')
            _cli_val=""
            _cli_takes_next=1
            ;;
    esac
}

# parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help; exit 0
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --silent)
            SILENT=true
            shift
            ;;
        -y|--yes)
            ALL_YES=true
            shift
            ;;
        --version)
            if [ -z "${2:-}" ]; then
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
        --*)
            # Any other long flag is an option-store setter.
            _parse_flag "$1"
            case " $OPT_VALUE_KEYS " in
                *" $_cli_key "*)
                    # Value key: if the flag had no =value, take $2.
                    if [ "$_cli_takes_next" = 1 ]; then
                        if [ -z "${2:-}" ]; then err "$1 requires a value"; exit 1; fi
                        _cli_val="$2"
                        _set_opt "$_cli_key" "$_cli_val"
                        shift 2
                    else
                        _set_opt "$_cli_key" "$_cli_val"
                        shift
                    fi
                    ;;
                *)
                    case " $OPT_YN_KEYS " in
                        *" $_cli_key "*)
                            # Bare --flag implies yes; --no-flag already sets "no".
                            if [ "$_cli_takes_next" = 1 ] && [ -z "$_cli_val" ]; then
                                _cli_val="yes"
                            fi
                            _set_opt "$_cli_key" "$_cli_val"
                            shift
                            ;;
                        *)
                            err "unknown argument: $1"
                            err "run 'install.sh --help' to see available flags"
                            exit 1
                            ;;
                    esac
                    ;;
            esac
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

# Read a line with readline editing (arrow keys, backspace, history) when
# the interpreter supports it.  Bash sets BASH_VERSION even when invoked as
# /bin/sh, which makes this a reliable runtime check; dash and other POSIX
# shells leave it unset and we fall back to plain read.
_prompt_read() {
    # _prompt_read VARNAME < tty
    if [ -n "${BASH_VERSION:-}" ]; then
        # shellcheck disable=SC3045  # read -e is bash-only, guarded above
        read -e -r "$1"
    else
        read -r "$1"
    fi
}

ask_yn() {
    # ask_yn KEY "prompt" — returns 0 for yes, 1 for no
    # If RMAIL_OPT_<KEY> is preset (from CLI/env), the prompt is skipped.
    # In --yes mode, unset keys default to yes.  In --silent mode, unset
    # keys error out instead of prompting.
    _k="$1"; shift
    _prompt="$1"
    if _has_opt "$_k"; then
        _parse_bool "$(_get_opt "$_k")"
        return
    fi
    if $ALL_YES; then return 0; fi
    if $SILENT; then
        _flag=$(echo "$_k" | tr '_' '-')
        err "--silent: $_k not set"
        err "  supply --$_flag or --no-$_flag"
        exit 1
    fi
    printf "  %s [y/N] " "$_prompt"
    _prompt_read ans
    case "$ans" in
        [Yy]*) return 0 ;;
        *) return 1 ;;
    esac
}

ask_value() {
    # ask_value KEY "prompt" "default"
    # If RMAIL_OPT_<KEY> is preset, the prompt is skipped and the preset
    # echoed.  In --silent mode, an unset key errors out.  Otherwise the
    # prompt is shown with default in [brackets]; pressing enter accepts
    # the default.  Prompt goes to /dev/tty so it's visible even when
    # stdout is captured via $(...).
    _k="$1"; shift
    _prompt="$1"; _default="$2"
    if _has_opt "$_k"; then
        _get_opt "$_k"
        return
    fi
    if $SILENT; then
        _flag=$(echo "$_k" | tr '_' '-')
        err "--silent: $_k not set"
        err "  supply --$_flag=VALUE"
        exit 1
    fi
    printf "  %s [%s]: " "$_prompt" "$_default" >/dev/tty
    _prompt_read _val </dev/tty
    if [ -z "$_val" ]; then
        echo "$_default"
    else
        echo "$_val"
    fi
}

read_config_value() {
    # read_config_value FILE KEY — returns current value or ""
    grep "^${2}[[:space:]]*=" "$1" 2>/dev/null | sed 's/^[^=]*=[[:space:]]*//' | head -1
}

sed_escape_replacement() {
    # Escape a value for safe use as the replacement side of `sed s|...|VAL|`
    # — doubles backslashes, escapes | and &.  Without this, a path
    # containing any of those characters either breaks the sed command or
    # gets interpreted (backref `&` becomes the matched text; `\n`
    # becomes a newline).  See #344.
    printf '%s' "$1" | sed 's/[\\|&]/\\&/g'
}

set_config_value() {
    # set_config_value FILE KEY VALUE
    # Replaces the line "KEY = ..." in FILE with "KEY = VALUE", or appends
    # it if no such line exists. Done via awk so arbitrary characters in
    # VALUE (slashes, pipes, ampersands, backslashes) never trip a sed
    # escape hazard — paths go through verbatim.
    _file="$1"; _key="$2"; _val="$3"
    if [ ! -f "$_file" ]; then
        printf '%s = %s\n' "$_key" "$_val" >> "$_file"
        return
    fi
    _tmp=$(mktemp)
    awk -v key="$_key" -v val="$_val" '
        BEGIN { done = 0 }
        {
            if (!done && match($0, "^[[:space:]]*" key "[[:space:]]*=") > 0) {
                printf "%s = %s\n", key, val
                done = 1
            } else {
                print
            }
        }
        END { if (!done) printf "%s = %s\n", key, val }
    ' "$_file" > "$_tmp" && mv "$_tmp" "$_file"
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

# save_notice NAME SOURCE_DIR [EXTRA_RELATIVE_PATH ...]
#
# Copies a dependency's copyright/licence files out of the source tree we
# just compiled, into deps/licenses/NAME/, so the notices stay next to the
# binaries built from them.
#
# Why this exists: this script compiles eight third-party projects from
# source into deps/ and libs/ — the Lua interpreter, OpenSSL, LuaSocket,
# the two port-forwarding helpers, and Info-ZIP's zip and unzip.  Every one
# of those carries a licence clause requiring that a *binary* redistribution
# reproduce the upstream copyright notice.  The git repository itself never
# ships those binaries (deps/ and libs/* are ignored), so the obligation
# looks dormant — but scripts/make-mailbox-drive.sh rsyncs a fully built
# tree, deps/ and all, onto a USB drive meant to be handed to another
# person.  That is a binary redistribution, and without this step it would
# leave without the notices.
#
# Harvested at build time rather than kept as a checked-in NOTICES file on
# purpose: a hand-written copy goes stale the moment a pinned version moves,
# and a stale licence notice is worse than none because it looks authoritative.
# Whatever upstream actually shipped in the tarball we actually built is what
# gets stored.
#
# The search covers the usual upstream spellings two directories deep, since
# some projects keep their terms in a subdirectory rather than at the root.
# Projects that hide their licence somewhere unguessable get their paths
# passed in explicitly — Lua is the one that needs this, as it states its
# terms in the manual and in the public header instead of a standalone file.
save_notice() {
    notice_name="$1"
    notice_src="$2"
    shift 2

    # Refuse to build a destination path out of an empty name, which would
    # otherwise aim the clearing step below at deps/licenses/ as a whole.
    if [ -z "$notice_name" ] || [ -z "$notice_src" ]; then
        err "save_notice called without a name and a source directory"
        return 1
    fi

    notice_dest="$DEPS/licenses/$notice_name"

    if [ ! -d "$notice_src" ]; then
        warn "cannot keep licence for $notice_name: no source tree at $notice_src"
        warn "a binary would ship without its copyright notice — see LICENSE"
        return 1
    fi

    # Start from empty every time.  --force rebuilds against whatever version
    # is pinned today, and a notice left over from the version pinned last
    # month would both misdescribe the shipped binary and, worse, be counted
    # as a success below — hiding the case where the new source tree has no
    # notice at all.  Stale attribution is the failure this whole routine
    # exists to prevent, so it must not be able to survive a rebuild.
    rm -rf "$notice_dest"
    mkdir -p "$notice_dest"

    # Collect first, copy second, so the list is inspectable if this misbehaves
    # and so the loop body doesn't run in a subshell where counts would vanish.
    notice_list="$BUILD/.notice-paths"
    find "$notice_src" -maxdepth 2 -type f \
        \( -iname 'LICENSE'   -o -iname 'LICENSE.*'   \
        -o -iname 'LICENCE'   -o -iname 'LICENCE.*'   \
        -o -iname 'COPYING'   -o -iname 'COPYING.*'   \
        -o -iname 'COPYRIGHT' -o -iname 'COPYRIGHT.*' \
        -o -iname 'NOTICE'    -o -iname 'NOTICE.*'    \) > "$notice_list"

    while IFS= read -r notice_file; do
        cp "$notice_file" "$notice_dest/"
    done < "$notice_list"

    for notice_extra in "$@"; do
        if [ -f "$notice_src/$notice_extra" ]; then
            cp "$notice_src/$notice_extra" "$notice_dest/"
        fi
    done

    rm -f "$notice_list"

    notice_count=$(find "$notice_dest" -type f | wc -l)

    # Zero found is a real problem, not a cosmetic one: it means we are about
    # to ship a binary bare.  Say so loudly with the path to look in, rather
    # than failing silently or aborting somebody's install over a text file.
    if [ "$notice_count" -eq 0 ]; then
        # Leave nothing behind: an empty deps/licenses/<name>/ directory reads
        # as "checked, nothing required" to anyone auditing the tree later.
        rmdir "$notice_dest"
        warn "no licence file found in the $notice_name source tree"
        warn "  looked in: $notice_src"
        warn "  a binary built from it would ship without its copyright notice"
        warn "  fix: find the notice in that tree and name it in the"
        warn "       save_notice call for $notice_name in this script"
        return 1
    fi

    ok "kept $notice_count licence file(s) for $notice_name (deps/licenses/$notice_name/)"
}

# ============================================================
# PHASE 1 — Configuration (interactive prompts; run before compilation)
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

# Mail directory default — prefer a stored value from an existing config,
# fall back to ~/mail.  This makes re-running install.sh show the current
# mailbox path in the [brackets] instead of resetting to the default.
DEFAULT_MAIL="${HOME}/mail"
if [ -n "$EXISTING_CONFIG" ]; then
    _existing_mail=$(read_config_value "$EXISTING_CONFIG" "mail")
    [ -n "${_existing_mail:-}" ] && DEFAULT_MAIL="$_existing_mail"
fi

RMAIL_MAIL=$(ask_value mail_dir "Mail directory" "$DEFAULT_MAIL") || exit 1
RMAIL_MAIL=$(echo "$RMAIL_MAIL" | sed "s|^~|$HOME|")
RMAIL_MAIL=$(echo "$RMAIL_MAIL" | sed 's|/*$||')  # strip trailing slashes
MAIL_DIR="$RMAIL_MAIL"

# Derive config filename from mail path: /home/ritz/mail -> config-home-ritz-mail.
# The dash-separated slug is intentional: one config file per mailbox, all
# parked under ~/.config/rmail/, distinguishable by the original path
# reflected in the filename.  (Re #344: slashes-to-dashes is this slug, not
# a path-mangling bug in the config content.)
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
    RMAIL_NAME=$(ask_value name "Your own name (used locally, not transmitted)" "$DEFAULT_NAME") || exit 1
    if echo "$RMAIL_NAME" | grep -qE '^[a-zA-Z0-9_-]+$'; then
        break
    fi
    warn "Name must contain only letters, numbers, hyphens, and underscores."
done

# prompt for port
while true; do
    RMAIL_PORT=$(ask_value port "Port to listen on" "$DEFAULT_PORT") || exit 1
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

# your own name — used locally so the daemon can tell "me" from "everyone else"
# in your contacts file.  Never transmitted; each contact sees you by whatever
# name they assigned you in their own contacts file.
name = $RMAIL_NAME

# port rmail listens on for incoming messages
port = $RMAIL_PORT

# mailbox directory — where inbox/, outbox/, contacts, and .state/ live.
# The daemon is currently launched with this path as a command-line
# argument (see the service file); this field records it so install.sh
# can pre-fill the prompt on re-run and so external tools have a single
# source of truth.
mail = $MAIL_DIR

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
# Hooks run a script in response to message events.  Each one points at
# a default orchestrator in scripts/hooks/ that passes data through
# unchanged (no-op).  Edit the script — or replace the path with any
# executable of your own — to customise behaviour.
#
# Argument reference and worked examples:
#   $ROOT/docs/scripting-tutorial.md
#
# To disable a hook entirely, set its value to the empty string:
#   on_receive = ""

on_receive_raw = $ROOT/scripts/hooks/on_receive_raw.sh
on_receive     = $ROOT/scripts/hooks/on_receive.sh
on_package     = $ROOT/scripts/hooks/on_package.sh
on_send        = $ROOT/scripts/hooks/on_send.sh
on_delete      = $ROOT/scripts/hooks/on_delete.sh
on_update      = $ROOT/scripts/hooks/on_update.sh
CONFIG
    ok "created config: $CONFIG_FILE"
else
    set_config_value "$CONFIG_FILE" "name" "$RMAIL_NAME"
    set_config_value "$CONFIG_FILE" "port" "$RMAIL_PORT"
    set_config_value "$CONFIG_FILE" "mail" "$MAIL_DIR"
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

# Firewall primer — shown once after port info so users unfamiliar with
# firewall config know what to expect and how to inspect their system.
cat <<FIREWALL
  About firewalls:
    A "port" is a numbered channel on your machine.  Each running network
    service claims one.  rmail needs port $RMAIL_PORT open so contacts can
    reach your daemon.  Without opening it, outbound sends still work but
    no one can deliver messages to you.

    To check what's currently listening or blocked, try one of:
      ss -tlnp                    # what's listening (most Linuxes)
      sudo iptables -L            # classic firewall rules
      sudo nft list ruleset       # modern nftables
      ufw status                  # Ubuntu / simple firewall
      firewall-cmd --list-all     # Fedora / firewalld
      pfctl -s rules              # macOS / BSD

    Whichever tool your system uses, you're looking for an "allow" rule
    on TCP port $RMAIL_PORT — from anywhere (0.0.0.0/0 or ::/0) if you want
    contacts on the public internet to reach you.

FIREWALL

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
# PHASE 2a — C compiler (required for every build below)
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
# PHASE 2b — Lua interpreter + headers (used by phases 5 and 6)
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

    # Promote discovery results to globals so later stages (luasocket check,
    # service-file generation) can reuse them.
    LUA_BIN="$lua_bin"
    # Extract just "<name> <version>" from the first line of `lua -v`, which
    # looks like "Lua 5.4.7  Copyright..." or "LuaJIT 2.1.0-beta3 -- Copyright..."
    # Anything after the copyright blurb is noise for install output.
    LUA_VER_STR=$(echo "$lua_ver" | awk 'NR==1 {print $1, $2}')

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
LUA_BIN=""

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
    # Lua ships no standalone LICENSE file — its terms live in the manual
    # and repeated at the foot of the public header, so both are named.
    save_notice lua "$BUILD/lua-$LUA_VERSION" doc/readme.html src/lua.h
    cd "$ROOT"
    LUA_INC="-I$DEPS/lua/include"
    LUA_LIB="-L$DEPS/lua/lib"
    LUA_BIN="$DEPS/lua/bin/lua"
    ok "done (deps/lua/)"
}

if [ -d "$DEPS/lua" ] && [ -f "$DEPS/lua/include/lua.h" ] && ! $FORCE; then
    LUA_INC="-I$DEPS/lua/include"
    LUA_LIB="-L$DEPS/lua/lib"
    LUA_BIN="$DEPS/lua/bin/lua"
    local_ver=$("$LUA_BIN" -v 2>&1 | awk 'NR==1 {print $1, $2}')
    ok "found locally compiled: deps/lua/ ($local_ver)"
elif find_lua_system; then
    ok "found system: $LUA_VER_STR"
    if ask_yn compile_lua "Compile a local version instead?"; then
        compile_lua
    fi
else
    if ask_yn compile_lua "Lua not found in PATH. Compile locally?"; then
        compile_lua
    else
        err "Lua is required — cannot continue without it"
        exit 1
    fi
fi

# ============================================================
# PHASE 3 — OpenSSL (used by rmail_crypto.so; skipped if already present)
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
    save_notice openssl "$BUILD/openssl-$OPENSSL_VERSION"
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
    if ask_yn compile_openssl "Compile a local version instead?"; then
        compile_openssl
    fi
else
    warn "OpenSSL not found — required for AES-256-GCM encryption"
    if ask_yn compile_openssl "Compile OpenSSL locally? (takes a few minutes)"; then
        compile_openssl
    else
        err "OpenSSL is required — cannot continue without it"
        exit 1
    fi
fi

# ============================================================
# PHASE 4 — dkjson (pure-Lua JSON library, no C)
# ============================================================

echo "Checking for dkjson..."

if [ -f "$LIBS/dkjson.lua" ] && ! $FORCE; then
    ok "found in libs/dkjson.lua"
else
    if $FORCE || [ ! -f "$LIBS/dkjson.lua" ]; then
        info "Downloading dkjson..."
        mkdir -p "$LIBS"
        download "http://dkolf.de/dkjson-lua/dkjson-$DKJSON_VERSION.lua" "$LIBS/dkjson.lua"
        # No save_notice call here on purpose: dkjson is a single source file
        # that carries its own copyright and permission notice in a comment
        # block at the top, and we ship that file verbatim.  The notice
        # already travels with the thing it covers.
        ok "done (libs/dkjson.lua)"
    fi
fi

# ============================================================
# PHASE 5 — luasocket (C extension: TCP, DNS, MIME)
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

    save_notice luasocket "$BUILD/luasocket-$LUASOCKET_VERSION"

    cd "$ROOT"
    ok "done (libs/socket/core.so, libs/mime/core.so)"
}

# Does the chosen Lua interpreter already have luasocket available — either
# from a system install or from a previous project-local build whose libs/
# directory is already on its cpath?  Trust the interpreter's own answer
# rather than probing filesystem paths.
_have_luasocket() {
    [ -n "$LUA_BIN" ] && \
        "$LUA_BIN" -e 'require("socket.core"); require("mime.core")' 2>/dev/null
}

if [ -f "$LIBS/socket/core.so" ] && ! $FORCE; then
    ok "found in libs/socket/core.so"
elif $FORCE; then
    install_luasocket
elif _have_luasocket; then
    # System (or otherwise-discoverable) luasocket works for this Lua.
    # Offer a project-local install but don't force it.
    ok "found: $LUA_BIN can require('socket') and require('mime')"
    if ask_yn compile_luasocket "Install a project-local copy into libs/ anyway?"; then
        install_luasocket
    else
        info "using system luasocket — rmail adds libs/ to cpath at startup"
        info "so a project-local copy will still take precedence if present"
    fi
else
    warn "luasocket not found — required for network operations"
    if ask_yn compile_luasocket "Compile project-local luasocket from source?"; then
        install_luasocket
    else
        err "luasocket is required — cannot continue without it"
        exit 1
    fi
fi

# ============================================================
# PHASE 6a — rmail_crypto.so  (AES-256-GCM + SHA-256, linked to OpenSSL)
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
# PHASE 6b — rmail_inotify.so  (outbox file-change watcher, Linux)
# ============================================================

echo ""
echo "Checking for rmail_inotify.so..."

install_rmail_inotify() {
    info "Compiling rmail_inotify.so..."
    $CC -shared -fPIC -O2 -Wall \
        $LUA_INC \
        -o "$LIBS/rmail_inotify.so" \
        "$ROOT/rmail_inotify.c"
    cd "$ROOT"
    ok "done (libs/rmail_inotify.so)"
}

if [ -f "$LIBS/rmail_inotify.so" ] && ! $FORCE; then
    ok "found in libs/rmail_inotify.so"
else
    install_rmail_inotify
fi

# ============================================================
# PHASE 7 — NAT traversal tools (optional, for the auto_port_forward flag)
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
    if ask_yn compile_upnp "Compile miniupnpc locally? (small, no extra dependencies)"; then
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
        save_notice miniupnpc "$BUILD/miniupnp-$MINIUPNPC_TAG/miniupnpc"
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
    if ask_yn compile_natpmp "Compile libnatpmp locally? (small, no extra dependencies)"; then
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
        save_notice libnatpmp "$BUILD/libnatpmp-$LIBNATPMP_COMMIT"
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
# PHASE 8 — Info-ZIP: zip + unzip  (required for attachment transfer)
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
    save_notice zip "$BUILD/${ZIP_SRC}"
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
    save_notice unzip "$BUILD/${UNZIP_SRC}"
    ok "compiled: deps/bin/unzip"
    cd "$ROOT"
}

ZIP_VERSION="3.0"
UNZIP_VERSION="6.0"

# zip and unzip ship as separate packages on most distros; detect them
# independently so a user who has one but not the other doesn't get asked
# to compile both.
_have_zip()   { [ -x "$BIN/zip" ]   || command -v zip   >/dev/null 2>&1; }
_have_unzip() { [ -x "$BIN/unzip" ] || command -v unzip >/dev/null 2>&1; }

if $FORCE; then
    # --force: always use project-local compiled versions
    _compile_zip && _compile_unzip || exit 1
elif ! _have_zip || ! _have_unzip; then
    # at least one is missing: list missing tools, offer to compile only those
    missing=""
    _have_zip   || missing="$missing zip"
    _have_unzip || missing="$missing unzip"
    warn "missing for attachment transfer:$missing"
    if ask_yn compile_zip "Compile missing tool(s) locally from Info-ZIP source?"; then
        _have_zip   || _compile_zip   || exit 1
        _have_unzip || _compile_unzip || exit 1
    else
        err "zip and unzip are both required — cannot continue without them"
        exit 1
    fi
elif [ -x "$BIN/zip" ] && [ -x "$BIN/unzip" ]; then
    ok "found locally compiled: deps/bin/zip, deps/bin/unzip"
else
    ok "found system: zip/unzip"
    if ask_yn compile_zip "Compile local versions instead?"; then
        _compile_zip && _compile_unzip
    fi
fi

# ============================================================
# PHASE 9 — Security probe (consolidate and report insecure NAT findings)
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
# CLEAN UP — remove temporary build artefacts
# ============================================================

if [ -d "$BUILD" ]; then
    info "Cleaning up build files..."
    rm -rf "$BUILD"
fi

# (config and contacts setup moved to section 1, before dependency checks)
# ============================================================
# SERVICE SETUP — generate the init unit for this system (systemd, runit, …)
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
elif ask_yn setup_service "Set up rmail to run as a service?"; then
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
      ExecStart = "\${pkgs.lua5_4}/bin/lua $ROOT/rmail.lua $CONFIG_FILE";
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
      ExecStart = "$LUA_BIN $ROOT/rmail.lua $CONFIG_FILE";
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
            if ask_yn user_service "Set up as a user service? (no root required, starts on login)"; then
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
ExecStart=$LUA_BIN $ROOT/rmail.lua $CONFIG_FILE
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
ExecStart=$LUA_BIN $ROOT/rmail.lua $CONFIG_FILE
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
exec chpst -u $(whoami) $LUA_BIN $ROOT/rmail.lua $CONFIG_FILE >>/tmp/rmail.log 2>&1
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
command_args="$ROOT/rmail.lua $CONFIG_FILE"
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
# DOCS GENERATION — expand docs/.templates/*.md with real install paths
# ============================================================
# docs/.templates/ holds the source-of-truth .md files with placeholder
# paths.  Here we substitute real install paths and write the resulting
# files to docs/ alongside the signpost (which is the one tracked file in
# docs/ — everything else is a generated artefact).  See
# issues/350-docs-templates-and-install-time-generation.md.

generate_docs() {
    local templates_dir="$ROOT/docs/.templates"
    local out_dir="$ROOT/docs"

    [ -d "$templates_dir" ] || return 0

    # Lua shebang target: bundled interpreter if it exists, system lua otherwise
    local lua_shebang
    if [ -x "$ROOT/deps/lua/bin/lua" ]; then
        lua_shebang="$ROOT/deps/lua/bin/lua"
    else
        lua_shebang="/usr/bin/env lua"
    fi

    # Escape replacement values so paths containing `|`, `\`, or `&` don't
    # break the sed command or get interpreted as backreferences.  See #344.
    local esc_shebang esc_root esc_cfg esc_mail
    esc_shebang=$(sed_escape_replacement "$lua_shebang")
    esc_root=$(sed_escape_replacement "$ROOT")
    esc_cfg=$(sed_escape_replacement "$CONFIG_DIR")
    esc_mail=$(sed_escape_replacement "$MAIL_DIR")

    for tmpl in "$templates_dir"/*.md; do
        [ -f "$tmpl" ] || continue
        local name
        name=$(basename "$tmpl")
        sed \
            -e "s|/home/you/programs/email/deps/lua/bin/lua|$esc_shebang|g" \
            -e "s|/home/you/programs/email|$esc_root|g" \
            -e "s|/home/you/.config/rmail|$esc_cfg|g" \
            -e "s|/home/you/mail|$esc_mail|g" \
            "$tmpl" > "$out_dir/$name"
    done

    # looking-for-docs.md deliberately stays in place.  It's the only
    # git-tracked file in docs/; everything else here is a generated
    # artefact.  Leaving it keeps `git status` clean after install.
}

generate_docs
ok "generated docs/ from docs/.templates/"

# ============================================================
# SUMMARY — print installed files, warnings, and next-step instructions
# ============================================================

echo ""
echo "All dependencies installed."
echo ""
echo "  libs/dkjson.lua        — JSON library"
echo "  libs/socket/core.so    — luasocket"
echo "  libs/mime/core.so      — luasocket mime"
echo "  libs/rmail_crypto.so   — AES-256-GCM encryption"
echo "  libs/rmail_inotify.so  — outbox file-change watcher"
if $NAT_INSECURE; then
    echo ""
    warn "NOTE: insecure NAT protocols detected on your router (see warnings above)"
fi
