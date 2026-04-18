#!/bin/sh
# make-mailbox-drive.sh — populate a USB drive with a running rmail mailbox.
#
# Implements issue #339.  The resulting drive is itself a runnable rmail
# node: plug it into any Linux host whose router forwards the configured
# port, run ./run.sh from the drive, and the mailbox is live.  Unplug and
# move the drive to another host and do the same — same mailbox, same
# contacts, same history.
#
# Drive layout:
#
#   /run.sh            # starts rmail with this drive's mailbox/config
#   /README.md         # plug-and-run instructions + router-port reminder
#   /source-code/      # full rmail source (same as #361, plus libs/)
#   /mailbox-0/
#       config         # real file (not a symlink — mount point differs per host)
#       inbox/
#       outbox/
#       attachments/
#       .state/
#       contacts       # starts empty
#
# Libs are copied from the source tree's libs/ directory, so the dev
# machine must have run scripts/install.sh at least once before this
# generator is useful.  If the host the drive is later plugged into has
# a different glibc/arch, run.sh will detect the mismatch and rebuild
# into libs/ on first launch (see "Rebuild on host mismatch" below).
#
# Usage:
#   scripts/make-mailbox-drive.sh --name NAME --port PORT \
#                                 [--dest PATH] [--mailbox NAME] [--dry-run]

set -e

# ---------------------------------------------------------------------------
FLASH_LABEL="RMAIL"

# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

. "$SCRIPT_DIR/lib/drive-common.sh"

DRY_RUN=false
DEST=""
NAME=""
PORT=""
MAILBOX_NAME="mailbox-0"
FORCE=false

show_help() {
    cat <<'HELP'
Usage: make-mailbox-drive.sh --name NAME --port PORT [options]

Required:
  --name NAME        Local identity (used so the daemon can tell "me" from
                     "everyone else" in the contacts file).  Never
                     transmitted.
  --port NUM         TCP port the daemon listens on.  Pick one the host's
                     router will forward to whatever machine the drive is
                     currently plugged into.

Options:
  -h, --help         Show this help and exit
  --dest PATH        Write to PATH instead of auto-detecting a flash drive
  --mailbox NAME     Name for the mailbox directory (default: mailbox-0)
  --dry-run          Print what would happen; don't modify anything
  --force            Overwrite an existing mailbox on the drive.  By
                     default, refuses if the mailbox directory already
                     exists — you almost never want to clobber real mail.

Auto-detection looks for a mounted filesystem whose mount-point basename
matches FLASH_LABEL (currently "RMAIL").  If zero or multiple drives
match, --dest is required.

The source tree's libs/ directory must exist (run scripts/install.sh
once locally before using this generator).  Libs are copied onto the
drive so the mailbox works out of the box; if the target host has an
incompatible glibc/arch, run.sh will rebuild on first launch.
HELP
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) show_help; exit 0 ;;
        --dest)
            [ -z "${2:-}" ] && { err "--dest requires a path"; exit 1; }
            DEST="$2"; shift 2 ;;
        --dest=*) DEST="${1#*=}"; shift ;;
        --name)
            [ -z "${2:-}" ] && { err "--name requires a value"; exit 1; }
            NAME="$2"; shift 2 ;;
        --name=*) NAME="${1#*=}"; shift ;;
        --port)
            [ -z "${2:-}" ] && { err "--port requires a value"; exit 1; }
            PORT="$2"; shift 2 ;;
        --port=*) PORT="${1#*=}"; shift ;;
        --mailbox)
            [ -z "${2:-}" ] && { err "--mailbox requires a value"; exit 1; }
            MAILBOX_NAME="$2"; shift 2 ;;
        --mailbox=*) MAILBOX_NAME="${1#*=}"; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        --force) FORCE=true; shift ;;
        *) err "unknown argument: $1"; show_help >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate inputs.

if [ -z "$NAME" ]; then
    err "--name is required"
    show_help >&2
    exit 1
fi
if ! echo "$NAME" | grep -qE '^[a-zA-Z0-9_-]+$'; then
    err "--name must contain only letters, numbers, hyphens, and underscores"
    exit 1
fi

if [ -z "$PORT" ]; then
    err "--port is required"
    show_help >&2
    exit 1
fi
if ! echo "$PORT" | grep -qE '^[0-9]+$' || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    err "--port must be an integer in 1..65535"
    exit 1
fi

case "$MAILBOX_NAME" in
    */*|"."|".."|"")
        err "--mailbox must be a simple directory name, got: $MAILBOX_NAME"
        exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Resolve destination.

if [ -z "$DEST" ]; then
    DEST=$(drive_detect)
    ok "detected flash drive: $DEST"
else
    info "using explicit destination: $DEST"
fi

if ! $DRY_RUN; then
    drive_confirm_writable "$DEST"
fi

_root_real=$(cd "$ROOT" && pwd -P)
_dest_real=$(cd "$DEST" 2>/dev/null && pwd -P || echo "$DEST")
case "$_dest_real" in
    "$_root_real"|"$_root_real"/*)
        err "destination is inside the source tree: $DEST"
        exit 1 ;;
esac

MAILBOX_DIR="$DEST/$MAILBOX_NAME"

if [ -d "$MAILBOX_DIR" ] && ! $FORCE; then
    err "mailbox already exists on drive: $MAILBOX_DIR"
    err "  pass --force to overwrite (you will lose any mail stored on the drive)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify libs are present in the source tree.  Without them the drive won't
# actually run — the generator's one hard prerequisite.

if [ ! -d "$ROOT/libs" ] || [ -z "$(ls -A "$ROOT/libs" 2>/dev/null)" ]; then
    err "no built libs found in $ROOT/libs"
    err "  run scripts/install.sh locally first to compile them,"
    err "  then re-run this script."
    exit 1
fi

# ---------------------------------------------------------------------------
# rsync source (including libs/ this time — the drive needs a working rmail).

info "populating $DEST/source-code/ from $ROOT"

RSYNC_FLAGS="-a --delete --human-readable"
if $DRY_RUN; then
    RSYNC_FLAGS="$RSYNC_FLAGS --dry-run --itemize-changes"
fi

RSYNC_EXCLUDES="
--exclude=.git/
--exclude=.gitignore
--exclude=.build-tmp/
--exclude=.logs/
--exclude=.claude/
--exclude=.vscode/
--exclude=.idea/
--exclude=.DS_Store
--exclude=*.swp
--exclude=*.swo
--exclude=__pycache__/
--exclude=mailbox-*/
--exclude=**/build/
--exclude=.gradle/
--exclude=*.apk
--exclude=*.aab
"

mkdir -p "$DEST/source-code"
# shellcheck disable=SC2086
rsync $RSYNC_FLAGS $RSYNC_EXCLUDES "$ROOT/" "$DEST/source-code/"

if $DRY_RUN; then
    ok "dry run complete — nothing written."
    exit 0
fi

# ---------------------------------------------------------------------------
# Create mailbox directory tree.

info "creating mailbox at $MAILBOX_DIR"
mkdir -p "$MAILBOX_DIR/inbox" "$MAILBOX_DIR/outbox" "$MAILBOX_DIR/attachments" "$MAILBOX_DIR/.state" "$MAILBOX_DIR/scripts"
: > "$MAILBOX_DIR/contacts"    # empty contacts file

# Copy the default hook scripts into the mailbox's own scripts/ dir.
# Config references them as ./scripts/<name>.sh (relative paths).  run.sh
# does `cd "$MAILBOX_DIR"` before exec'ing the daemon so relative paths in
# config resolve to this mailbox regardless of where the drive is
# mounted.  Users can edit these scripts in place on the drive — the
# customisations travel with the mailbox.
if [ -d "$ROOT/scripts/hooks" ]; then
    for _h in "$ROOT/scripts/hooks"/*.sh; do
        [ -f "$_h" ] || continue
        cp "$_h" "$MAILBOX_DIR/scripts/"
        chmod +x "$MAILBOX_DIR/scripts/$(basename "$_h")"
    done
fi

# ---------------------------------------------------------------------------
# Write the mailbox config.  Design notes:
#
#   • No `mail = ...` — the daemon is launched in "directory form" (arg =
#     mailbox path), which ignores this field.  Hard-coding a
#     mount-point-dependent path here would break across hosts.
#   • No `libs = ...` — rmail.lua automatically searches
#     <script_dir>/libs/, which resolves to $DRIVE/source-code/libs
#     regardless of mount point.
#   • `notify_ip_change = false` — a portable drive's IP changes every
#     time it's plugged into a new host; auto-notifying contacts on
#     every move would be noisy and leak host-hopping behaviour.  Flip
#     to true if the drive mostly lives on one machine.
#   • Hooks use `./scripts/<name>.sh` relative paths.  run.sh cd's into
#     the mailbox before exec'ing the daemon, so these resolve to the
#     scripts/ directory inside this mailbox on any host.

cat > "$MAILBOX_DIR/config" <<CONFIG
# rmail configuration — portable mailbox drive
# generated by scripts/make-mailbox-drive.sh

# local identity (never transmitted)
name = $NAME

# listening port — make sure the host's router forwards this to the host
port = $PORT

# portable drives move between hosts; each host has a different public
# IP, so IP-change notifications would fire on every replug.  Flip this
# to true if the drive mostly lives on one machine.
notify_ip_change = false

# Hook scripts live in ./scripts/ inside this mailbox.  Paths are
# relative to the mailbox dir because run.sh cd's into it before
# starting the daemon, so they survive the drive being moved between
# hosts (no absolute mount-point path in config).  Edit the scripts
# in place to customise; set a line to "" to disable that hook.
on_receive_raw = ./scripts/on_receive_raw.sh
on_receive     = ./scripts/on_receive.sh
on_package     = ./scripts/on_package.sh
on_send        = ./scripts/on_send.sh
on_delete      = ./scripts/on_delete.sh
on_update      = ./scripts/on_update.sh
CONFIG
ok "wrote config: $MAILBOX_DIR/config"

# ---------------------------------------------------------------------------
# Write the drive's top-level run.sh.

cat > "$DEST/run.sh" <<RUN
#!/bin/sh
# run.sh — start rmail using this drive's mailbox and config.
#
# Paths are resolved relative to this script's location, so the drive
# works from whatever mount point the host picks (/run/media/…,
# /media/…, a manual mount, …).

set -e
DRIVE="\$(cd "\$(dirname "\$0")" && pwd)"
MAILBOX_DIR="\$DRIVE/$MAILBOX_NAME"
SRC="\$DRIVE/source-code"

if [ ! -d "\$MAILBOX_DIR" ]; then
    echo "error: no mailbox at \$MAILBOX_DIR" >&2
    exit 1
fi

# Pick the Lua the same way run-rmail.sh does, then check whether the
# prebuilt libs on this drive actually load under that Lua.  A Lua-version
# or glibc/arch mismatch shows up as "undefined symbol" or "incompatible
# Lua version" from require — in that case, rebuild libs for this host.
_lua=""
if [ -x "\$SRC/deps/lua/bin/lua" ]; then
    _lua="\$SRC/deps/lua/bin/lua"
else
    for _l in lua5.4 luajit lua5.3 lua5.2 lua5.1 lua; do
        if command -v "\$_l" >/dev/null 2>&1; then _lua=\$(command -v "\$_l"); break; fi
    done
fi

_libs_ok=1
if [ -z "\$_lua" ]; then
    echo "error: no lua interpreter found (install lua5.4 or similar)" >&2
    exit 1
fi
if [ ! -d "\$SRC/libs" ] || [ -z "\$(ls -A "\$SRC/libs" 2>/dev/null)" ]; then
    _libs_ok=0
else
    # Probe: can this Lua load the key C modules from the drive's libs?
    if ! LUA_PATH="\$SRC/libs/?.lua;;" LUA_CPATH="\$SRC/libs/?.so;;" \\
         "\$_lua" -e 'require "socket.core"; require "rmail_crypto"' >/dev/null 2>&1; then
        echo "rmail libs on drive are not compatible with this host's Lua —" >&2
        echo "rebuilding (one-time, a few minutes)." >&2
        _libs_ok=0
    fi
fi

if [ "\$_libs_ok" = 0 ]; then
    # Re-use the drive's own config values so install.sh's prompts are
    # satisfied with valid data.  install.sh will write a side-effect
    # config file under \$HOME/.config/rmail/ on the host — harmless; the
    # drive's own config at \$MAILBOX_DIR/config is what the daemon actually uses
    # at launch (directory form passes through to the mailbox config).
    _name=\$(awk -F'[ \\t]*=[ \\t]*' '/^[[:space:]]*name[[:space:]]*=/ {print \$2; exit}' "\$MAILBOX_DIR/config")
    _port=\$(awk -F'[ \\t]*=[ \\t]*' '/^[[:space:]]*port[[:space:]]*=/ {print \$2; exit}' "\$MAILBOX_DIR/config")
    : "\${_name:=portable}"
    : "\${_port:=54321}"
    ( cd "\$SRC" && ./scripts/install.sh --silent --yes --force \\
        --mail-dir="\$MAILBOX_DIR" --name="\$_name" --port="\$_port" \\
        --no-setup-service ) || {
        echo "rebuild failed — see output above." >&2
        exit 1
    }
fi

# cd into the mailbox so relative hook paths in config (e.g.
# ./scripts/on_receive.sh) resolve correctly regardless of mount point.
# The daemon doesn't chdir during its run, so CWD stays stable.
cd "\$MAILBOX_DIR"
exec "\$SRC/run-rmail.sh" "\$MAILBOX_DIR"
RUN
chmod +x "$DEST/run.sh"

# ---------------------------------------------------------------------------
# Write the drive's top-level README.md.

cat > "$DEST/README.md" <<README
# Portable rmail mailbox

This USB drive **is** a running rmail mailbox.  Plug it into any Linux
host whose router is forwarding port \`$PORT\` to that host, run
\`./run.sh\` from the drive, and you're live.  Unplug, move to another
host that also has port \`$PORT\` forwarded, run \`./run.sh\` again —
same mailbox, same contacts, same history.

## Before first use on a new host

1. **Open port \`$PORT\`** in the host's router and firewall, pointing
   at this host's LAN IP.  Without that, the world can't reach your
   daemon.  (The exact steps depend on your router — search its admin
   UI for "port forwarding".)
2. **Install a Lua interpreter** if the host doesn't have one.  Any of
   \`lua5.4\`, \`luajit\`, \`lua5.3\`, \`lua5.2\`, \`lua5.1\`, or \`lua\`
   on \$PATH will do.  On Debian/Ubuntu: \`sudo apt install lua5.4\`.

## Run it

From the drive's mount point:

    ./run.sh

Logs go to stdout; Ctrl-C to stop.  For a long-running daemon, use
\`nohup ./run.sh > mail.log 2>&1 &\` or set it up as a systemd user
service pointing at \`./run.sh\`.

## Rebuild on host mismatch

The drive ships with libs prebuilt on whatever machine generated it.
Those libs won't work if this host has a materially different glibc or
architecture.  \`run.sh\` checks for that case on launch and kicks off
\`scripts/install.sh\` once to rebuild, caching the result back into
\`source-code/libs/\` on the drive.  First launch on a new architecture
takes a few minutes; subsequent launches are instant.

## Troubleshooting

* **"no lua interpreter found"** — see step 2 above.
* **"address already in use"** — another process on this host is
  already using port \`$PORT\`.  Stop it or pick a different port (edit
  \`$MAILBOX_NAME/config\` on the drive).
* **Contacts can't reach you** — double-check the router forwards
  \`$PORT\` to this host's current LAN IP.  The drive's source tree
  includes \`source-code/scripts/validate-router-settings.sh\` which
  can help diagnose.

## Customising hooks

Hook scripts live in \`$MAILBOX_NAME/scripts/\` inside the mailbox.
Edit them in place — the customisations are part of the mailbox and
travel with the drive.  The config references them with relative
paths (\`./scripts/on_receive.sh\` etc.) which resolve correctly
because \`run.sh\` cd's into the mailbox before launching the daemon.
Set a hook line in the config to \`""\` to disable that hook entirely.

## What's on the drive?

* \`run.sh\` — launcher.  Resolves paths from its own location so the
  mount point doesn't matter.
* \`$MAILBOX_NAME/\` — the mailbox itself.  Inbox, outbox, contacts,
  attachments, state, and hook scripts all live here.
* \`$MAILBOX_NAME/scripts/\` — the mailbox's hook scripts.  Edit in
  place to customise; they're referenced with relative paths from
  the mailbox config so they stay portable.
* \`source-code/\` — full rmail source plus prebuilt libs.  Don't
  usually need to touch this; \`run.sh\` manages it automatically.
* \`README.md\` — this file.
README

# ---------------------------------------------------------------------------
# Summary.

_bytes=$(du -sh "$DEST" 2>/dev/null | awk '{print $1}')
echo ""
ok "mailbox drive ready at $DEST (total size: ${_bytes:-unknown})"
info "drive contents:"
info "    $DEST/run.sh"
info "    $DEST/README.md"
info "    $DEST/source-code/"
info "    $DEST/$MAILBOX_NAME/  (config, inbox, outbox, attachments, contacts, scripts)"
echo ""
info "identity: $NAME"
info "port:     $PORT"
echo ""
warn "before first use on any host: forward port $PORT on that host's router."
echo ""
drive_eject_hint "$DEST"
