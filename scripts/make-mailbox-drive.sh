#!/bin/sh
# make-mailbox-drive.sh — populate a USB drive with a running rmail mailbox.
#
# Implements issue #616.  The resulting drive is itself a runnable rmail
# node: plug it into any Linux host whose router forwards the configured
# port and run one of the mailbox's launchers -- sync-with-contacts.sh for
# a single visit, auto-sync.sh to stay live until unplugged.  Unplug and
# move the drive to another host and do the same — same mailbox, same
# contacts, same history.  Nothing announces itself until you run one.
#
# Drive layout:
#
#   /README.md         # plug-and-run instructions + router-port reminder
#   /mailbox-0/
#       sync-with-contacts.sh   # one visit: announce, sync, linger, stop
#       auto-sync.sh            # normal sync cycle until unplugged
#       config         # real file (not a symlink — mount point differs per host)
#       inbox/
#       outbox/
#       attachments/
#       hooks/         # this mailbox's own hook scripts, edited in place
#       .state/
#       contacts       # starts empty
#       source-code/   # the program, trimmed — see below
#           <arch>/    # one per kind of machine: x86_64/, aarch64/
#
# A mailbox on a machine holds no program: one git checkout serves every
# mailbox there, and the service file says which mailbox each daemon is
# for.  This is the exception, and the reason is the medium rather than
# the mailbox — there is no checkout on the far end of a USB cable, so
# the drive brings one (#102).
#
# What travels is a payload built for drives by
# scripts/generate-portable-mailbox.sh (#617), and it is an allowlist,
# not the whole tree minus exclusions:
#
#   rmail.lua, run-rmail.sh, libs/     the daemon and its libraries
#   deps/lua/                          the interpreter — required, not optional
#   rmail_crypto.c, rmail_inotify.c    the source behind the two .so files
#   BUILD-NOTES.txt                    the commands that compiled them
#   LICENSE, licenses/                 ship with the binaries
#
# This script places a payload and compiles nothing.  It used to copy
# whatever install.sh had left in libs/ and deps/, which was built for a
# local install, and then patch it up for a drive: relink the crypto
# module against a static OpenSSL, warn about a readline Lua.  The
# generator now does the right build in the first place.
#
# Not the Android client, the docs, the issues, or the development
# transcripts.  A drive is somebody's mailbox made portable, not a way
# of handing the project to a new person, and the transcripts in
# particular have no business travelling.  Subtracting from the whole
# tree meant the drive silently gained whatever the project gained next;
# an allowlist means a new directory has to be asked for.
#
# The interpreter is required because the alternative is asking the host
# for one, and a host's Lua may be a different version than these
# libraries were built against — which fails as an undefined symbol from
# inside require rather than as a sentence anybody can act on.
#
# What a drive still asks of a host is a CPU it was built for.  That is
# not fixable by bundling one program: an x86-64 binary does not run on
# ARM.  So a drive carries one program per kind of machine it is meant
# for (#619), each given with --payload, in source-code/<arch>/, and the
# launchers pick this machine's.  For a kind it holds none for, they name
# the kinds it does hold and stop, where it used to quietly spend a few
# minutes recompiling on somebody else's machine.
#
# install.sh used to travel, solely to do that recompiling, and it also
# stood in as the build instructions the licence wants alongside shipped
# binaries.  BUILD-NOTES.txt covers the second job, and the first job is
# one nobody wanted done.
#
# Usage:
#   scripts/make-mailbox-drive.sh --name NAME --port PORT \
#                                 [--payload DIR] [--dest PATH] \
#                                 [--mailbox NAME] [--dry-run]

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
PAYLOADS=""   # one directory per line: a payload for each architecture

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
  --payload DIR      The program to put on the drive, as built by
                     scripts/generate-portable-mailbox.sh.  Give it once
                     for each kind of machine the drive should run on
                     (#619): one payload per architecture.  Default: this
                     machine's own, deps/portable/<arch>/payload, which is
                     built first if it is not there yet.
  --dest PATH        Write to PATH instead of auto-detecting a flash drive
  --mailbox NAME     Name for the mailbox directory (default: mailbox-0)
  --dry-run          Print what would happen; don't modify anything
  --force            Overwrite an existing mailbox on the drive.  By
                     default, refuses if the mailbox directory already
                     exists — you almost never want to clobber real mail.

Auto-detection looks for a mounted filesystem whose mount-point basename
matches FLASH_LABEL (currently "RMAIL").  If zero or multiple drives
match, --dest is required.

This script compiles nothing.  The payload carries its own Lua and its
own OpenSSL, so the drive runs without asking a host for an interpreter
or a library.  To build one for another kind of machine:

    scripts/generate-portable-mailbox.sh --target aarch64

and pass the directory it prints to --payload, beside this machine's:

    --payload deps/portable/x86_64/payload --payload deps/portable/aarch64/payload

A drive runs on the kinds of machine it holds a payload for.  Plugged
into any other kind, the launchers name the kinds it holds and stop.
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
        --payload)
            [ -z "${2:-}" ] && { err "--payload requires a directory"; exit 1; }
            PAYLOADS="$PAYLOADS$2
"; shift 2 ;;
        --payload=*) PAYLOADS="$PAYLOADS${1#*=}
"; shift ;;
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
# The payload: the program this drive will carry.
#
# Given one, use it.  Otherwise use this machine's own from where the
# generator leaves it, and build that first if it is not there — the
# common case stays one command, and the build is the generator's, with
# its phases and its checks, rather than a second copy of them here.

# The architecture names, as uname -m and the generator use them
host_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo x86_64 ;;
        aarch64|arm64) echo aarch64 ;;
        *) uname -m ;;
    esac
}
# what readelf -h says a binary for <arch> is
elf_machine() {
    case "$1" in
        x86_64)  echo "Advanced Micro Devices X86-64" ;;
        aarch64) echo "AArch64" ;;
    esac
}
# the architecture a payload was built for: its ARCH file, written by the
# generator, or for a payload made before that file, its interpreter's
# machine as readelf reads it
payload_arch() {
    if [ -s "$1/ARCH" ]; then
        head -n 1 "$1/ARCH" | tr -d ' \t\r'
        return
    fi
    case "$(readelf -h "$1/deps/lua/bin/lua" 2>/dev/null | sed -n 's/^ *Machine: *//p')" in
        "Advanced Micro Devices X86-64") echo x86_64 ;;
        AArch64) echo aarch64 ;;
        *) echo unknown ;;
    esac
}
HOST_ARCH=$(host_arch)

if [ -z "$PAYLOADS" ]; then
    PAYLOAD="$ROOT/deps/portable/$HOST_ARCH/payload"
    if [ ! -d "$PAYLOAD" ]; then
        if $DRY_RUN; then
            info "would build a payload first: scripts/generate-portable-mailbox.sh"
        else
            info "no payload for $HOST_ARCH yet; building one"
            "$SCRIPT_DIR/generate-portable-mailbox.sh" --target "$HOST_ARCH"
        fi
    fi
    PAYLOADS="$PAYLOAD
"
fi

# Each payload: there, finished, of a known architecture, and no two for
# the same one.  ARCHES lists them in the order given, "x86_64 aarch64".
ARCHES=""
_nl='
'
_old_ifs=$IFS
IFS=$_nl
for PAYLOAD in $PAYLOADS; do
    IFS=$_old_ifs
    [ -n "$PAYLOAD" ] || continue
    if [ ! -d "$PAYLOAD" ]; then
        if $DRY_RUN; then continue; fi
        err "no payload at $PAYLOAD"
        err "  build one with scripts/generate-portable-mailbox.sh"
        exit 1
    fi
    PAYLOAD=$(cd "$PAYLOAD" && pwd)

    # The bundled interpreter is required, not preferred.  A drive carrying
    # libraries but no Lua is asking the host for one, and a host that has
    # no Lua — or one built against a different Lua version than these
    # libraries were — is exactly the situation a portable drive exists to
    # survive.  Refuse to make half a drive.
    if [ ! -x "$PAYLOAD/deps/lua/bin/lua" ]; then
        err "the payload has no Lua at $PAYLOAD/deps/lua/bin/lua"
        err "  it is not a payload the generator finished; build it again with"
        err "  scripts/generate-portable-mailbox.sh --force"
        exit 1
    fi
    for _f in rmail.lua run-rmail.sh libs BUILD-NOTES.txt LICENSE; do
        if [ ! -e "$PAYLOAD/$_f" ]; then
            err "the payload is missing $_f: $PAYLOAD"
            err "  build it again with scripts/generate-portable-mailbox.sh --force"
            exit 1
        fi
    done
    _a=$(payload_arch "$PAYLOAD")
    if [ -z "$(elf_machine "$_a")" ]; then
        err "cannot tell which kind of machine $PAYLOAD is for (${_a:-nothing})"
        err "  the drive's kinds are x86_64 and aarch64; build it again with"
        err "  scripts/generate-portable-mailbox.sh --target <kind> --force"
        exit 1
    fi
    case " $ARCHES " in
        *" $_a "*)
            err "two payloads for $_a: a drive holds one program for each kind of machine"
            exit 1 ;;
    esac
    ARCHES="${ARCHES:+$ARCHES }$_a"
    ok "payload for $_a: $PAYLOAD"
    IFS=$_nl
done
IFS=$_old_ifs

if $DRY_RUN; then
    info "would create the mailbox at $MAILBOX_DIR"
    info "would copy the trimmed program into $MAILBOX_DIR/source-code/, for: ${ARCHES:-this machine}"
    ok "dry run complete — nothing written."
    exit 0
fi

# ---------------------------------------------------------------------------
# Create mailbox directory tree.

info "creating mailbox at $MAILBOX_DIR"
mkdir -p "$MAILBOX_DIR/inbox" "$MAILBOX_DIR/outbox" "$MAILBOX_DIR/attachments" "$MAILBOX_DIR/.state" "$MAILBOX_DIR/hooks"
: > "$MAILBOX_DIR/contacts"    # empty contacts file

# Copy the default hook scripts into the mailbox's own hooks/ dir.
# Config references them as ./hooks/<name>.sh.  The daemon resolves a
# relative hook path against the directory holding the config file, and
# the config sits inside the mailbox, so these land on this mailbox's own
# copies at whatever mount point the host picks.  Users edit them in place
# on the drive and the customisations travel with the mailbox.
if [ -d "$ROOT/scripts/hooks" ]; then
    for _h in "$ROOT/scripts/hooks"/*.sh; do
        [ -f "$_h" ] || continue
        cp "$_h" "$MAILBOX_DIR/hooks/"
        chmod +x "$MAILBOX_DIR/hooks/$(basename "$_h")"
    done
fi

# ---------------------------------------------------------------------------
# Copy the program into the mailbox.
#
# This is the one kind of mailbox that carries its own program.  A mailbox
# on a machine runs the daemon out of the git checkout, named by its
# service file; a mailbox on removable media has no checkout at the far
# end, so it brings one.
#
# An allowlist rather than the whole tree with exclusions.  Copying
# everything and subtracting meant the drive quietly gained whatever was
# added to the project next — at one point the entire Android client and
# the development transcripts.  Listing what a daemon needs in order to
# run and to be rebuilt is a short list, and a new directory in the
# project does not join it by default.
#
SRC_DIR="$MAILBOX_DIR/source-code"
info "copying the program into $SRC_DIR"
# the program only, never mail: what an earlier drive (--force) left of
# it, perhaps in the older single-machine layout, goes
rm -rf "$SRC_DIR"
mkdir -p "$SRC_DIR"

# A payload is already exactly what travels for one kind of machine: the
# generator laid it out for a drive, trimmed the interpreter's build-time
# pieces, and wrote the build notes and licences.  So nothing here
# chooses, relinks or rebuilds any part of it.
#
# Laid out per architecture (#619), so one drive can carry several:
#
#   source-code/rmail.lua, run-rmail.sh, libs/*.lua, LICENSE, licenses/,
#               the C sources            the same for every kind of machine
#   source-code/<arch>/deps/lua/         that kind's interpreter
#   source-code/<arch>/libs/**.so        its compiled libraries
#   source-code/<arch>/BUILD-NOTES.txt   how they were built
#
# The launchers put the shared part and their machine's part together in
# a temporary copy, the flat layout the daemon expects.  What is shared
# must be the same in every payload -- built from one checkout -- or one
# kind of machine would run a different rmail from another; a difference
# is refused, naming it.
STAGE="$MAILBOX_DIR/.source-code-staging"
rm -rf "$STAGE"
mkdir -p "$STAGE/shared"
_first=true
IFS=$_nl
for PAYLOAD in $PAYLOADS; do
    IFS=$_old_ifs
    [ -n "$PAYLOAD" ] || continue
    PAYLOAD=$(cd "$PAYLOAD" && pwd)
    _a=$(payload_arch "$PAYLOAD")
    _one="$STAGE/one"
    rm -rf "$_one"
    mkdir -p "$_one/shared" "$STAGE/$_a/libs"
    cp -R "$PAYLOAD/." "$_one/shared/"
    mv "$_one/shared/deps" "$STAGE/$_a/deps"
    mv "$_one/shared/BUILD-NOTES.txt" "$STAGE/$_a/BUILD-NOTES.txt"
    rm -f "$_one/shared/ARCH"
    ( cd "$_one/shared" && find libs -name '*.so' ) | while IFS= read -r _rel; do
        mkdir -p "$STAGE/$_a/$(dirname "$_rel")"
        mv "$_one/shared/$_rel" "$STAGE/$_a/$_rel"
    done
    if $_first; then
        cp -R "$_one/shared/." "$STAGE/shared/"
        _first=false
    elif ! _diff=$(diff -rq "$STAGE/shared" "$_one/shared" 2>&1); then
        err "the payloads differ in more than their compiled parts:"
        printf '%s\n' "$_diff" | sed "s|$STAGE/shared|first|; s|$_one/shared|$_a|" | head -5 >&2
        err "  build them all from one checkout, then make the drive again"
        rm -rf "$STAGE"
        exit 1
    fi
    rm -rf "$_one"
    IFS=$_nl
done
IFS=$_old_ifs
cp -R "$STAGE/shared/." "$SRC_DIR/"
for _a in $ARCHES; do
    mv "$STAGE/$_a" "$SRC_DIR/$_a"
    chmod +x "$SRC_DIR/$_a/deps/lua/bin/lua"
done
rm -rf "$STAGE"
chmod +x "$SRC_DIR/run-rmail.sh"

# Prove the drive works before handing it over.
#
# The launchers run this same check on every launch and, when it fails, tell
# the user the drive was not built for that kind of machine.  That sentence
# is only honest if the drive was known to work somewhere.  For the payload
# built for this machine the somewhere is here, now; for one built for
# another kind, this machine cannot run it, so every binary in it is checked
# to be for the kind it says (readelf), which is weaker but not nothing.
for _a in $ARCHES; do
    if [ "$_a" = "$HOST_ARCH" ]; then
        if LUA_PATH="$SRC_DIR/libs/?.lua;;" LUA_CPATH="$SRC_DIR/$_a/libs/?.so;;" \
             "$SRC_DIR/$_a/deps/lua/bin/lua" \
             -e 'require "socket.core"; require "rmail_crypto"; require "rmail_inotify"' \
             >/dev/null 2>&1; then
            ok "checked: the drive's own $_a Lua loads the drive's own libraries"
        else
            err "the drive's own $_a interpreter cannot load the drive's own libraries"
            err "  this drive would not run on a $_a machine, including this one, so it"
            err "  is not worth carrying.  Build the payload again with"
            err "  scripts/generate-portable-mailbox.sh --force, then make the drive again."
            exit 1
        fi
    elif command -v readelf >/dev/null 2>&1; then
        _want=$(elf_machine "$_a")
        _bad=$(cd "$SRC_DIR/$_a" && find deps/lua/bin/lua libs -type f \( -name lua -o -name '*.so' \) | while IFS= read -r _bin; do
            _m=$(readelf -h "$_bin" 2>/dev/null | sed -n 's/^ *Machine: *//p')
            [ "$_m" = "$_want" ] || printf '%s (%s) ' "$_bin" "${_m:-not an ELF file}"
        done)
        if [ -n "$_bad" ]; then
            err "the $_a payload holds binaries for another kind of machine: $_bad"
            exit 1
        fi
        ok "checked: every $_a binary is built for $_a (this machine cannot run them)"
    else
        warn "this machine cannot run the $_a program and has no readelf to check it with"
    fi
done

ok "program: $SRC_DIR ($(du -sh "$SRC_DIR" | cut -f1))"

# ---------------------------------------------------------------------------
# Write the mailbox config.  Design notes:
#
#   • Nothing naming the mailbox.  The daemon serves the directory its
#     config sits in, and this config sits in the mailbox, so the
#     mailbox is right on every host and at every mount point without
#     anybody writing a path down.  This is why a drive works at all:
#     there is no mount point recorded to go stale.
#   • No `libs = ...` — rmail.lua automatically searches
#     <script_dir>/libs/, which resolves to the mailbox's own source-code/libs
#     regardless of mount point.
#   • Hooks use `./hooks/<name>.sh` relative paths, which the daemon
#     resolves against the directory holding this config — the mailbox
#     itself — so they reach this mailbox's own copies on any host.

cat > "$MAILBOX_DIR/config" <<CONFIG
# rmail configuration — portable mailbox drive
# generated by scripts/make-mailbox-drive.sh

# local identity.  Not carried in the mail you send — each contact sees you
# by the name they gave you in their own contacts file, and the plaintext
# health check does not send it.
name = $NAME

# listening port — make sure the host's router forwards this to the host
port = $PORT

# Hook scripts live in ./hooks/ inside this mailbox.  The paths are
# relative to this config file, which sits in the mailbox, so they
# survive the drive being moved between hosts with no mount-point path
# written down anywhere.  Edit the scripts in place to customise; set a
# line to "" to disable that hook.
on_receive_raw = ./hooks/on_receive_raw.sh
on_receive     = ./hooks/on_receive.sh
on_package     = ./hooks/on_package.sh
on_consent     = ./hooks/on_consent.sh
on_send        = ./hooks/on_send.sh
on_delete      = ./hooks/on_delete.sh
on_update      = ./hooks/on_update.sh
CONFIG
ok "wrote config: $MAILBOX_DIR/config"

# ---------------------------------------------------------------------------
# Write the mailbox's two launchers.
#
# A portable mailbox never announces itself on its own.  Plugged into a
# friend's machine, it has no business telling every contact that it now
# lives there -- so nothing runs until someone runs one of these, and
# running one is the decision to be reachable here:
#
#   sync-with-contacts.sh [SECONDS]   one visit: announce where we are,
#                                     send the outbox, stay reachable
#                                     SECONDS (default 60) so contacts can
#                                     deliver, then stop.
#   auto-sync.sh                      the normal sync cycle, until the
#                                     drive is unplugged or Ctrl-C.
#
# Both live inside the mailbox rather than at the drive root: the mailbox
# is the installation (#102), and a mailbox copied off the drive should
# still carry its way to run.
#
# Both run the daemon from a copy of source-code/ in a temporary directory
# rather than from the drive.  Pulling the drive out from under a running
# interpreter is a SIGBUS the next time it pages code in; from a copy, the
# daemon notices its mailbox is gone and exits cleanly instead.  For the
# same reason the whole script body is one function: sh reads a function
# in full before running it, so it never needs the drive to read on.

write_launcher() {  # <file> <once|auto>
    if [ "$2" = once ]; then
        _what='one visit: tell contacts where this mailbox is, send the
# outbox, stay reachable for SECONDS (default 60) so contacts can deliver,
# then stop.  Run it again whenever you want to check for mail.
#
# usage: ./sync-with-contacts.sh [SECONDS]'
        _args='--once="${1:-60}"'
        _check='case "${1:-60}" in *[!0-9]*|"") echo "usage: $0 [SECONDS]" >&2; return 2 ;; esac'
    else
        _what='keep this mailbox live -- the normal sync cycle, announcing
# where it is and delivering as mail arrives -- until the drive is unplugged
# or you press Ctrl-C.
#
# usage: ./auto-sync.sh'
        _args=''
        _check=':'
    fi
    cat > "$1" <<LAUNCH
#!/bin/sh
# $(basename "$1") -- $_what
#
# Paths are worked out from this script's own location, so the drive works
# from whatever mount point the host picks.

main() {
    $_check
    MAILBOX_DIR="\$(cd "\$(dirname "\$0")" && pwd)"
    SRC="\$MAILBOX_DIR/source-code"

    # This machine's kind, named as the drive names its folders (#619)
    case "\$(uname -m)" in
        x86_64|amd64) ARCH=x86_64 ;;
        aarch64|arm64) ARCH=aarch64 ;;
        *) ARCH="\$(uname -m)" ;;
    esac
    # The kinds this drive holds a program for
    HELD=""
    for _lua in "\$SRC"/*/deps/lua/bin/lua; do
        [ -x "\$_lua" ] || continue
        _kind="\${_lua%/deps/lua/bin/lua}"
        HELD="\${HELD:+\$HELD, }\${_kind##*/}"
    done

    # The drive's own interpreter, and only that one: a host's Lua may be a
    # different version than these libraries were built against, and that
    # fails as an "undefined symbol" deep inside require.
    if [ -z "\$HELD" ]; then
        echo "error: this drive holds no program at all (no \$SRC/<kind>/deps/lua/bin/lua)" >&2
        echo "  it is incomplete; regenerate it with make-mailbox-drive.sh" >&2
        return 1
    fi
    if [ ! -x "\$SRC/\$ARCH/deps/lua/bin/lua" ]; then
        echo "error: this drive was not built for this kind of machine." >&2
        echo "  This drive:  \$HELD" >&2
        echo "  This host:   \$(uname -m)" >&2
        echo "  Nothing is damaged and no mail has been touched." >&2
        return 1
    fi

    # Run from a copy, so pulling the drive cannot pull code out from
    # under the interpreter.  See make-mailbox-drive.sh.  The copy puts
    # the shared program and this machine's compiled part together.
    RUN="\$(mktemp -d "\${XDG_RUNTIME_DIR:-/tmp}/rmail-XXXXXX")" || return 1
    trap 'rm -rf "\$RUN"' EXIT INT TERM
    cp -R "\$SRC/rmail.lua" "\$SRC/run-rmail.sh" "\$SRC/libs" "\$RUN/" || return 1
    cp -R "\$SRC/\$ARCH/libs/." "\$RUN/libs/" || return 1
    cp -R "\$SRC/\$ARCH/deps" "\$RUN/" || return 1

    # Anything that fails to load here is a mismatch between this drive's
    # \$ARCH program and this host: a 32-bit system on a 64-bit processor,
    # or a C library older than the build's.  Say so and stop rather than
    # rebuilding on somebody else's machine.
    if ! LUA_PATH="\$RUN/libs/?.lua;;" LUA_CPATH="\$RUN/libs/?.so;;" \\
         "\$RUN/deps/lua/bin/lua" -e 'require "socket.core"; require "rmail_crypto"' >/dev/null 2>&1; then
        echo "error: this drive's \$ARCH program does not run on this machine." >&2
        echo "  This drive:  \$HELD" >&2
        echo "  This host:   \$(uname -m), \$(getconf LONG_BIT 2>/dev/null || echo '?')-bit" >&2
        echo "  Nothing is damaged and no mail has been touched." >&2
        return 1
    fi

    # cd into the mailbox so relative hook paths in config resolve.  The
    # daemon is handed the config file; the mailbox is wherever it sits.
    cd "\$MAILBOX_DIR" || return 1
    "\$RUN/run-rmail.sh" "\$MAILBOX_DIR/config" $_args
}

main "\$@"
exit \$?
LAUNCH
    chmod +x "$1"
}

write_launcher "$MAILBOX_DIR/sync-with-contacts.sh" once
write_launcher "$MAILBOX_DIR/auto-sync.sh" auto
ok "wrote launchers: $MAILBOX_NAME/sync-with-contacts.sh, $MAILBOX_NAME/auto-sync.sh"

# ---------------------------------------------------------------------------
# Write the drive's top-level README.md.

# the kinds of machine, in words someone holding the drive can match
ARCH_WORDS=""
for _a in $ARCHES; do
    case "$_a" in
        x86_64)  _w="x86_64 (most laptops and desktops)" ;;
        aarch64) _w="aarch64 (64-bit ARM: Raspberry Pi 3 and later with a 64-bit system, other single-board computers)" ;;
        *)       _w="$_a" ;;
    esac
    ARCH_WORDS="${ARCH_WORDS:+$ARCH_WORDS; }$_w"
done
ARCH_LIST=$(echo "$ARCHES" | sed 's/ /, /g')

cat > "$DEST/README.md" <<README
# Portable rmail mailbox

This USB drive **is** an rmail mailbox.  Plug it into any Linux host
whose router forwards port \`$PORT\` to that host and run one of the
mailbox's two launchers.  Unplug, move to another host that also has port
\`$PORT\` forwarded, do the same — same mailbox, same contacts, same
history.

Nothing happens on its own.  Plugging the drive in announces nothing to
anyone; running a launcher is how you say "I'm reachable here now".

## Before first use on a new host

**Open port \`$PORT\`** in the host's router and firewall, pointing at
this host's LAN IP.  Without that, contacts can't deliver to you.  (The
exact steps depend on your router — search its admin UI for "port
forwarding".)

## Check for mail once

    ./$MAILBOX_NAME/sync-with-contacts.sh

Tells your contacts where you are, sends everything in the outbox, stays
reachable for a minute so they can deliver what they have for you, then
stops.  Give it a number of seconds to stay longer — worth it when large
attachments are on their way:

    ./$MAILBOX_NAME/sync-with-contacts.sh 300

## Stay live until unplugged

    ./$MAILBOX_NAME/auto-sync.sh

Runs the normal sync cycle: mail goes out as soon as it lands in the
outbox and comes in whenever a contact sends it.  It stops by itself when
the drive is pulled out, or on Ctrl-C.  It runs the program from a
temporary copy on the host, so pulling the drive cannot crash it.

## What this drive needs from a host

Almost nothing.  It carries its own Lua interpreter and its own
libraries, and uses them in preference to anything installed on the
host, so it does not care whether the machine has rmail, or Lua, or
anything else.  The interpreter is built without readline, so all it
wants from the system is the C library and the maths library — which
every Linux has.

The one thing it cannot bring is a CPU.  An x86-64 program does not
run on an ARM machine, or the other way round, so the drive carries one
program for each kind of machine it was made for.  **This drive runs
on: $ARCH_WORDS.**  The launchers ask the machine what it is and run
the matching program.  On any other kind they say which kinds the
drive holds and stop, rather than failing somewhere confusing.  Nothing
is damaged and no mail is touched; the mailbox is plain files and is
readable anywhere.

Earlier versions recompiled themselves in that situation, which took a
few minutes and wrote to the drive on a machine somebody had only just
plugged it into.  It now says what is wrong and leaves the decision to
you.

## Troubleshooting

* **"this drive was not built for this kind of machine"** — see the
  section above.  The drive is fine; this host is a kind it holds no
  program for.  Make it again with a payload for this kind as well.
* **"this drive's ... program does not run on this machine"** — the
  drive holds a program for this kind of processor, but the system
  cannot run it: most often a 32-bit system on a 64-bit processor.
* **"this drive holds no program at all"** — the drive was not generated
  completely.  Make it again with \`scripts/make-mailbox-drive.sh\`.
* **"address already in use"** — another process on this host is
  already using port \`$PORT\`.  Stop it or pick a different port (edit
  \`$MAILBOX_NAME/config\` on the drive).
* **Contacts can't reach you** — double-check the router forwards
  \`$PORT\` to this host's current LAN IP.  The connectivity checker is
  not on the drive; it lives in the git checkout this drive was made
  from, as \`scripts/validate-router-settings.sh\`.

## Customising hooks

Hook scripts live in \`$MAILBOX_NAME/hooks/\` inside the mailbox.
Edit them in place — the customisations are part of the mailbox and
travel with the drive.  The config references them with relative
paths (\`./hooks/on_receive.sh\` etc.), which the daemon resolves
against the directory the config sits in, so they follow the mailbox
to whatever mount point a host gives it.
Set a hook line in the config to \`""\` to disable that hook entirely.

## What's on the drive?

* \`$MAILBOX_NAME/\` — the mailbox itself.  Inbox, outbox, contacts,
  attachments, state, hooks and the program all live here.
* \`$MAILBOX_NAME/sync-with-contacts.sh\`, \`auto-sync.sh\` — the two
  launchers.  They resolve paths from their own location, so the mount
  point doesn't matter.
* \`$MAILBOX_NAME/hooks/\` — the mailbox's hook scripts.  Edit in
  place to customise; they're referenced with relative paths from
  the mailbox config so they stay portable.
* \`$MAILBOX_NAME/source-code/\` — the daemon, its libraries and the C
  sources behind the compiled ones, and one folder per kind of machine
  ($ARCH_LIST) with that kind's own Lua interpreter, compiled
  libraries and \`BUILD-NOTES.txt\` saying how they were built.  The
  launchers use this; you shouldn't need to go in.
* \`README.md\` — this file.

## What this drive is not

It carries enough rmail to run this mailbox, and no more.  It is not a
copy of the project: no Android client, no documentation beyond this
file, no issue history.  A drive is your mailbox made portable, not a
way of handing rmail to somebody new.

For any of that — including the Android app, which is built from source
and sideloaded — go to the git checkout the drive was made from.
README

# ---------------------------------------------------------------------------
# Summary.

_bytes=$(du -sh "$DEST" 2>/dev/null | awk '{print $1}')
echo ""
ok "mailbox drive ready at $DEST (total size: ${_bytes:-unknown})"
info "drive contents:"
info "    $DEST/$MAILBOX_NAME/sync-with-contacts.sh  (one visit)"
info "    $DEST/$MAILBOX_NAME/auto-sync.sh          (live until unplugged)"
info "    $DEST/README.md"
info "    $DEST/$MAILBOX_NAME/source-code/  (the daemon and its libraries, for: $ARCH_LIST)"
info "    $DEST/$MAILBOX_NAME/  (config, inbox, outbox, attachments, contacts, hooks)"
echo ""
info "identity: $NAME"
info "port:     $PORT"
echo ""
warn "before first use on any host: forward port $PORT on that host's router."
echo ""
drive_eject_hint "$DEST"
