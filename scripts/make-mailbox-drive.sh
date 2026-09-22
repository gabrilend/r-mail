#!/bin/sh
# make-mailbox-drive.sh — populate a USB drive with a running rmail mailbox.
#
# Implements issue #339.  The resulting drive is itself a runnable rmail
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
#
# A mailbox on a machine holds no program: one git checkout serves every
# mailbox there, and the service file says which mailbox each daemon is
# for.  This is the exception, and the reason is the medium rather than
# the mailbox — there is no checkout on the far end of a USB cable, so
# the drive brings one (#382).
#
# What travels is an allowlist, not the whole tree minus exclusions:
#
#   rmail.lua, run-rmail.sh, libs/     the daemon and its libraries
#   deps/lua/                          the interpreter — required, not optional
#   rmail_crypto.c, rmail_inotify.c    the source behind the two .so files
#   BUILD-NOTES.txt                    the commands that compiled them
#   LICENSE                            ships with the binaries
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
# not fixable by bundling: an x86-64 binary does not run on ARM.  So
# the launchers check on launch and stops with an explanation, where it used to
# quietly spend a few minutes recompiling on somebody else's machine.
#
# install.sh used to travel, solely to do that recompiling, and it also
# stood in as the build instructions the licence wants alongside shipped
# binaries.  BUILD-NOTES.txt covers the second job in fifteen lines, and
# the first job is one nobody wanted done.
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

This checkout must already have both libs/ and a locally compiled Lua
under deps/lua — run scripts/install.sh once, choosing to compile Lua,
before using this generator.  Both are copied onto the drive, which
then runs without asking the host for an interpreter or a library.

A drive is tied to the CPU architecture it was built on.  Plugged into
a machine of a different kind, the launchers say so and stop.
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

# The bundled interpreter is required, not preferred.  A drive carrying
# libraries but no Lua is asking the host for one, and a host that has no
# Lua — or one too old, or built against a different Lua version than
# these libraries were — is exactly the situation a portable drive exists
# to survive.  Refuse to make half a drive.
if [ ! -x "$ROOT/deps/lua/bin/lua" ]; then
    err "no bundled Lua at $ROOT/deps/lua/bin/lua"
    err "  a portable drive carries its own interpreter, so this checkout"
    err "  needs one compiled before it can make a drive."
    err "  re-run scripts/install.sh and choose to compile Lua locally."
    exit 1
fi

if $DRY_RUN; then
    info "would create the mailbox at $MAILBOX_DIR"
    info "would copy the trimmed program into $MAILBOX_DIR/source-code/"
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
mkdir -p "$SRC_DIR"

for _f in rmail.lua run-rmail.sh rmail_crypto.c rmail_inotify.c LICENSE; do
    if [ -f "$ROOT/$_f" ]; then
        cp "$ROOT/$_f" "$SRC_DIR/$_f"
    else
        err "missing from the checkout: $_f"
        exit 1
    fi
done
chmod +x "$SRC_DIR/run-rmail.sh"

cp -a "$ROOT/libs" "$SRC_DIR/libs"

# Relink the crypto module so it carries its own OpenSSL.
#
# The checkout's copy borrows libcrypto from the machine it was built on
# — on a normal install that is correct and costs nothing.  On a drive it
# is a dependency on a stranger: OpenSSL 3 and OpenSSL 1.1 export
# different symbols, so a drive built against one and plugged into a host
# with the other fails at load.  That is not an exotic case; it is the
# difference between a current distribution and a long-term-support one.
#
# Only the archive's referenced parts get pulled in, but OpenSSL 3 routes
# even AES-GCM through its provider machinery, so "referenced" turns out
# to be most of the library.  It costs about 6.7 MB.  A flash drive has
# it; a host that cannot load the module does not.
_libcrypto_a=""
for _d in /usr/lib /usr/lib64 /usr/local/lib /usr/lib/x86_64-linux-gnu "$ROOT/deps/openssl/lib" "$ROOT/deps/openssl/lib64"; do
    [ -n "$_d" ] || continue
    if [ -f "$_d/libcrypto.a" ]; then _libcrypto_a="$_d/libcrypto.a"; break; fi
done

if [ -z "$_libcrypto_a" ]; then
    err "no static libcrypto.a found"
    err "  a drive carries its own OpenSSL rather than borrowing the host's,"
    err "  so the static archive is needed to build it.  Install your"
    err "  distribution's OpenSSL development package and try again."
    exit 1
fi

info "linking a self-contained crypto module against $_libcrypto_a"
if ! cc -shared -fPIC -O2 -Wall \
        -I"$ROOT/deps/lua/include" \
        -o "$SRC_DIR/libs/rmail_crypto.so" \
        "$ROOT/rmail_crypto.c" \
        "$_libcrypto_a" -lpthread 2>/dev/null; then
    err "could not build a self-contained crypto module"
    err "  needs a C compiler and OpenSSL headers on this machine."
    exit 1
fi

if ldd "$SRC_DIR/libs/rmail_crypto.so" 2>/dev/null | grep -q libcrypto; then
    err "the crypto module still wants libcrypto from a host"
    err "  the static link did not take; this drive would not be portable."
    exit 1
fi
ok "crypto module carries its own OpenSSL ($(du -h "$SRC_DIR/libs/rmail_crypto.so" | cut -f1))"


# The interpreter, and it is not optional.  A drive that relies on the host
# having a usable Lua is a drive that works on the hosts you tried and not
# on the one you needed.  Bundling it means the only thing the drive asks
# of a host is a CPU it was built for.
mkdir -p "$SRC_DIR/deps"
cp -a "$ROOT/deps/lua" "$SRC_DIR/deps/lua"

# The interpreter's build-time pieces do not travel.  liblua.a exists to
# compile modules against and luac compiles Lua to bytecode; neither is
# touched at runtime, and together they are most of what deps/lua weighs.
# The headers stay, because BUILD-NOTES.txt tells the reader they can
# rebuild the compiled parts and that should be true of what is in their
# hand.
rm -f "$SRC_DIR/deps/lua/bin/luac" "$SRC_DIR/deps/lua/lib/liblua.a"
rm -rf "$SRC_DIR/deps/lua/man" "$SRC_DIR/deps/lua/share"

# The recipe for the two compiled libraries.  They are shipped as binaries,
# and the licence this project is under says that anyone given a binary can
# ask for the source it came from — where "source" includes the commands
# that did the compiling, not only the .c files beside them.
#
# This used to be satisfied by putting the whole installer on the drive,
# which was a two-thousand-line answer to a two-line question.
cat > "$SRC_DIR/BUILD-NOTES.txt" <<'BUILDNOTES'
How the compiled parts of this drive were built
===============================================

Two of the files here are compiled from C, and this is how.  You need a C
compiler, OpenSSL's headers, and the Lua headers from deps/lua/include.

  cc -shared -fPIC -O2 -Wall -I deps/lua/include \
     -o libs/rmail_crypto.so rmail_crypto.c -lcrypto

  cc -shared -fPIC -O2 -Wall -I deps/lua/include \
     -o libs/rmail_inotify.so rmail_inotify.c

The interpreter in deps/lua is stock Lua, built with its own makefile and
no local changes:

  make linux          # deliberately not linux-readline — see below
  make install INSTALL_TOP=<somewhere>/deps/lua

It is built without readline on purpose.  readline is only used by Lua's
interactive prompt, which nothing here runs, and linking it would add
libreadline and libncursesw to what this drive needs from a host.  As
built, it needs libc and libm and nothing else.

The luasocket libraries under libs/socket and libs/mime are stock
luasocket.  The full project, including the build script that assembles
all of this, is at https://github.com/gabrilend/r-mail
BUILDNOTES

# Prove the drive works before handing it over.
#
# The launchers run this same check on every launch and, when it fails, tells
# the user the drive was built for a different kind of machine.  That
# sentence is only honest if the drive was known to work somewhere, so
# the somewhere is here, now, on the machine that just built it.
# Otherwise a drive assembled from a broken checkout would travel and
# then blame the host it arrived at.
if ! LUA_PATH="$SRC_DIR/libs/?.lua;;" LUA_CPATH="$SRC_DIR/libs/?.so;;" \
     "$SRC_DIR/deps/lua/bin/lua" \
     -e 'require "socket.core"; require "rmail_crypto"; require "rmail_inotify"' \
     >/dev/null 2>&1; then
    err "the copied interpreter cannot load the copied libraries"
    err "  this drive would not run anywhere, including here, so it is"
    err "  not worth carrying.  Re-run scripts/install.sh --force in the"
    err "  checkout to rebuild them, then make the drive again."
    exit 1
fi
ok "checked: the drive's own Lua loads the drive's own libraries"

# A Lua built before the no-readline change carries two dependencies it
# has no use for, and they are the two a spare or unusual host is most
# likely to be missing.  The drive still works everywhere that has them,
# so this is worth saying rather than refusing over — but it is worth
# saying, because otherwise every drive made from this checkout keeps
# inheriting it silently.
if command -v ldd >/dev/null 2>&1; then
    if ldd "$SRC_DIR/deps/lua/bin/lua" 2>/dev/null | grep -q "readline\|ncurses"; then
        warn "this checkout's Lua was built with readline, so the drive needs"
        warn "  libreadline and libncursesw from any host it is plugged into."
        warn "  Nothing here uses Lua's interactive prompt, which is all"
        warn "  readline is for.  Rebuilding drops them:"
        warn "      scripts/install.sh --force"
        warn "  then make the drive again."
    else
        ok "its Lua needs only libc and libm from a host"
    fi
fi

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
# by the name they gave you in their own contacts file — but not a secret
# either: the plaintext health check answers with it to any caller.
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
# is the installation (#382), and a mailbox copied off the drive should
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

    # The drive's own interpreter, and only that one: a host's Lua may be a
    # different version than these libraries were built against, and that
    # fails as an "undefined symbol" deep inside require.
    if [ ! -x "\$SRC/deps/lua/bin/lua" ]; then
        echo "error: this drive has no interpreter at \$SRC/deps/lua/bin/lua" >&2
        echo "  it is incomplete; regenerate it with make-mailbox-drive.sh" >&2
        return 1
    fi

    # Run from a copy, so pulling the drive cannot pull code out from
    # under the interpreter.  See make-mailbox-drive.sh.
    RUN="\$(mktemp -d "\${XDG_RUNTIME_DIR:-/tmp}/rmail-XXXXXX")" || return 1
    trap 'rm -rf "\$RUN"' EXIT INT TERM
    cp -R "\$SRC/rmail.lua" "\$SRC/run-rmail.sh" "\$SRC/libs" "\$SRC/deps" "\$RUN/" || return 1

    # Anything that fails to load here is a mismatch between the drive and
    # this host -- almost always CPU architecture.  Say so and stop rather
    # than rebuilding on somebody else's machine.
    if ! LUA_PATH="\$RUN/libs/?.lua;;" LUA_CPATH="\$RUN/libs/?.so;;" \\
         "\$RUN/deps/lua/bin/lua" -e 'require "socket.core"; require "rmail_crypto"' >/dev/null 2>&1; then
        echo "error: this drive was built for a different kind of machine." >&2
        echo "  This drive:  \$(file -b "\$SRC/deps/lua/bin/lua" 2>/dev/null | cut -d, -f1-2)" >&2
        echo "  This host:   \$(uname -m)" >&2
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

The one thing it cannot bring is a CPU.  A drive built on an x86-64
machine will not run on an ARM one, or the other way round.  The
launchers check this on launch and stops with an explanation naming both, rather
than failing somewhere confusing.  Nothing is damaged and no mail is
touched; the mailbox is plain files and is readable anywhere.

Earlier versions recompiled themselves in that situation, which took a
few minutes and wrote to the drive on a machine somebody had only just
plugged it into.  It now says what is wrong and leaves the decision to
you.

## Troubleshooting

* **"this drive was built for a different kind of machine"** — see the
  section above.  The drive is fine; this host is the wrong shape for it.
* **"this drive has no interpreter"** — the drive was not generated
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
* \`$MAILBOX_NAME/source-code/\` — the daemon, its own Lua interpreter,
  its libraries, the C sources behind the compiled ones, and
  \`BUILD-NOTES.txt\` saying how those were built.  The launchers use
  this; you shouldn't need to go in.
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
info "    $DEST/$MAILBOX_NAME/source-code/  (the daemon and its libraries)"
info "    $DEST/$MAILBOX_NAME/  (config, inbox, outbox, attachments, contacts, hooks)"
echo ""
info "identity: $NAME"
info "port:     $PORT"
echo ""
warn "before first use on any host: forward port $PORT on that host's router."
echo ""
drive_eject_hint "$DEST"
