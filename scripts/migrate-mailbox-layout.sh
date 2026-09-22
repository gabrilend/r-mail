#!/bin/sh
# migrate-mailbox-layout.sh — move an existing mailbox to the current layout
#
# A mailbox used to be a directory of mail plus pointers to things kept
# somewhere else: its config in ~/.config/rmail/, and its hook scripts in the
# git checkout, shared with every other mailbox on the machine.  Both now live
# inside the mailbox they belong to.  See issues/382.
#
# The daemon does not.  One checkout runs every mailbox on a machine, and the
# service file is what says which mailbox a given daemon serves.  Only a
# mailbox on removable media carries a copy of the program, because there is
# no checkout at the far end, and the drive generator is what puts it there.
#
# This moves one existing mailbox across.  What it does, in order:
#
#   1. Copies the config out of ~/.config/rmail/ and into the mailbox, where
#      the symlink used to point outward.  The original is left in place.
#   2. Gives the mailbox its own copies of the hook scripts, and rewrites the
#      config's hook lines to point at them relatively.
#   2b. Removes the `mail =` line, which the daemon no longer reads.
#   3. Turns IP-change notices off, which is now the default everywhere: a
#      mailbox that can be picked up and run elsewhere should not announce
#      itself to every contact on arrival.
#   4. Removes a program-files/ copy if an earlier version of this script put
#      one there.
#
# It does NOT touch mail, contacts, sync state, attachments, or any hook
# script already inside the mailbox.  It does not stop or start anything, and
# it does not install service files — those are root-owned and this script
# never escalates.  It prints the service line that needs changing and leaves
# that to you.
#
# Safe to run twice: anything already in the new shape is reported and left.
#
# Usage:
#   scripts/migrate-mailbox-layout.sh ~/mail
#   scripts/migrate-mailbox-layout.sh ~/mail /path/to/checkout
#   DRY_RUN=1 scripts/migrate-mailbox-layout.sh ~/mail     # say, don't do
#
# Exit status is 0 on success, 1 if the mailbox could not be migrated.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${2:-$(cd "$SCRIPT_DIR/.." && pwd)}"

MAILBOX="${1:-}"
DRY_RUN="${DRY_RUN:-0}"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
err()  { printf "  \033[31merror\033[0m %s\n" "$*" >&2; }
warn() { printf "  \033[33m!\033[0m    %s\n" "$*"; }
info() { printf "       %s\n" "$*"; }
act()  { if [ "$DRY_RUN" = 1 ]; then printf "  would %s\n" "$*"; fi; }

if [ -z "$MAILBOX" ]; then
    err "usage: $0 <mailbox-directory> [checkout]"
    exit 1
fi

MAILBOX=$(echo "$MAILBOX" | sed "s|^~|$HOME|" | sed 's|/*$||')

if [ ! -d "$MAILBOX" ]; then
    err "no such mailbox: $MAILBOX"
    exit 1
fi
if [ ! -d "$MAILBOX/inbox" ] || [ ! -d "$MAILBOX/outbox" ]; then
    err "$MAILBOX has no inbox/ and outbox/ — is it really a mailbox?"
    exit 1
fi
if [ ! -f "$DIR/rmail.lua" ]; then
    err "no checkout at $DIR — pass one as the second argument"
    exit 1
fi

echo ""
echo "rmail mailbox layout migration"
echo "  mailbox:  $MAILBOX"
echo "  checkout: $DIR"
[ "$DRY_RUN" = 1 ] && echo "  DRY RUN — nothing will be written"
echo ""

# --------------------------------------------------------------------------
# 1. The config.
#
# The old layout left a symlink at <mailbox>/config pointing out to
# ~/.config/rmail/config-<slug>.  Replacing the symlink with a copy of what
# it pointed at is the whole move.  The original is deliberately left where
# it is: something may still be running against it, and deleting the file a
# live daemon read is not this script's decision to make.

CONFIG="$MAILBOX/config"

if [ -L "$CONFIG" ]; then
    _target=$(readlink -f "$CONFIG")
    if [ ! -f "$_target" ]; then
        err "$CONFIG is a symlink to $_target, which does not exist"
        exit 1
    fi
    if [ "$DRY_RUN" = 1 ]; then
        act "replace the symlink $CONFIG with a copy of $_target"
    else
        cp "$_target" "$CONFIG.migrated"
        rm "$CONFIG"
        mv "$CONFIG.migrated" "$CONFIG"
        ok "config is now a real file in the mailbox"
        info "  copied from $_target, which is left in place"
    fi
elif [ -f "$CONFIG" ]; then
    ok "config is already a real file in the mailbox"
else
    err "no config at $CONFIG — nothing to migrate from"
    exit 1
fi

# --------------------------------------------------------------------------
# 2. Hooks.
#
# Existing scripts in the mailbox are never overwritten — they are the ones
# somebody may have edited, which is the entire reason for giving each
# mailbox its own.  Only the missing ones are filled in from the checkout's
# defaults.

if [ "$DRY_RUN" = 1 ]; then
    act "copy default hook scripts into $MAILBOX/hooks/ where missing"
else
    mkdir -p "$MAILBOX/hooks"
    _added=0
    _kept=0
    for _h in "$DIR/scripts/hooks"/*.sh; do
        [ -f "$_h" ] || continue
        _dest="$MAILBOX/hooks/$(basename "$_h")"
        if [ -f "$_dest" ]; then
            _kept=$((_kept + 1))
        else
            cp "$_h" "$_dest"
            chmod +x "$_dest"
            _added=$((_added + 1))
        fi
    done
    ok "hooks: added $_added, left $_kept already there alone"
fi

# Rewrite the config's hook lines to the mailbox's own copies.  Only lines
# that still point into the checkout are touched; a hook somebody has already
# repointed at something of their own is left exactly as written.
rewrite_hook_line() {
    _key="$1"
    _current=$(grep "^[[:space:]]*$_key[[:space:]]*=" "$CONFIG" |
               sed 's/^[^=]*=[[:space:]]*//' | head -1)
    [ -n "$_current" ] || return 0
    # Matched on shape — anything under a `scripts/hooks/` directory — and
    # not on this checkout's own path.  A checkout is reachable by more
    # than one path more often than you would think: a bind mount, a
    # symlinked home directory, a move since the config was written.  On
    # the machine this was first run against, the config said
    # /home/ritz/programs/r-mail while the checkout answered to
    # /mnt/mtwo/programs/r-mail, and a prefix match recognised nothing at
    # all and silently left every hook pointing outside the mailbox.
    case "$_current" in
        */scripts/hooks/*)
            _base=$(basename "$_current")
            if [ ! -f "$MAILBOX/hooks/$_base" ] && [ "$DRY_RUN" != 1 ]; then
                warn "$_key names $_base, which is not in $MAILBOX/hooks/ — left alone"
                return 0
            fi
            if [ "$DRY_RUN" = 1 ]; then
                act "point $_key at ./hooks/$_base (was $_current)"
            else
                sed -i "s|^\([[:space:]]*$_key[[:space:]]*=[[:space:]]*\).*|\1./hooks/$_base|" "$CONFIG"
                HOOKS_REPOINTED=$((HOOKS_REPOINTED + 1))
            fi
            ;;
        ./hooks/*)
            HOOKS_ALREADY=$((HOOKS_ALREADY + 1))
            ;;
        *)
            warn "$_key points at $_current — left alone, it is not a default"
            ;;
    esac
}

HOOKS_REPOINTED=0
HOOKS_ALREADY=0
for _key in on_receive_raw on_receive on_package on_send on_delete on_update; do
    rewrite_hook_line "$_key"
done
if [ "$DRY_RUN" != 1 ]; then
    ok "config hook paths: repointed $HOOKS_REPOINTED, already relative $HOOKS_ALREADY"
fi

# --------------------------------------------------------------------------
# 2b. The dead `mail` key.
#
# Old configs name their mailbox with a `mail = /some/path` line.  The
# daemon ignores it now — a config lives in the mailbox it serves, so the
# directory the file is in already says which mailbox it is, and a line
# saying the same thing can only ever go on to say something different.
# Removed here rather than left, because a migration is exactly where a
# line that no longer means anything should stop being there.

_mail_line=$(grep -c "^[[:space:]]*mail[[:space:]]*=" "$CONFIG")
if [ "$_mail_line" -gt 0 ]; then
    if [ "$DRY_RUN" = 1 ]; then
        act "remove the now-ignored 'mail =' line"
    else
        _stated=$(grep "^[[:space:]]*mail[[:space:]]*=" "$CONFIG" |
                  sed 's/^[^=]*=[[:space:]]*//' | head -1)
        _stated=$(echo "$_stated" | sed "s|^~|$HOME|" | sed 's|/*$||')
        if [ -n "$_stated" ] && [ "$_stated" != "." ] && [ "$_stated" != "$MAILBOX" ]; then
            warn "that config's 'mail =' said $_stated, not $MAILBOX"
            warn "  the daemon ignores the line now and serves this directory."
            warn "  If the other path is the mailbox you wanted, stop and"
            warn "  migrate that one instead."
        fi
        sed -i '/^[[:space:]]*mail[[:space:]]*=/d' "$CONFIG"
        ok "removed the 'mail =' line the daemon no longer reads"
    fi
else
    ok "no 'mail =' line to remove"
fi

# --------------------------------------------------------------------------
# 3. IP-change notices off.
#
# Now the default everywhere, because every mailbox can be moved once it
# carries its own config, hooks and program.  An explicit `true` in an
# existing config is turned off here rather than left, so that migrated
# mailboxes and new ones behave alike.

_notify=$(grep "^[[:space:]]*notify_ip_change[[:space:]]*=" "$CONFIG" |
          sed 's/^[^=]*=[[:space:]]*//' | head -1)
if [ "$_notify" = "true" ]; then
    if [ "$DRY_RUN" = 1 ]; then
        act "turn notify_ip_change off (currently true)"
    else
        sed -i 's|^\([[:space:]]*notify_ip_change[[:space:]]*=[[:space:]]*\).*|\1false|' "$CONFIG"
        ok "turned IP-change notices off"
    fi
elif [ -n "$_notify" ]; then
    ok "IP-change notices already off"
else
    if [ "$DRY_RUN" = 1 ]; then
        act "add notify_ip_change = false"
    else
        printf '\nnotify_ip_change = false\n' >> "$CONFIG"
        ok "added notify_ip_change = false"
    fi
fi

# --------------------------------------------------------------------------
# 4. Any program copy left inside the mailbox.
#
# An earlier version of this script put the daemon and its libraries in
# <mailbox>/program-files/.  That was withdrawn: a mailbox on a machine
# runs the checkout's daemon, and a per-mailbox copy only meant every
# mailbox quietly held a snapshot that nothing kept current.  A mailbox
# on removable media still carries a copy, but the drive generator is
# what puts it there.
#
# Removed here so a mailbox migrated during that afternoon does not keep
# a stale daemon around looking like it might be the one in use.

if [ -d "$MAILBOX/program-files" ]; then
    if [ "$DRY_RUN" = 1 ]; then
        act "remove the leftover $MAILBOX/program-files/ ($(du -sh "$MAILBOX/program-files" | cut -f1))"
        info "  its service must point at $DIR/rmail.lua instead — see below"
    else
        rm -rf "$MAILBOX/program-files"
        ok "removed the leftover program-files/ copy"
        PROGRAM_COPY_REMOVED=1
    fi
else
    ok "no program copy inside the mailbox, which is right"
fi

# --------------------------------------------------------------------------
# What is left for a human.

if [ "$DRY_RUN" = 1 ]; then
    echo ""
    info "dry run finished — nothing was written"
    exit 0
fi

_name=$(grep "^[[:space:]]*name[[:space:]]*=" "$CONFIG" | sed 's/^[^=]*=[[:space:]]*//' | head -1)
_port=$(grep "^[[:space:]]*port[[:space:]]*=" "$CONFIG" | sed 's/^[^=]*=[[:space:]]*//' | head -1)

echo ""
ok "$MAILBOX now holds its own config and hooks"
info "  identity $_name, port $_port"
info "  the daemon it runs comes from the checkout, named by its service file"
echo ""
info "Its service needs to name this mailbox's config, and run the"
info "daemon out of the checkout:"
echo ""
echo "    $DIR/rmail.lua $CONFIG"
echo ""
if [ "${PROGRAM_COPY_REMOVED:-0}" = 1 ]; then
    warn "This mailbox had a program-files/ copy, now removed, so its"
    warn "  service may still be pointing at a daemon that is gone."
    warn "  Check the service file before restarting it."
    echo ""
fi
info "Nothing that was running has been stopped, and no mail, contacts or"
info "sync state was touched."
echo ""
