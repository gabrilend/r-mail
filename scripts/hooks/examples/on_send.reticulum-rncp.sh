#!/bin/sh
# on_send.reticulum-rncp.sh — also hand each message to Reticulum's rncp (#904)
#
# An example, not installed: install.sh copies only scripts/hooks/*.sh into
# a mailbox, never this folder.  To use it, copy it over your mailbox's
# hooks/on_send.sh (or point `on_send` in the config at a copy) and give
# each contact who runs Reticulum a field naming their rncp receiver:
#
#   alice.reticulum = 256320d405d6d525d1e9
#
# rmail itself knows nothing of Reticulum.  This hook sends a copy of each
# message to such a contact with `rncp <file> <destination>`, and prints
# nothing, so rmail still sends the message over IP as written: the mesh
# copy goes *as well*, not instead.  A contact may therefore get a message
# twice, once each way; nothing here, and nothing in rmail, joins the two.
#
# What it needs, all of it yours to set up:
#   - Reticulum, with `rncp` on the daemon's PATH (or RNCP set to it)
#   - rmail's helpers/rfield.sh on the PATH (or RFIELD set to it)
#   - the contact running `rncp` in receive mode, allowing your identity;
#     see their rncp's own help, which differs between versions
#
# on_send runs each time the daemon prepares a message for a contact, and
# for a contact it cannot reach that is every pass that tries again.  So
# this hook keeps a record, one empty file per message it has handed over
# (named by the sha-256 of recipient, subject and body), and does not hand
# the same message over twice.  An edit has a new body, so it goes again.
#
# Arguments (rmail's on_send): $1 recipient, $2 subject, the body on stdin.
# Environment, all optional:
#   RNCP            the rncp to run (default: rncp)
#   RFIELD          the rfield.sh to run (default: rfield.sh)
#   RMAIL_CONTACTS  the contacts file (default: ../contacts beside this
#                   hook's folder, which is where a mailbox keeps it)
#   RETICULUM_SENT  where the record is kept (default: .reticulum-sent
#                   beside this hook)
#
# Whatever goes wrong here -- no field, no rncp, rncp failing -- the hook
# exits 0 and prints nothing, so the message still goes over IP unchanged.

recipient=$1
subject=$2
here=$(cd "$(dirname "$0")" && pwd)
RNCP=${RNCP:-rncp}
RFIELD=${RFIELD:-rfield.sh}
CONTACTS=${RMAIL_CONTACTS:-$here/../contacts}
SENT=${RETICULUM_SENT:-$here/.reticulum-sent}

note() { echo "on_send (reticulum): $*" >&2; }

# The body first, whole: stdin is the only place a long one is given.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rmail-rncp-XXXXXX") || exit 0
cat > "$tmp/body"

dest=$("$RFIELD" "$CONTACTS" "$recipient" reticulum 2>/dev/null)
if [ -z "$dest" ]; then
    rm -rf "$tmp"
    exit 0          # not a Reticulum contact: IP only, as always
fi
case "$dest" in
    *[!0-9a-fA-F]*)
        note "$recipient.reticulum is not a hexadecimal hash: $dest"
        rm -rf "$tmp"; exit 0 ;;
esac
if ! command -v "$RNCP" >/dev/null 2>&1; then
    note "no $RNCP to run; $recipient gets this over IP only"
    rm -rf "$tmp"; exit 0
fi

# one record per message: recipient, subject and body, hashed
key=$( { printf '%s\n%s\n' "$recipient" "$subject"; cat "$tmp/body"; } | sha256sum | cut -d' ' -f1)
mkdir -p "$SENT"
if [ -e "$SENT/$key" ] || [ -e "$SENT/$key.sending" ]; then
    rm -rf "$tmp"
    exit 0
fi

# The file is named after the subject, which is what the contact sees.
name=$(printf '%s' "$subject" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-80)
[ -n "$name" ] || name=message
mv "$tmp/body" "$tmp/$name.txt"

# Over a radio link a transfer can take minutes, and the daemon waits for
# this hook, so rncp runs in the background.  The ".sending" mark stops a
# second copy meanwhile; it becomes the record if rncp succeeds, and is
# removed if it fails, so a later pass tries again.
: > "$SENT/$key.sending"
(
    if "$RNCP" "$tmp/$name.txt" "$dest" > "$tmp/rncp.out" 2>&1; then
        mv "$SENT/$key.sending" "$SENT/$key"
    else
        rm -f "$SENT/$key.sending"
        note "rncp to $recipient failed: $(tail -n 1 "$tmp/rncp.out")"
    fi
    rm -rf "$tmp"
) < /dev/null > /dev/null &
# (only stdout is closed: rmail reads it until it ends, so a background
# job holding it would hold the daemon; stderr goes to the daemon's log)
exit 0
