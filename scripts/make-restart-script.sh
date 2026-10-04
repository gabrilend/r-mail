#!/bin/sh
# make-restart-script.sh — build this machine's restart-mailboxes.sh from
# its template
#
# restart-mailboxes.sh restarts every mailbox's service after an update,
# from a list of service names kept at its top.  That list belongs to one
# machine, and git cannot ignore single lines of a tracked file, so the
# script itself is untracked: it is built from a tracked template,
# scripts/.templates/restart-mailboxes.sh, the way the documents are
# built from docs/.templates/.  (#622)
#
# The template holds one folded block per service manager (runit,
# systemd, openrc, nixos).  The built script, scripts/restart-mailboxes.sh,
# keeps only the block for the manager named here, with the program folder
# filled in.  An existing built script holds the owner's list, so it is
# left alone unless --force says to rebuild it -- and a rebuild carries
# the list over, so updating the template never loses anyone's mailboxes.
# The installer runs this when no built script exists yet.
#
# Usage:
#   scripts/make-restart-script.sh <manager>                 for this checkout
#   scripts/make-restart-script.sh <manager> /path           for another checkout
#   scripts/make-restart-script.sh --force <manager> [/path] rebuild an existing
#                                                            one, keeping its list
#
# <manager> is runit, systemd, openrc or nixos.
#
# Exit status: 0 built (or an existing one kept); 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
err()  { printf "  \033[31merror\033[0m %s\n" "$*" >&2; }
info() { printf "       %s\n" "$*"; }

FORCE=false
MANAGER=""
DIR=""
for _arg in "$@"; do
    case "$_arg" in
        --force) FORCE=true ;;
        -h|--help) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) err "unknown option: $_arg"; exit 1 ;;
        *)
            # the first plain argument is the manager, the second the folder
            if [ -z "$MANAGER" ]; then MANAGER="$_arg"
            elif [ -z "$DIR" ]; then DIR="$_arg"
            else err "too many arguments: $_arg"; exit 1
            fi ;;
    esac
done
DIR="${DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
DIR=$(echo "$DIR" | sed 's|/*$||')

TEMPLATE="$DIR/scripts/.templates/restart-mailboxes.sh"
BUILT="$DIR/scripts/restart-mailboxes.sh"

if [ ! -f "$TEMPLATE" ]; then
    err "no template at $TEMPLATE"
    exit 1
fi

# The managers the template knows are the names on its block markers, so
# a manager added to the template is accepted here with no other change.
KNOWN=$(sed -n 's/^# {{{ manager: \([a-z0-9-]*\)$/\1/p' "$TEMPLATE" | tr '\n' ' ' | sed 's/ $//')
if [ -z "$MANAGER" ]; then
    err "name the service manager: one of $KNOWN"
    exit 1
fi
case " $KNOWN " in
    *" $MANAGER "*) ;;
    *) err "the template has no block for '$MANAGER' (it has: $KNOWN)"; exit 1 ;;
esac

# An existing built script holds this machine's list.  Without --force it
# is kept as it is; with --force it is rebuilt, and its list is carried
# into the new one.
KEPT_LIST=""
if [ -f "$BUILT" ]; then
    if ! $FORCE; then
        ok "kept the existing $BUILT (its list is this machine's)"
        exit 0
    fi
    KEPT_LIST=$(sed -n 's/^MAILBOX_SERVICES="\(.*\)"$/\1/p' "$BUILT")
fi

# {{{ sed_escape
# The folder goes into a sed replacement, where | (the separator here),
# \ and & mean something; each is escaped so a path holding one comes
# through unchanged.
sed_escape() {
    printf '%s' "$1" | sed 's/[|\\&]/\\&/g'
}
# }}}

# Keep every line outside a manager block, and the lines of the chosen
# block; drop the other blocks whole, markers included.  A block runs
# from "# {{{ manager: X" to "# }}} manager: X" — its own closing marker,
# because the functions inside carry ordinary folds of their own.
esc_dir=$(sed_escape "$DIR")
awk -v keep="$MANAGER" '
    /^# \{\{\{ manager: / { block = $4; if (block == keep) print; next }
    /^# \}\}\} manager: / { if (block == keep) print; block = ""; next }
    block == "" || block == keep { print }
' "$TEMPLATE" |
    sed -e "s|@PROGRAM_DIR@|$esc_dir|" -e "s|@SERVICE_MANAGER@|$MANAGER|" \
        -e "s|^MAILBOX_SERVICES=\"\"\$|MAILBOX_SERVICES=\"$(sed_escape "$KEPT_LIST")\"|" > "$BUILT.new"

# Checked before it replaces anything: exactly one manager block, the
# right one, every placeholder filled, and the shell can read it.
_blocks=$(grep -c '^# {{{ manager: ' "$BUILT.new")
if [ "$_blocks" != 1 ] || ! grep -q "^# {{{ manager: $MANAGER\$" "$BUILT.new"; then
    err "the built script has $_blocks manager blocks, expected only '$MANAGER'"
    rm -f "$BUILT.new"
    exit 1
fi
if grep -q '@PROGRAM_DIR@\|@SERVICE_MANAGER@' "$BUILT.new"; then
    err "the built script still has an unfilled placeholder"
    rm -f "$BUILT.new"
    exit 1
fi
if ! sh -n "$BUILT.new"; then
    err "the built script does not parse"
    rm -f "$BUILT.new"
    exit 1
fi
chmod 755 "$BUILT.new"
mv "$BUILT.new" "$BUILT"
ok "built $BUILT for $MANAGER"
if [ -n "$KEPT_LIST" ]; then
    info "kept its list: $KEPT_LIST"
else
    info "the installer adds each mailbox it sets up; run with the list empty, it asks for the names"
fi
