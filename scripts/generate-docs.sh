#!/bin/sh
# generate-docs.sh — rebuild docs/ from docs/.templates/ without reinstalling
#
# The files in docs/ are build artefacts.  The source of truth is
# docs/.templates/, which holds the same documents with placeholder paths in
# them — `/home/you/mail`, `/home/you/programs/email` — that get replaced with
# wherever this machine actually put things.  install.sh does that expansion
# at the end of every install.
#
# That left no way to rebuild the docs after editing a template, short of
# re-running the whole installer against a working mail setup.  This script is
# that missing way.  It does exactly what the installer's docs step does,
# because it runs the installer's own routine: the two functions are lifted
# out of install.sh at run time rather than copied into here.  A copy would
# drift, and then this script would quietly produce different docs from the
# ones a real install produces.
#
# The docs quote real paths, including a mailbox path, so this needs to know
# which mailbox to write them for.  There is no registry of mailboxes to ask
# — each one holds its own config and none of them know about each other —
# so either name one or accept ~/mail.
#
# Usage:
#   scripts/generate-docs.sh                           # for ~/mail
#   RMAIL_MAIL_DIR=~/notes/rmail scripts/generate-docs.sh
#   scripts/generate-docs.sh /path/to/checkout         # some other checkout
#
# Exit status is 0 when the docs were written, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"

INSTALLER="$DIR/scripts/install.sh"

# The two paths the templates get expanded with.  MAIL_DIR is the one that
# genuinely varies; with several mailboxes on one machine the docs can only
# show one of them, so it shows this one.
ROOT="$DIR"
MAIL_DIR=$(echo "${RMAIL_MAIL_DIR:-$HOME/mail}" | sed "s|^~|$HOME|" | sed 's|/*$||')

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
err()  { printf "  \033[31merror\033[0m %s\n" "$*" >&2; }
info() { printf "       %s\n" "$*"; }

if [ ! -f "$INSTALLER" ]; then
    err "no install script at $INSTALLER"
    exit 1
fi

if [ ! -d "$MAIL_DIR" ]; then
    warn_missing=1
fi

echo ""
echo "rmail docs generation"
echo "  checkout: $ROOT"
echo "  mailbox:  $MAIL_DIR"
if [ "${warn_missing:-0}" = 1 ]; then
    info "  (that mailbox does not exist yet — the docs will still name it)"
fi
echo ""

# ---- lift the routines out of the installer -------------------------------
#
# Both are matched by an exact `name() {` line through the next line that is
# a lone `}` — which holds because install.sh indents every function body.
# If that ever stops being true the extraction fails loudly here rather than
# silently producing nothing.
LIFTED="/tmp/rmail/generate-docs-lifted.sh"
mkdir -p "$(dirname "$LIFTED")"
: > "$LIFTED"

for _fn in sed_escape_replacement generate_docs; do
    _before=$(wc -l < "$LIFTED")
    sed -n "/^${_fn}() {\$/,/^}\$/p" "$INSTALLER" >> "$LIFTED"
    _after=$(wc -l < "$LIFTED")
    if [ "$_before" -eq "$_after" ]; then
        err "could not lift $_fn out of install.sh"
        info "the function's shape changed — check how it is declared"
        exit 1
    fi
done
ok "lifted the expansion routines from install.sh ($(wc -l < "$LIFTED") lines)"

. "$LIFTED"

generate_docs || {
    err "docs generation failed"
    exit 1
}

_count=$(find "$ROOT/docs" -maxdepth 1 -name '*.md' | wc -l)
ok "wrote $_count files to $ROOT/docs/"
echo ""
