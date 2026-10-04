#!/bin/sh
# test-service-templates.sh — check the service files and the service guide
# that the installer builds from templates
#
# The installer writes one service file per mailbox, for whichever service
# manager the machine runs (systemd, runit, OpenRC, NixOS).  Since
# 2026-10-04 (#614) each kind is a template in scripts/.templates/services/
# with @NAME@ placeholders, filled in by the installer, and the service
# guide built into docs/ keeps only this machine's manager's section.
#
# This lifts the installer's own filling and docs routines out of
# scripts/install.sh (the way generate-docs.sh does, so what is tested is
# what runs) and checks, in a scratch folder:
#
#   templates     every template fills with no placeholder left; values
#                 holding | & and \ come through unchanged; each file names
#                 the mailbox's config, its log and its program
#   unfillable    a template asking for a value the installer does not
#                 know stops the fill, and leaves no file behind
#   guide         built for each manager, service.md has that manager's
#                 section and no other, the shared sections, and no markers
#                 left; built for "unknown", it has all four
#   detection     scripts/detect-service-manager.sh prints one known word
#
# Usage:
#   scripts/test-service-templates.sh          # use the enclosing checkout
#   scripts/test-service-templates.sh /path    # use some other checkout
#
# Exit status is 0 when every case passes, 1 otherwise.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIR="${1:-$(cd "$SCRIPT_DIR/.." && pwd)}"
INSTALLER="$DIR/scripts/install.sh"
WORK="/tmp/rmail/tests/service-templates"

ok()   { printf "  \033[32mok\033[0m   %s\n" "$*"; }
fail() { printf "  \033[31m--\033[0m   %s\n" "$*"; }
FAILURES=0
note_fail() { fail "$*"; FAILURES=$((FAILURES + 1)); }

echo ""
echo "rmail service templates test"
echo "  checkout: $DIR"
echo "  scratch:  $WORK"
echo ""

rm -rf "$WORK"
mkdir -p "$WORK"

# ---- the installer's routines, lifted -------------------------------------
LIFTED="$WORK/lifted.sh"
: > "$LIFTED"
for _fn in sed_escape_replacement fill_service_template generate_docs; do
    _before=$(wc -l < "$LIFTED")
    sed -n "/^${_fn}() {\$/,/^}\$/p" "$INSTALLER" >> "$LIFTED"
    if [ "$(wc -l < "$LIFTED")" -eq "$_before" ]; then
        note_fail "could not lift $_fn out of install.sh"
        exit 1
    fi
done
# the helpers the routines call, quiet versions
err()  { echo "error: $*" >> "$WORK/errors"; }
info() { echo "$*" >> "$WORK/info"; }
. "$LIFTED"

# Values with the characters a replacement can trip on: | (the separator),
# & (the whole match) and \ (an escape).
ROOT="$DIR"
RMAIL_MAIL='/tmp/a&b|c\d/mail'
CONFIG_FILE='/tmp/a&b|c\d/mail/config'
RMAIL_SERVICE="rmail-tmp-a-b-c-d-mail"
RMAIL_SERVICE_LOG="/tmp/rmail-tmp-a-b-c-d-mail.log"
LUA_BIN="/usr/bin/lua5.4"
NIX_PORT=8025

echo "templates"
for t in "$DIR"/scripts/.templates/services/*; do
    name=$(basename "$t")
    out="$WORK/$name"
    # fill_service_template exits on failure; run it in a subshell
    if ! ( fill_service_template "$name" "$out" ); then
        note_fail "$name: could not be filled ($(cat "$WORK/errors" 2>/dev/null))"
        continue
    fi
    if grep -q '@[A-Z_]*@' "$out"; then
        note_fail "$name: a placeholder is left"
    elif ! grep -qF "$CONFIG_FILE" "$out"; then
        note_fail "$name: the config path did not come through unchanged"
    elif ! grep -qF "$RMAIL_SERVICE_LOG" "$out"; then
        note_fail "$name: does not name the service's log"
    elif ! grep -qF "rmail.lua" "$out"; then
        note_fail "$name: does not name the program"
    else
        ok "$name: filled, | & and \\ intact, names config, log and program"
    fi
done

echo "unfillable"
mkdir -p "$WORK/fake-root/scripts/.templates/services"
printf 'value = @NOT_A_KNOWN_VALUE@\n' > "$WORK/fake-root/scripts/.templates/services/bad"
if ( ROOT="$WORK/fake-root"; fill_service_template bad "$WORK/bad-out" ) 2>/dev/null; then
    note_fail "a template with an unknown placeholder was accepted"
elif [ -e "$WORK/bad-out" ]; then
    note_fail "the half-filled file was left behind"
else
    ok "an unknown placeholder stops the fill and leaves no file"
fi

echo "guide"
# {{{ build_guide <manager>
# Builds the docs into a scratch folder holding only the service guide's
# template, for one manager, and prints the path of the built guide.
build_guide() {
    _r="$WORK/docs-$1"
    mkdir -p "$_r/docs/.templates"
    cp "$DIR/docs/.templates/service.md" "$_r/docs/.templates/"
    ( ROOT="$_r"; MAIL_DIR="/home/you/mail"; INIT_SYSTEM="$1"; generate_docs )
    echo "$_r/docs/service.md"
}
# }}}
HEADINGS="## systemd|## runit|## OpenRC|## NixOS"
for m in systemd runit openrc nixos; do
    g=$(build_guide "$m")
    count=$(grep -cE "^($HEADINGS)\$" "$g")
    case "$m" in
        systemd) want="## systemd" ;;
        runit)   want="## runit" ;;
        openrc)  want="## OpenRC" ;;
        nixos)   want="## NixOS" ;;
    esac
    if [ "$count" = 1 ] && grep -qx "$want" "$g" \
       && grep -qx "## Running multiple instances" "$g" && grep -qx "## Logging" "$g" \
       && ! grep -q "manager:" "$g"; then
        ok "$m: its own section only, the shared ones kept, no markers"
    else
        note_fail "$m: $count manager sections, or a shared section or marker wrong"
    fi
done
: > "$WORK/info"
g=$(build_guide unknown)
if [ "$(grep -cE "^($HEADINGS)\$" "$g")" = 4 ] && ! grep -q "manager:" "$g" \
   && grep -q "no service manager found" "$WORK/info"; then
    ok "unknown: all four sections, and it says so"
else
    note_fail "unknown: did not keep all four sections, or did not say so"
fi

echo "guide examples"
# The guide's example files are made from the templates; one that no
# longer matches means a template was changed without re-running the tool.
if "$DIR/scripts/fill-guide-examples.lua" --check "$DIR" > "$WORK/check.out" 2>&1; then
    ok "every example in the guide matches its template"
else
    note_fail "$(head -1 "$WORK/check.out")"
fi
g=$(build_guide runit)
if grep -q '^<!-- .* example' "$g"; then
    note_fail "an example marker is left in the built guide"
elif grep -q "^exec chpst -u YOURUSER " "$g"; then
    ok "the built guide shows the runit example, without its markers"
else
    note_fail "the built guide does not show the runit example"
fi

echo "detection"
word=$("$DIR/scripts/detect-service-manager.sh")
case "$word" in
    nixos|systemd|runit|openrc|unknown) ok "this machine: $word" ;;
    *) note_fail "the detection printed '$word'" ;;
esac

rm -rf "$WORK"

echo ""
if [ "$FAILURES" -eq 0 ]; then
    printf "  \033[32mall cases passed\033[0m\n"
    exit 0
fi
printf "  \033[31m%d case(s) failed\033[0m\n" "$FAILURES"
exit 1
