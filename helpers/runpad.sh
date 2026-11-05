#!/bin/sh
# runpad — put the words of a padded attachment back into its message (#902)
# Usage: runpad <padded-file> <inbox-file>
#
# The receiving half of rpad.sh, meant to be called from an on_package hook
# with its $3 and $4.  Finds the last
#
#   -------------------------------------------------------------------------------
#       end of encrypted message. what follows is random data with no meaning.
#   -------------------------------------------------------------------------------
#
# in <padded-file>, writes everything before it into <inbox-file> (in
# place, so the file keeps its name and everything that knows it), and
# removes <padded-file>.  The last marker, not the first: a message that
# quotes the marker keeps every word, and random bytes do not spell it.
#
# With no inbox file (the message was deleted before its file arrived) the
# words are written beside the padded file, as <padded-file>.txt.
#
# Exit status 0 when the words were put back; 1, with nothing changed, when
# the file has no marker or cannot be read.

MARK_TEXT="    end of encrypted message. what follows is random data with no meaning."
DASHES="-------------------------------------------------------------------------------"

die() { printf 'runpad: %s\n' "$*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: runpad <padded-file> <inbox-file>"
file=$1
inbox=$2
[ -f "$file" ] || die "no file at $file"

# where the marker's middle line starts, the last time it does
at=$(LC_ALL=C grep -a -b -o -F -- "$MARK_TEXT" "$file" | tail -n 1 | cut -d: -f1)
[ -n "$at" ] || die "$file has no end-of-message marker"
before=$(( ${#DASHES} + 2 ))        # "\n" dashes "\n" before that line
words=$(( at - before ))
[ "$words" -ge 0 ] || die "$file has a broken marker"

tmp=$(mktemp "${file%/*}/.runpad.XXXXXX") || die "no temporary file beside $file"
expect=$(mktemp "${file%/*}/.runpad.XXXXXX") || { rm -f "$tmp"; die "no temporary file"; }
printf '\n%s\n' "$DASHES" > "$expect"
head -c "$at" "$file" | tail -c "$before" > "$tmp"
if ! cmp -s "$tmp" "$expect"; then
    rm -f "$tmp" "$expect"
    die "$file has a broken marker"
fi
rm -f "$expect"

head -c "$words" "$file" > "$tmp" || { rm -f "$tmp"; die "could not read $file"; }
if [ -n "$inbox" ] && [ -f "$inbox" ]; then
    cat "$tmp" > "$inbox" || { rm -f "$tmp"; die "could not write $inbox"; }
    rm -f "$tmp"
else
    mv "$tmp" "$file.txt" || { rm -f "$tmp"; die "could not write $file.txt"; }
fi
rm -f "$file"
