#!/bin/sh
# rpad — send a message with its words in a padded attachment, so its size is hidden (#902)
# Usage: rpad <mailbox> <draft> [<name>]
#
# <draft> is written like an outbox file: `to:` lines (and any `attach:`
# lines), a blank line, then the message.  rpad puts the message in
# <mailbox>/padded/<name>/message.padded-body, followed by the marker
#
#   -------------------------------------------------------------------------------
#       end of encrypted message. what follows is random data with no meaning.
#   -------------------------------------------------------------------------------
#
# and random bytes, up to a size that fills whole pieces of the mailbox's
# `attachment_chunk_size` (5 MiB unless the config says otherwise) less a
# fixed 4 KiB for the zip's own headers.  Then it writes
# <mailbox>/outbox/<name> with the draft's header lines, an `attach:` line
# for that file, and a short fixed body saying where the words are.
#
# On the wire every message then looks the same: the same short body, and
# one attachment of the same size in the same number of pieces, until the
# words outgrow a piece.  The receiver needs the two hooks in the encryption
# guide ("Sending the body as a padded attachment"), or it sees the short
# body and a file of noise.
#
# <name> is the outbox file's name, the draft's own name by default.  The
# draft is left where it is.  Keep padded/<name>/ until every recipient has
# the attachment: a big one is sent from where it lies.
#
# Exit status 0 when the outbox file was written, 1 otherwise.

MARK_TEXT="    end of encrypted message. what follows is random data with no meaning."
DASHES="-------------------------------------------------------------------------------"
STUB="This message was sent padded (#902): its words are in the attached file,
message.padded-body, and the receiver's hooks put them here when it arrives.
If you can read this after the file has arrived, those hooks are not set up:
see \"Sending the body as a padded attachment\" in the encryption guide."

die() { printf 'rpad: %s\n' "$*" >&2; exit 1; }

[ $# -ge 2 ] || die "usage: rpad <mailbox> <draft> [<name>]"
mailbox=${1%/}
draft=$2
name=${3:-$(basename "$draft")}

[ -d "$mailbox/outbox" ] || die "no outbox in $mailbox"
[ -f "$draft" ] || die "no draft at $draft"
case "$name" in ""|.*|*/*) die "not a name for an outbox file: $name" ;; esac
[ -e "$mailbox/outbox/$name" ] && die "outbox/$name already exists"

# the piece size the daemon will cut the attachment into
chunk=$(sed -n 's/^[[:space:]]*attachment_chunk_size[[:space:]]*=[[:space:]]*"\{0,1\}\([0-9][0-9]*\)"\{0,1\}[[:space:]]*$/\1/p' \
    "$mailbox/config" 2>/dev/null | tail -n 1)
chunk=${chunk:-5242880}
[ "$chunk" -ge 1024 ] || die "attachment_chunk_size $chunk is too small to pad to"
# room for the zip's headers, so the zip still fills the same pieces
reserve=4096
[ "$chunk" -ge 16384 ] || reserve=$((chunk / 4))

# the header block: leading to:/attach: lines, then one optional blank line
headers=0
has_to=no
while IFS= read -r line; do
    case "$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')" in
        to:*)     headers=$((headers + 1)); has_to=yes ;;
        attach:*) headers=$((headers + 1)) ;;
        *) break ;;
    esac
done < "$draft"
[ "$has_to" = yes ] || die "the draft has no to: line"
skip=$headers
if [ "$(sed -n "$((headers + 1))p" "$draft")" = "" ]; then skip=$((headers + 1)); fi

dir="$mailbox/padded/$name"
file="$dir/message.padded-body"
mkdir -p "$dir" || die "could not make $dir"

# the words, byte for byte, then the marker
tail -n +"$((skip + 1))" "$draft" > "$file" || die "could not write $file"
printf '\n%s\n%s\n%s\n' "$DASHES" "$MARK_TEXT" "$DASHES" >> "$file"
used=$(wc -c < "$file")
pieces=$(( (used + reserve + chunk - 1) / chunk ))
target=$(( pieces * chunk - reserve ))
if [ "$target" -gt "$used" ]; then
    head -c "$((target - used))" /dev/urandom >> "$file" || die "could not pad $file"
fi

# the outbox file, written beside the outbox and moved in whole, so the
# daemon never reads half of it
tmp="$mailbox/.rpad-$$"
{
    head -n "$headers" "$draft"
    printf 'attach: %s\n\n%s\n' "$file" "$STUB"
} > "$tmp" || { rm -f "$tmp"; die "could not write the outbox file"; }
mv "$tmp" "$mailbox/outbox/$name" || { rm -f "$tmp"; die "could not move it into the outbox"; }
printf 'outbox/%s: %d bytes of words in %d piece(s) of %d\n' "$name" \
    "$(( used - ${#DASHES} * 2 - ${#MARK_TEXT} - 4 ))" "$pieces" "$chunk"
