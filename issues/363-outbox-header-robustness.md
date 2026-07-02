# #363 — Tolerate blank lines in the outbox header, log missing attach: files, and strip quotes from attach: paths

## Problem

Three related ways an outbox message can silently do the wrong thing:

### (a) Blank line inside the header block swallows `attach:` into the body

`parse_outbox_file` (`rmail.lua:2440`) builds the header block by
scanning lines from the top and breaks on the **first line that isn't
`to:` or `attach:`**. A blank line counts as "not a header line", so
an outbox file like:

```
to: alice

attach: /home/alice/pictures/cat.jpg

body body body
```

parses as one `to:`, zero attachments, and a body that starts with
`attach: /home/alice/pictures/cat.jpg`. The sender's daemon then
delivers that string as plain message text, and the receiver sees the
raw `attach:` line at the top of their inbox file. No attachment is
ever queued, no consent form is ever sent, and the sender logs no
error because from the daemon's point of view this is a perfectly
valid message with a plain body.

This actually happened: a user sent a message with a stray blank line
after `to:` and the recipient got `attach: <path>` as body text
instead of a real attachment (session of 2026-04-17).

### (b) `attach:` path refers to a file that doesn't exist

When the daemon *does* recognize an `attach:` line and the path
doesn't exist, the pipeline fails quietly. `measure_size` returns 0
or nil, `compress_attachment` can't read the source, `zip_path` comes
back nil, and the for-loop in `sync_outbox` just skips the
attachment. No log line names the missing path. The recipient gets
the body but no attachment, no consent form, and no indication
anything went wrong. The sender has no indication either.

Both of these produce the same end-user symptom — "I attached a file
but the recipient didn't see it" — with no diagnostic trail. The
sender has to notice by staring at their own outbox file.

### (c) Quoted path in an `attach:` line is taken literally

The extractor at `rmail.lua:2400` captures everything after `attach:`
up to end-of-line:

```lua
local afp = line:match("^[Aa][Tt][Tt][Aa][Cc][Hh]:%s*(.-)%s*$")
```

It does not strip surrounding quotes.  So an `attach:` line written
as:

```
attach: "/home/ritz/music/the-barbarian/CD 1/09-Theology.mp3"
```

yields the literal string `"/home/ritz/music/.../Theology.mp3"` —
`"` characters included as part of the path.  `zip` then looks for a
file whose name starts with `"` and fails, `compress_attachment`
returns nil, and the pipeline drops into the same silent-failure
mode as (b).

The matching parser in `load_contacts` (around line 600) *does*
strip surrounding quotes, so users reasonably expect the outbox
parser to do the same.  The inconsistency is the bug.

Quoting isn't semantically required — the parser already reads to
end-of-line, so spaces in paths work unquoted — but users do quote
out of shell-habit, and it should just work.

## Proposed fix

### (a) Header parser: skip blank lines inside the header block

Change the loop in `parse_outbox_file` (`rmail.lua:2440-2450`) from
"break on first non-header line" to:

- Skip blank lines (including whitespace-only lines).
- Accumulate `to:` / `attach:` lines.
- Break on the first line that is non-blank AND not `to:` / `attach:`.

A blank line between `to:` and `attach:` stays in the file as the
user wrote it (we don't re-normalize), but it no longer terminates
the header. The body starts at the first line that is neither blank
nor a recognized header.

Edge case: a file that is ALL blank + header lines with no body at
all should still parse. `body` ends up as `""`, which is fine — the
existing "too small to send" guards are unchanged.

Make sure `remove_recipient_from_file` (`rmail.lua:1738`) and
`remove_attach_from_file` (`rmail.lua:2450`) use the same new rule.
Otherwise `remove_*` would clip the header too early and leave
orphan `attach:` lines at the top of the body.

### (b) Missing-file detection with a visible marker

When `sync_outbox` is about to queue a new attachment for an
existing recipient (`rmail.lua:3426`), check `file_exists(filepath)`
first. If it doesn't exist:

- Log: `attach: file not found: <path> (in <outbox-file>)`.
- Mark the outbox file with a `// MISSING ATTACHMENT:` line, mirroring
  the existing `// UNKNOWN CONTACT:` pattern (`rmail.lua:3409-3419`).
  The marker goes right after the offending `attach:` line so the
  user can see both together.
- Skip queuing the transfer. Don't retry on every cycle — the marker
  line is the signal to the user that they need to fix it.

De-dup the marker: if we've already marked this line (check for the
marker on the line immediately after the attach), don't add a second
one.

When the user fixes the path (edits the `attach:` line), the marker
is stale. Simplest rule: a `//` comment line is ignored by
`parse_outbox_file` and removed during the next file-rewrite cycle
if the attach below it now exists. Alternative: leave marker removal
up to the user. Start with "leave it to the user" — they see it,
they delete it. If this becomes annoying we can auto-clean later.

### (c) Strip a single layer of surrounding quotes from attach: paths

In the same places the path is extracted:

- `rmail.lua:2360` (glob expansion check)
- `rmail.lua:2400` (per-recipient attachment list)
- `rmail.lua:2531` (in `remove_attach_from_file`)

After the existing `line:match("^[Aa][Tt][Tt][Aa][Cc][Hh]:%s*(.-)%s*$")`
capture, unwrap one layer of surrounding double or single quotes:

```lua
local unquoted = afp:match('^"(.*)"$') or afp:match("^'(.*)'$")
if unquoted then afp = unquoted end
```

Mirrors the quote handling in `load_contacts`.  Extract this into a
small helper (e.g. `_extract_attach_path(line)`) so the three call
sites share one implementation.

**No write-back normalisation.**  The parser strips quotes on read;
it does not edit the user's outbox file just to remove them.  This
matches the "don't reformat blanks" non-goal below — the daemon
leaves the file as the user wrote it.  If the user later edits the
line (e.g. via glob expansion in #362, or a #363 marker being added),
the rewriter's own output is naturally unquoted because it emits
`"attach: " .. abs_path` with no quotes.  Over time a file touched
by the daemon will drift to unquoted paths; untouched lines stay as
the user wrote them.

**Globs.**  The glob matcher at `rmail.lua:2362` operates on the
extracted path string.  Stripping quotes before matching means
`attach: "/home/ritz/photos/*.jpg"` globs correctly — the `*` is
passed as a literal character in the unquoted path to the matcher.

### Non-goal: don't reformat the user's file just to normalize blanks

Part (a) is purely a *parser* change. We don't want the daemon to
start deleting blank lines the user inserted for readability between
`attach:` and the body. Keep the file on disk as the user wrote it
(except when glob expansion from #362 or the #363 marker requires a
rewrite).

## Relationship to #362

#362 rewrites the outbox file to expand `attach:` globs. #363 makes
the header parser more forgiving and adds visible error markers.
They touch the same function (`parse_outbox_file`) and the same set
of helpers (`remove_recipient_from_file`, `remove_attach_from_file`),
so land them in sequence and re-read each after the other to make
sure the header-scanning rules stay consistent across all three.

## Source

Diagnosed from a real message on 2026-04-17: received
`~/mail/inbox/atch-test` contained the raw `attach:` line as its
first body line, because the sender had a blank line between `to:`
and `attach:`. Sender's daemon logged no error.

Part (c) added 2026-04-18 after another real-message case on sorelu:
`~/mail/outbox/music-for-you` had `attach: "<path>"` with the path
in double quotes; every sync cycle logged `failed to compress <path>`
with a confusing `/tmp/rmail-<uuid>.zip: No such file or directory`
from the post-zip `wc -c` probe.  Root cause was the literal quotes
staying in the path.

## Status

Open.
