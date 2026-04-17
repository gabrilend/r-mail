# #363 — Tolerate blank lines in the outbox header, and log missing attach: files

## Problem

Two related ways an outbox message can silently do the wrong thing:

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

## Status

Open.
