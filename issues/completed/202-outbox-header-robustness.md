# #202 — Tolerate blank lines in the outbox header, log missing attach: files, and strip quotes from attach: paths

## Status

Completed 2026-09-23.  Part (a) and part (b) were built in April 2026
(commit eafbf29).  Part (c) was written into this issue in July 2026
(commit 831195f) but not built until September 2026.  The September
pass (commit aad3f4c) also fixed part (b) for `~` paths and made the
missing-file note clear itself on already-delivered messages too.
Verified by `scripts/test-outbox-headers.sh`, which runs the real daemon
against throwaway mailboxes and passes all its checks: blank lines,
missing files (undelivered, delivered and `~` paths) and quoted paths.
The note clearing on an already-delivered message was also checked by
hand on 2026-09-23 with a quoted `~` path.  That run is not yet part of
the script.

## Current Behavior

### (a) Blank lines inside the header

The header of an outbox file is the run of `to:` and `attach:` lines at
the top.  Blank lines, whitespace-only lines and `//` note lines may sit
anywhere among them.  They are kept in the file exactly as written but
do not end the header.  The header ends at the first line that is none of
`to:`, `attach:`, blank or `//`.  That line is where the message body
starts.  A file that is all header and blank lines, with no body, still
parses (body is empty).  The header is read the same way when a recipient
is struck out (`remove_recipient_from_file`) and when a finished
attachment is struck out (`remove_attach_from_file`), so neither leaves
orphan `attach:` lines at the top of the body.

### (b) Missing attachment files

Before sending anything for an `attach:` line, `sync_outbox` checks
that the file exists.  When it does not:

- The line `// MISSING ATTACHMENT: <full path> — file not found` is
  written directly under the offending `attach:` line.  It mirrors the
  `// UNKNOWN CONTACT:` note.  The path in the note is the expanded one,
  with `~` resolved and quotes removed.
- The log says `attach: file not found: <path> (in <outbox file>)`.
- Nothing is queued for that file.
- The note is written once.  If it is already in the file, later syncs
  neither add a second one nor log again.  Only writing the note logs.

What happens to the message depends on whether it has been delivered:

- **Not yet delivered:** the message body is held back until every
  attached file exists.  Sent early, the recipient would get text that
  promises a file which never follows, or which has not finished
  uploading from a phone yet.
- **Already delivered:** only the missing attachment waits.

Once the file appears, the next sync removes the note, logs `attach:
found <path>, cleared its missing-attachment marker`, and carries on:
the message is delivered, or the attachment is queued.  This happens
for both delivered and undelivered messages.  **This goes further than
this issue first planned.**  The April plan (see Intended Behavior) was
to leave the note for the person to delete.  The daemon now removes it,
because a note left behind keeps saying "file not found" next to a file
that is being sent.

### (c) Quoted paths

People quote paths out of shell habit:
`attach: "/home/ritz/music/the-barbarian/CD 1/09-Theology.mp3"`.  One
layer of matching double or single quotes is taken off wherever an
`attach:` path is read:

- the wildcard check and expansion (#204), so a quoted wildcard expands;
- the per-recipient attachment list;
- the missing-file note;
- the strike-out of a finished attachment.

The daemon never rewrites the file just to remove the quotes.  The
quotes stay on the person's line, and the missing-file note names the
unquoted path.  A line the daemon writes for its own reasons, such as
a wildcard expansion, comes out unquoted anyway.  So a file the daemon
has touched slowly drifts to unquoted paths, and untouched lines stay
as written.

## Intended Behavior

Three ways an outbox message could silently do the wrong thing.  All
three show the person the same symptom: "I attached a file but the
recipient didn't see it", and they leave no trail to diagnose it by.
The sender had to notice by staring at their own outbox file.

### (a) Blank line inside the header swallowed `attach:` into the body

`parse_outbox_file` used to build the header by scanning from the top
and stopping at the first line that was not `to:` or `attach:`.  A
blank line counted as "not a header line", so this file:

```
to: alice

attach: /home/alice/pictures/cat.jpg

body body body
```

parsed as one `to:`, zero attachments, and a body starting with
`attach: /home/alice/pictures/cat.jpg`.  The daemon delivered that as
plain text; the receiver saw the raw `attach:` line at the top of their
inbox file.  No attachment was queued, no consent form sent, and nothing
was logged, because to the daemon it was a valid plain message.  This
really happened (session of 2026-04-17).

The plan: skip blank and whitespace-only lines, collect `to:` and
`attach:` lines, and stop at the first line that is non-blank and not
a header line.  Blank lines stay in the file as written.  Apply the
same rule in `remove_recipient_from_file` and `remove_attach_from_file`,
or those would cut the header short and leave orphan `attach:` lines.

### (b) `attach:` path to a file that does not exist

The pipeline used to fail quietly: `measure_size` returned 0 or nil,
`compress_attachment` could not read the source and gave no compressed
copy, and the loop in `sync_outbox` skipped the attachment.  No log line
named the missing path.  The recipient got the body without the
attachment, and neither side was told.

The plan (April 2026): check the file exists before queuing.  If it does
not:

- log it;
- write a `// MISSING ATTACHMENT:` line under the `attach:` line,
  mirroring the `// UNKNOWN CONTACT:` pattern;
- queue nothing;
- do not retry every cycle, because the note is the person's signal;
- do not write the note twice.

On removing a stale note, the April text said: "Simplest rule: a `//`
comment line is ignored by `parse_outbox_file` and removed during the
next file-rewrite cycle if the attach below it now exists.  Alternative:
leave marker removal up to the user.  Start with 'leave it to the user'
— they see it, they delete it.  If this becomes annoying we can auto-clean
later."  It did become a problem, because a note left behind is false.
The daemon now cleans it up automatically (see Current Behavior).

### (c) Quoted path taken literally

The `attach:` reader captured everything after `attach:` to the end of
the line, quotes included.  `zip` then looked for a file whose name
started with `"` and failed.  `compress_attachment` gave no copy, and
the pipeline fell into the same silent failure as (b).  The contacts
file reader (`load_contacts`) already removes surrounding quotes, so
people reasonably expected the outbox reader to do the same.  The
inconsistency was the bug.  Quoting is not needed, since spaces in
paths work unquoted, but people quote out of shell habit and it should
just work.

The plan: take off one layer of surrounding double or single quotes,
the same way `load_contacts` does.  Put this in one small shared helper
used everywhere a path is read.  Never rewrite the file just to remove
quotes.

### Non-goal: don't reformat the person's file to normalise blanks

Part (a) is purely a change to how the file is read.  The daemon must
not delete blank lines the person put in for readability.  The file on
disk changes only when a wildcard is expanded (#204) or a note is
written or removed.

## Suggested Implementation Steps

All in `rmail.lua`.

1. **Header scanner (part a).**  In the "outbox header scanning (#202)"
   section, before `remove_recipient_from_file`:
   - `_is_transparent_header_line(line)` is true for blank,
     whitespace-only and `//` lines.
   - `_scan_outbox_header(text)` returns the header lines (transparent
     ones included, verbatim) and the body text from the first line
     that is none of `to:`, `attach:` or transparent.
   - `parse_outbox_file`, `remove_recipient_from_file` and
     `remove_attach_from_file` all use it.  The two strike-out functions
     write back the header lines they kept, followed by the body.

   Decision: `//` lines are treated as transparent too, not only blank
   lines.  Without that, the daemon's own note would end the header and
   push the following `attach:` lines into the body.  The cost is that a
   body whose first line starts with `//` is read as part of the header.
2. **Shared path reader (part c).**  `_extract_attach_path(line)`, just
   above `_list_dir_files`, returns the text after `attach:`, trimmed,
   with one layer of matching `"…"` or `'…'` removed, or nil for a line
   that is not an `attach:` line.  It leaves `~` alone because the
   wildcard check needs the path before expansion.  Callers:
   - the wildcard pass in `parse_outbox_file`;
   - the per-recipient list in `parse_outbox_file`, which expands `~`
     on the result;
   - `mark_missing_attachment`;
   - `remove_attach_from_file`.

   The last two compare the expanded result of this reader
   (`expand_tilde` of its output) with the expanded path they are
   given.
3. **Missing-file note (part b).**
   - `mark_missing_attachment(outbox_path, filepath, outbox_name)`, just
     after `parse_outbox_file`, returns at once if the note for this
     path is already in the file.  Otherwise it finds the `attach:`
     line whose expanded path equals `filepath`, inserts the note on the
     next line, and logs.
   - `clear_missing_marker(outbox_path, filepath)`, a local helper at
     the top of `sync_outbox`, deletes the note's line and logs.
4. **Where `sync_outbox` checks.**
   - For a recipient not yet delivered to, every attachment is checked.
     Any missing file gets a note, the body is held back, and the file
     is recorded as unresolved, so the end-of-sync cleanup does not
     mistake "nobody delivered yet" for "everybody delivered".  An
     existing file has its note cleared.
   - For a recipient already delivered to, each attachment not already
     in flight is checked.  A missing file gets a note and nothing is
     queued.  An existing file has its note cleared, then is compressed
     and queued.
5. **Test.**  `scripts/test-outbox-headers.sh`, cases `blank-lines`
   (including the note clearing on an undelivered message),
   `missing-delivered`, `missing-tilde` and `quotes`.  Manual checklist:
   the "Outbox header robustness (#202)" section of `q-a-tests.md`.

### September 2026 fixes

`scripts/test-outbox-headers.sh` found three problems, fixed in commit
aad3f4c:

- **Part (c) had never been built.**  The July commit only described
  it.  Quoted paths to existing files were being marked missing, and
  quoted wildcards were not expanded.  Fixed by
  `_extract_attach_path`.
- **A missing `~` path got no note and no log line.**  The body was held
  back waiting for the file, so the message sat forever without a word:
  the exact failure part (b) exists to prevent.  The cause was that
  every place read `attach:` paths its own way.  The parser expanded
  `~`, but the note-writer and the strike-out compared the raw text
  (`~/…`) with the expanded path, so they never matched.  The same
  mismatch meant a finished attachment written with `~` or quotes would
  never have been struck out of the file.  Fixed by routing every reader
  through `_extract_attach_path` and comparing expanded paths.
- **The note did not clear on already-delivered messages.**  Automatic
  clearing had been added only to the undelivered branch, so on a
  delivered message the note kept saying "file not found" beside a file
  being sent.  The delivered branch now calls `clear_missing_marker` too.

## Edge Cases

- Several blank lines in a row, and whitespace-only lines: treated like
  a single blank line.  Tested.
- Header and blank lines with no body: parses, body is empty.  Tested.
- The note is written for a missing file named with `~`, and names the
  expanded path.  Tested.
- A quoted path to a missing file: the note names the unquoted path, and
  the quotes stay on the person's `attach:` line.  Tested.
- A wildcard that matches nothing stays in the file (#204).  Read as a
  path, it does not exist, so it also gets a note.
- An `attach:` line with no `to:` above it is dropped as an orphan when
  a recipient is struck out.

## Relationship to #204

#204 rewrites the outbox file to expand `attach:` wildcards.  #202 makes
the header reader more forgiving and adds visible notes.  Both touch
`parse_outbox_file`, `remove_recipient_from_file` and
`remove_attach_from_file`.  They share `_scan_outbox_header` and
`_extract_attach_path`, so the header rules are the same everywhere.
They were landed one after the other, each re-read after the other.

## Source

Diagnosed from a real message on 2026-04-17.  The received
`~/mail/inbox/atch-test` had the raw `attach:` line as its first body
line, because the sender had a blank line between `to:` and `attach:`.
The sender's daemon logged no error.

Part (c) was added 2026-04-18 (written into this file in July) after
another real message on sorelu.  `~/mail/outbox/music-for-you` had
`attach: "<path>"` with the path in double quotes.  Every sync logged
`failed to compress <path>`, with a confusing
`/tmp/rmail-<uuid>.zip: No such file or directory` from the size check
after zipping.  The root cause was the quotes staying in the path.
