# #362 — Support `*` (glob) wildcards in `attach:` file paths

## Status

Completed 2026-09-23.  Built April 2026 (commit abafc56); one gap (a link
to a folder was attached as though it were a file) found and fixed in
September 2026 (commit aad3f4c).  Verified by
`scripts/test-outbox-headers.sh`, which runs the real daemon against
throwaway mailboxes and passes all its checks, including every wildcard
case listed under Edge Cases below.

## Current Behavior

An `attach:` line in an outbox file may name one file, or may carry
shell-style wildcards (`*`, `?`, `[...]`) in its last path component:

```
attach: ~/photos/trip/*.jpg
attach: ~/photos/trip/*
attach: ~/reports/2026-*.pdf
attach: ~/logs/app-[0-9][0-9].log
```

When the daemon reads an outbox file and finds such a line, it replaces
it — in the file on disk — with one `attach:` line per matching file,
each a full absolute path, in sorted (lexicographic) order.  From then on
the rest of the pipeline (missing-file check, compression, consent
request, chunked transfer, striking the line out when the transfer
finishes) only ever sees plain literal paths, exactly as if the person
had typed each one by hand.

What a wildcard matches:

- Files only.  Folders are left out, and so is a symbolic link to a
  folder (see September 2026 fix below).  A link to a file is followed
  and attached, the same as a literal `attach:` path to a link.
- Hidden files (leading `.`) are left out, as a shell does.
- A filename with spaces is kept exactly — the matcher is Lua, not a
  shell, so there is no word-splitting.
- `~` is expanded first, so `~/foo/*.jpg` and `~/*` work.
- One layer of surrounding quotes is taken off before matching (from
  #363 part c), so `attach: "/home/ritz/photos/*.jpg"` expands too.

What is logged and what is left alone:

- Each expansion logs `attach: expanded <pattern> -> N file(s) in
  <outbox file>`, so a runaway wildcard matching thousands of files is
  visible in the log.  There is no cap.
- A wildcard that matches nothing stays in the file unchanged and logs
  `attach: no files match <pattern> (<outbox file>)` once per daemon run
  (not every sync).  The rest of the message is not abandoned: its other
  `attach:` lines stay and are handled normally.  (The unmatched line
  itself then reads as a path that does not exist, so #363's
  `// MISSING ATTACHMENT:` note appears under it and the message body
  waits — the person sees both the log and the note.)
- A wildcard in a folder component (`~/p*/a.jpg`) is refused: logged once
  as `attach: glob in directory component not supported`, line left as
  written.
- A wildcard that is neither absolute nor `~`-anchored (`pics/*.jpg`) is
  refused: logged once as `attach: glob pattern must be absolute or
  ~-anchored`, line left as written.
- A file with no wildcard lines is never rewritten — it stays
  byte-for-byte as the person wrote it.
- A match that is already being sent (an in-flight transfer for the same
  message, recipient and path) is not queued a second time.

## Intended Behavior

The original request (2026-04-17): a person who wants to send every file
in a folder, or every file matching a pattern, should not have to list
each one on its own `attach:` line.  Listing by hand is tedious and makes
it easy to miss a file or include one that should not go.  Before this
change `parse_outbox_file` took the text after `attach:`, expanded `~`,
and treated the result as one literal path.

Requirements as originally stated, all met:

- Expansion happens after `~` expansion, so `~/foo/*.jpg` works.
- Only regular files are attached; folders matched by the wildcard are
  skipped.  (The original text said "rmail attaches files, not
  directories".  Since then a *literal* `attach:` of a folder is
  supported — `compress_attachment` zips it with its structure intact —
  but a wildcard still matches files only, so that `*` never sweeps up a
  whole subtree by surprise.)
- Matches are sorted so attachment order does not depend on the order
  the filesystem lists them in.
- A literal path with no wildcard keeps its old behaviour exactly.
- A wildcard with zero matches logs a clear warning naming the pattern
  and is skipped; the whole message is not aborted.
- Hidden files are excluded by default, matching shell behaviour.
  (Revisit if users ask for it.)

## Suggested Implementation Steps

All in `rmail.lua`, in the "attach: glob expansion (#362)" section just
above `parse_outbox_file`:

1. `_has_glob_chars(s)` — true when the path holds `*`, `?` or `[`.
2. `_glob_to_lua_pattern(glob)` — translates one filename-component glob
   into an anchored Lua pattern: `*` becomes "any run of non-slash
   characters", `?` one non-slash character, `[...]` a character class
   (`[!...]` becomes a negated class), and Lua's magic characters are
   escaped.
3. `_extract_attach_path(line)` (shared with #363) — the path an
   `attach:` line names, trimmed, with one layer of matching quotes
   removed; `~` is left for the caller.
4. `_list_dir_files(dir)` — lists a folder with `ls -1pL`: `-p` marks
   folders with a trailing `/`, and `-L` makes a link to a folder get
   that mark too.  Entries with a trailing `/` and entries starting with
   `.` are dropped.
5. `_expand_attach_glob(pattern, outbox_file)` — expands `~`, refuses
   relative patterns and folder-component wildcards (returns nil, warns
   once through the per-run table `_glob_warned`), otherwise lists the
   folder, keeps names matching the translated pattern, and returns the
   sorted absolute paths (an empty list for zero matches).
6. In `parse_outbox_file`: after the shared header scan
   (`_scan_outbox_header`, from #363), walk the header lines; each
   `attach:` line whose path has wildcards is replaced by its matches,
   logs the count, and marks the file as changed.  Zero-match and refused
   lines are kept as written.  Only if something expanded is the file
   written back (header lines joined, then the body untouched).  The
   per-recipient attachment lists are then built from the expanded
   header.

   Decision: expand in the file at parse time rather than keep the
   wildcard line and track its matches.  The strike-out logic
   (`remove_attach_from_file`, run when a transfer completes) then only
   ever deals with the literal lines it sees, and the person can see in
   their own file exactly which files are going.
7. Duplicate protection lives in `sync_outbox`'s branch for a recipient
   already delivered to: before queuing an attachment it looks for an
   existing transfer with the same recipient, outbox file and path, and
   skips it if found.
8. Test: `scripts/test-outbox-headers.sh`, cases `glob-basic`,
   `glob-unexpanded`, `in-flight` (and the quoted-wildcard check in
   `quotes`).  Manual checklist: the "attach: glob expansion (#362)"
   section of `q-a-tests.md`.

Implementation choices considered and decided against:

- Shelling out to `sh -c 'for f in <pattern>…'` or `printf '%s\n'
  <pattern>` to let a shell do the matching.  The pattern would have to
  go unquoted into a shell command, which opens an injection surface and
  word-splits filenames with spaces.  The small Lua matcher avoids both;
  only the folder name, shell-quoted, reaches `ls`.
- Globbing folder components.  Too ambiguous to expand automatically
  (which of several matching folders?); refused with a clear log line.

### September 2026 fix

`scripts/test-outbox-headers.sh` found that a symbolic link to a folder,
matched by a wildcard, was attached as though it were a file: plain
`ls -1p` puts the `/` mark on real folders but not on links to them.
Since links are followed (as for a literal path), a followed link to a
folder is a folder and must be left out like one.  Fixed by adding `-L`
to the listing in `_list_dir_files`.  The same September pass moved all
reading of `attach:` paths into `_extract_attach_path` (see #363), which
is why a quoted wildcard now expands.

## Edge Cases

- Wildcard matches an attachment already in flight from a previous
  parse: deduplicated against the in-progress transfer list (step 7).
  Tested.
- Wildcard with `~`: `~/*` expands correctly.  Tested (`~/pics/*.jpg`).
- Matched filenames with spaces: preserved exactly, no word-splitting.
  Tested.
- Very large matches: no hard cap; the count is logged.  Log line tested.
- Symlinks: followed, same as a literal `attach:` path.  A link to a file
  is attached; a link to a folder is skipped as a folder.  Both tested.
- A filename containing a newline would be split by the line-by-line
  `ls` listing.  Not handled; such names are not expected in practice.

## Relationship to #363

#363 made the outbox header scanner tolerate blank lines and `//`
notes, added the missing-file note, and added quote stripping.  Both
issues touch `parse_outbox_file`, `remove_recipient_from_file` and
`remove_attach_from_file`; they share `_scan_outbox_header` and
`_extract_attach_path` so the header rules stay the same in every place
that reads the header.

## Source

User request 2026-04-17.
