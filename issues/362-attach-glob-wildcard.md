# #362 — Support `*` (glob) wildcards in `attach:` file paths

## Problem

Outbox messages attach files by writing one `attach:` line per file:

```
to: alice
attach: ~/photos/trip/IMG_0001.jpg
attach: ~/photos/trip/IMG_0002.jpg
attach: ~/photos/trip/IMG_0003.jpg
...
```

When a user wants to send every file in a directory, or every file
matching a pattern (e.g. all `.jpg` in a folder), they have to list
each one by hand. This gets tedious fast and is error-prone — easy to
miss a file or include one that shouldn't go.

Currently `parse_outbox_file` in `rmail.lua` (around line 2358) takes
the raw text after `attach:`, runs it through `expand_tilde`, and
treats the result as a single literal file path.

## Proposed fix

Allow shell-style glob wildcards in `attach:` lines. When the parser
sees a path containing `*` (or `?`, `[...]`), expand it to the list of
matching files and queue each matched file as its own attachment.

Examples that should all work:

```
attach: ~/photos/trip/*.jpg
attach: ~/photos/trip/*
attach: ~/reports/2026-*.pdf
attach: ~/logs/app-[0-9][0-9].log
```

After expansion, each matched path is treated exactly as if the user
had typed that literal path on its own `attach:` line.

## Requirements

- Expansion happens after `expand_tilde`, so `~/foo/*.jpg` works.
- Only regular files are attached; directories matched by the glob
  are skipped (same rule as elsewhere — rmail attaches files, not
  directories; see the `list_files` directory-skip logic around
  `rmail.lua:294`).
- Matches are sorted deterministically (lexicographic) so the order
  of attachments doesn't depend on filesystem enumeration order.
- A literal path with no wildcard characters keeps its current
  behavior exactly — no globbing, no surprises.
- If a glob matches zero files, log a clear warning naming the
  pattern and skip it. Don't abort the whole message; the user may
  have other `attach:` lines that are fine.
- Hidden files (leading `.`) are excluded by default, matching normal
  shell glob behavior. (Revisit if users ask for it.)

## Implementation notes

- `parse_outbox_file` (`rmail.lua:2328`) is where the expansion
  belongs. Replace the single
  `attachments[#attachments + 1] = expand_tilde(fp)` with a helper
  that returns a list of paths and appends each.
- Lua doesn't have a built-in glob. Options:
  - Shell out to `ls` / `printf '%s\n' <pattern>` via `io.popen` and
    read matches line by line. Quote carefully — the pattern itself
    must *not* be shell-quoted (it needs to be expanded), but the
    surrounding path handling must still be safe against injection.
    Safest approach: use `sh -c 'for f in <pattern>; do …; done'`
    with the pattern inserted after expand_tilde, and a guard that
    rejects patterns containing shell-metacharacters other than the
    glob set (`*`, `?`, `[`, `]`).
  - Or write a small Lua glob (walk the directory, match with
    `string.match` after converting the glob to a Lua pattern).
    More code, but avoids a shell-injection surface entirely.
  - Prefer the Lua implementation unless it turns out to be ugly.
- The `attach:` line-stripping logic (`rmail.lua:2450`,
  `rmail.lua:3239`) removes completed attachments by matching the
  original `attach:` text. Make sure glob lines are handled: either
  leave the original glob line in place until *all* its matches
  finish, then strip it, or expand the glob into individual
  `attach:` lines in the outbox file at parse time. Expansion at
  parse time (keeping the file on disk unchanged) is simpler — the
  stripping logic only has to know about the literal lines the user
  wrote.

## Edge cases

- Pattern matches an attachment already in flight from a previous
  parse: deduplicate against the in-progress transfer list so we
  don't start a second upload of the same file.
- Pattern inside `~`: `~/*` should expand correctly.
- Pattern with spaces in matched filenames: matches must preserve
  the filename exactly — no word-splitting. (Another reason to
  prefer the Lua implementation over shell expansion.)
- Very large matches (thousands of files): no hard cap, but log the
  count so a runaway glob is visible in the daemon log.
- Symlinks: follow them, same as a literal `attach:` path to a
  symlink does today.

## Source

User request 2026-04-17.

## Status

Open.
