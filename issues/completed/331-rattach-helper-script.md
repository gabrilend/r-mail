# #331 — rattach helper script: insert attachments into outbox files

## Problem

There's no convenient way to add `attach:` lines to an outbox file from
the command line or from user hook scripts. Attachments must be manually
inserted at the right position within the header block.

## Design

A shell script `helpers/rattach.sh` that inserts one or more `attach:`
lines into an outbox file. Each positional argument after the filename
becomes an `attach: <path>` line.

### Insertion point

Same rule as `rto.sh` (#330): new lines go **after** the existing header
block (all contiguous `to:` and `attach:` lines at the top). This means
the attachments apply to every `to:` recipient above them.

### Usage

```
helpers/rattach.sh <file> <path> [<path> ...]
```

Example:
```
helpers/rattach.sh ~/mail/outbox/hello ~/photos/pic.jpg ~/docs/notes.txt
```

## Source

From `issues/addresser`.

## Status

Completed. Implemented as `helpers/rattach.sh` and documented in
`docs/helper-scripts.md`.
