# #330 — rto helper script: insert recipients into outbox files

## Problem

There's no convenient way to add `to:` lines to an outbox file from the
command line or from user hook scripts. Users must manually edit the file
and place `to:` lines at the correct position.

## Design

A shell script `helpers/rto.sh` that inserts one or more `to:` lines into
an outbox file. Each positional argument after the filename becomes a
`to: <name>` line.

### Insertion point

New `to:` lines are inserted **after** the existing header block (all
contiguous `to:` and `attach:` lines at the top of the file). This ensures
correct ordering: attachments above the new recipients are not sent to them,
while attachments added later (below) will be.

### Usage

```
helpers/rto.sh <file> <recipient> [<recipient> ...]
```

Example:
```
helpers/rto.sh ~/mail/outbox/hello alice bob
```

Produces (if file was empty or had no headers):
```
to: alice
to: bob
```

If the file already had `to: carol\nattach: photo.jpg\n\nHi!`, the result
would be:
```
to: carol
attach: photo.jpg
to: alice
to: bob

Hi!
```

## Source

From `issues/addresser`.

## Status

Completed. Implemented as `helpers/rto.sh` and documented in
`docs/helper-scripts.md`.
