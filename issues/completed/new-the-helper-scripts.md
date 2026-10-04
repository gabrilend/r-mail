# #new-the-helper-scripts — Small shell helpers for working with a mailbox's files

## Status

Completed — a blueprint written 2026-10-04 (#402) gathering the helpers
built under #326, #330, #331, #332 and #364, and the two built without
an issue.  The foundation of phase 7.

## Current Behavior

A mailbox is files, so anything that edits text can use it.  The
helpers in `helpers/` are the edits people make often, as commands, for
hooks and for hands.  Each is a short POSIX shell script with its usage
in its header; each works on the files it is given and talks to no
daemon.

| helper | does | issue |
|---|---|---|
| `rto.sh <file> <name>…` | adds `to:` lines to an outbox file, after its existing header block | #330 |
| `rattach.sh <file> <path>…` | adds `attach:` lines the same way (they apply to the `to:` lines above them) | #331 |
| `raccept.sh <form>` | answers a consent form yes: removes its `deny` line | #332 |
| `rdeny.sh <form>` | answers no: removes its `accept` line | #332 |
| `rfield.sh <contacts> <name> <field>` | prints one field of one contact from a contacts file | #326, #364 |
| `checksum.sh <file>` | prints a file's SHA-256 in hex, the form every rmail checksum takes | — |
| `filename.sh <path>` | prints the last part of a path (a hook's argument is often a path) | — |

Typical use is in a hook: an `on_receive` that answers a known sender's
forms with `raccept.sh`, refuses executables with `rdeny.sh`, or files
messages by sender (`docs/.templates/helper-scripts.md`,
`defensive-patterns.md`).  The helpers read and write the mailbox's
files exactly as a person would; the daemon sees the change on its next
cycle (or at once, for the outbox, #new-file-watchers-wake-the-sync).

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `helpers/*.sh`, each with its header.  They are run by path
   (`helpers/raccept.sh`) or put on the PATH by the owner; the installer
   does not install them anywhere.

## Related documents

- `docs/.templates/helper-scripts.md`
- `#326`, `#330`, `#331`, `#332`, `#364`, `#new-hooks`
