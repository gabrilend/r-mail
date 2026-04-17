# #364 — rfield.sh: take the contacts file as an argument

## Problem

`helpers/rfield.sh` currently reads
`$HOME/.config/rmail/config` to find the `mail = ...` line, then appends
`/contacts` to get the contacts file it actually needs.  That's two
problems at once:

1. **Wrong config path.**  Since #344, configs live at
   `~/.config/rmail/config-<slug>`, one per mailbox.  The old single
   `~/.config/rmail/config` path `rfield` looks for no longer exists on
   a modern install.
2. **Doesn't survive multiple mailboxes or portable mailboxes.**  A
   user with two mailboxes on one host has two separate config files;
   `rfield` can read at most one.  A user running the portable mailbox
   drive (#339) has their config inside the mailbox on the drive, not
   under `$HOME` at all — `rfield` can't find it.

The script doesn't actually need the config for anything.  The only
thing it uses is the path to the `contacts` file.

## Fix

Change the signature to take the contacts file directly:

```sh
Usage: rfield <contacts-file> <name> <field>
Example: rfield ~/mail/contacts alice phone
```

This matches every other helper in `helpers/`:

- `rto.sh <file> <recipient>...`
- `rattach.sh <file> <path>...`
- `raccept.sh <consent-file>`
- `rdeny.sh <consent-file>`
- `checksum.sh <file>`
- `filename.sh <path>`

All file-path first, no config lookups, no implicit `$HOME` dependency.
The helpers are designed for scripted/hook use, not interactive one-
shots, so requiring the caller to supply the path is the right trade.

## Implementation

- Replace the arg-count check with `[ $# -ne 3 ]`.
- Remove the `config=...`, `mail_dir=...`, `${HOME}` lookup and the
  fall-back to `${HOME}/mail`.
- Take `contacts="$1"`, `name="$2"`, `field="$3"`.
- Keep the existing `[ ! -f "$contacts" ]` guard.
- Update the help text and the `# Example:` line at the top.
- Update any caller (hook, doc, test) that invokes `rfield` today to
  pass the contacts path explicitly.

## Related work

Split out of the #339 / #361 portable-drive work, where this came up
as a pre-existing fragility affecting the portable-mailbox case.  Not
blocking those issues, but worth tracking so the portable drive's
helpers are consistent with the rest.

## Source

Fell out of the env-var audit during #339 / #361 implementation
(2026-04-17).  User chose "take the contacts file as an arg" over
"take the mailbox dir as an arg" because the former matches every
other helper and removes even the tiny `<mailbox>/contacts` indirection.

## Status

Completed 2026-04-17.  Signature changed to
`rfield <contacts-file> <name> <field>`; config/HOME lookups removed;
`docs/helper-scripts.md`, `docs/scripting-tutorial.md`, and both
`.templates/` copies updated to match.  Smoke-tested across found
values (quoted + unquoted), missing field, missing contact, missing
file, and wrong arg count.
