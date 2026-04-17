# #334 — Install script: accept all interactive inputs as CLI arguments

## Problem

Every value the install script needs is gathered through an interactive
prompt. There's no way to run the installer unattended (e.g. from a
configuration-management script or a USB-stick bootstrap).

## Requirements

- Each interactive question (name, port, mail directory, etc.) accepts a
  corresponding command-line flag.
- When a value is supplied via CLI, the matching prompt is skipped
  entirely — not even shown as "default = X". The installer proceeds
  silently for that step.
- If every required value is supplied, the installer runs with no
  prompts at all.

## Implementation

Landed in 7c8d0ee (plus 9cc04f5 move-to-completed and a follow-up
commit dropping environment-variable support).

Environment variables were considered and initially included
(RMAIL_INSTALL_* one per key) but removed at the user's request: stale
exports from earlier sessions had a habit of silently changing install
behaviour in ways that were hard to notice.  Values now come from CLI
flags only.  If an `RMAIL_*` env var is set, the installer ignores it —
the error message for a missing value says "supply --mail-dir=VALUE",
not "... or export $RMAIL_INSTALL_MAIL_DIR".

## Source

From `issues/new-issue-please-sort`.
