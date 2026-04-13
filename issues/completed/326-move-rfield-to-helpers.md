# #326 — Move rfield.sh to helpers/ directory

## Problem

`rfield.sh` is in the `scripts/` directory but it's a helper script meant
to be integrated into user hook scripts, not a standalone tool.

## Action

Move `rfield.sh` (or a copy) to `helpers/` — the directory for scripts that
users source or call from their own hooks. Update any references in docs
and scripting tutorial.

## Source

From `unsorted-issue-5`.
