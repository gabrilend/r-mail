# #333 — Install script: arrow keys insert control characters into prompts

## Problem

During interactive install prompts, pressing the arrow keys inserts raw
control sequences (e.g. `^[[A`) into the input instead of moving the
cursor. Users who try to edit their entered text end up with a corrupted
value.

## Fix

Use `read -e` (readline editing) or otherwise enable line editing on the
interactive prompts so arrow keys behave as expected.

## Source

From `issues/new-issue-please-sort`.
