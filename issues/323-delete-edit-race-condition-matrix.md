# #323 — Audit delete/edit race conditions between sender and receiver

## Problem

If a receiver deletes an inbox message and the sender edits (updates) the
same outbox message, the outcome depends on whose sync cycle runs first.
The update might "undelete" the file on the receiver's side.

## Action

Build two tables of all sender/receiver event interactions:

1. **Table 1**: sender's sync cycle runs first
2. **Table 2**: receiver's sync cycle runs first

Rows = receiver-side events/hooks (receive, delete, update, etc.)
Columns = sender-side events/hooks (send, delete, update, etc.)

Trace each interaction through the system to validate the behavior.
Document which combinations are handled correctly and which need fixes.

Record findings directly in this file. Do not mark this issue complete
until every problematic combination has either been split into its own
issue or explicitly closed as "not a problem".

## Source

From `unsorted-issue-2`.
