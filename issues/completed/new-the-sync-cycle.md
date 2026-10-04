# #new-the-sync-cycle — The sync cycle: what goes out, in what order, and what it decides about each contact

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it.  #397 (a sync in planned passes) will
change its shape; this describes it as it is.

## Current Behavior

A **sync cycle** is the daemon's whole outgoing side.  It runs when the
outbox or contacts change, or when any contact's timer comes due
(#new-one-daemon-one-mailbox), and does, in order:

| step | what it looks at | what it may send |
|---|---|---|
| 1 transfers file | the author's edits to `transfers` | (cancels; #406) |
| 2 outbox | `outbox/` against `.state/outbox.json` | new messages, edits, removals, deletions, attachment offers, withdrawals (#new-a-message-is-a-file, #409, #406) |
| 3 inbox | `inbox/` against `.state/inbox.json` | "I deleted your message" (#new-deletes-travel-both-ways) |
| 4 addresses | owed address announcements | `/update-address` (#new-announcing-a-new-address) |
| 5 consent forms | the owner's answers in forms | (records them) |
| 6 consent answers | answers not yet delivered | `attachment_response` |
| 7 pieces | accepted outgoing attachments | `attachment_chunk`, batch by batch (#105) |
| 8 cancels | transfers the owner cancelled | `attachment_cancel` (#407) |
| 9 progress | outgoing transfers | rewrites the `transfers` file |

Each step that sends works the same way: **collect** every operation it
owes (reading the files and its record), **build** one request per
operation, **send** them as one batch (#new-encrypted-frames), then
**read the results** and change its record only for what succeeded.
A failure changes nothing, so the operation is built again next cycle —
retrying is not a separate mechanism, it is the next cycle.  (Every step
must honour this; #409 was a step that recorded success before sending.)

**Per contact, per cycle** (#377, #324):

- a request to a contact not yet due is withheld and reported to its
  builder as an ordinary failure;
- whether each contact was reached — any answer at all counts, a 404
  included — is recorded as the cycle goes, and applied **once** at the
  end: reached returns the contact's timer to 30 s (± 30 s jitter), not
  reached grows it by 6 minutes up to 2 hours.  Six messages to one dead
  contact are one failure, not six;
- a contact due but with nothing to send is moved on by 30 s, without
  backing off;
- one log line names the contacts every request to whom failed after a
  real attempt ("unreachable contacts this cycle: …"), instead of a line
  per request.

Everything the cycle does runs on the main thread, between requests: no
incoming request is processed until it ends (#387).  While a batch waits,
a contact it is dialing who calls at that moment is answered "busy" at
once (both sides then retry at the floor instead of stalling each other),
and any other caller is held and served the moment the cycle ends.

## Intended Behavior

As above; #397 plans the cycle as explicit passes (check, record the
plan, act, check the results, record them), and #387 lets requests in
while it waits.

## Suggested Implementation Steps

1. `rmail.lua`: `run_sync_cycle` (the order, the per-contact outcome
   pass, the op-less sweep); the steps: `check_transfers_file_cancellations`,
   `sync_outbox`, `sync_inbox`, `sync_address_notifications`,
   `check_consent_pending`, `send_consent_responses`, `send_next_chunks`,
   `send_attachment_cancellations`, `write_transfers_file`.
2. `ctimer` (the per-contact timers), `note_contact_result` /
   `flush_unreachable_summary` (the one-line summary),
   `http_post_batch_with_fallback` (the gate).
3. Tests: every two-mailbox test exercises it; `test-edit-delivery.sh`
   checks the "failure changes nothing" rule for edits.

## Related documents

- `#377`, `#324`, `#387`, `#396`, `#397`
