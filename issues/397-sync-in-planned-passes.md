# #397 — A sync runs in planned passes: check, record the plan, act, check the results, record them

## Status

Open — designed with the owner 2026-09-23; not started.  Three open questions
below.  Absorbs #396.

## Current Behavior

A sync cycle (`run_sync_cycle` in `rmail.lua`) is seven builders run in a
fixed order — outbox, inbox, address notices, consent check, consent
answers, attachment pieces, attachment cancellations — each of which both
decides what needs doing *and* does it over the network, in one call.  After
all seven, one block of bookkeeping moves every contact's timer (`ctimer`),
retires confirmed address notices, and writes the "unreachable contacts
this cycle" summary.

The whole cycle sits inside one protected call in the main loop.  When
anything in it throws:

- every builder after the one that threw is skipped;
- the bookkeeping is skipped, so no contact's `next_due` moves, every due
  contact stays due, the main loop's sleep (`ctimer.time_to_due`) comes out
  as zero, and the next cycle starts at once and throws in the same place;
- the builders before it re-run their work on every pass (the likely reason
  "notified kuvalu-notes of address change" repeated on every pass during
  the September incident — not proven);
- the log keeps only the last line of the error, which names the helper
  that failed rather than the caller that handed it bad input.

Observed 2026-09-22 → 23 on the main mailbox: a stale attachment record
made the attachment-piece builder throw on every pass; 1,091,617 identical
error lines, 200 MB of RAM-backed log, several passes a second, all outbound
mail from that mailbox stopped.  The record's own bug is fixed (see
`scripts/test-stale-transfer-records.sh`); the cycle's shape that turned
one bad record into a stalled mailbox is what this issue is about.

The daemon's own log copy defaults to `.state/rmail.log` inside the
mailbox — on disk (`_log_file`, the `log_file` config setting).  The service
script separately captures the same lines into `/tmp/<service>.log`, which
is RAM.

Outbox change notices that arrive during a sync are discarded by the drain
at the end of the cycle, so a file saved mid-sync waits for a timer (was
#396, see below).

## Intended Behavior

### One sync is a series of passes

Each pass has five parts, in this order:

1. **Check.**  Read everything that can create work — outbox, inbox record,
   pending address notices, consents, outgoing transfers — plus the errors
   stored by the previous pass or cycle.  Produce one list of planned
   actions.  Each action names what it is, which contact, and what it needs
   (for instance "send pieces 0–3 of transfer X to sorelu, from compressed
   copy at P").  Nothing touches the network here.  Questions like "does the
   compressed copy still exist?" are asked here, so a bad record is a
   checking problem, found before anything is sent.
2. **Record the plan.**  Write down what is about to be attempted, for whom.
   Timers do not move yet.
3. **Act.**  Carry out the list.  A refusal from the world (no answer,
   connection refused, a file gone, a recipient that says no) is returned
   as a described failure, not thrown.
4. **Check the results.**  Sort what came back into successes and world
   failures.  Work that a result makes possible — a consent that arrived,
   a copy that has to be rebuilt — becomes input to the next pass's check.
5. **Record the outcome.**  Move each contact's timer by what happened to
   them, retire confirmed notices, write the summary line, and store the
   world failures where the next check reads them.

Passes repeat within one sync until a check plans nothing.  In the owner's
words: "Sorta like linters that make multiple passes for different tasks."
A pass can fix what the one before it found.

### How the passes stop

- **A contact the world refused is left out for the rest of the sync.**
  Their failure is stored and their timer backs off as today; only
  contacts that answered can generate further passes.
- **A pass that plans exactly the same list as the pass before it is a
  bug.**  It stops the sync with an error naming the repeated actions.
  There is no "at most N passes" cap: a cap would quietly hide a loop.

Together these guarantee the passes end: each pass either shrinks the
reachable work or produces something new, or the sync stops and says why.

### Code errors versus world errors

- **A code error** (anything thrown — a Lua runtime error, a failed
  assertion, the repeated-plan error) is written to the log as one entry
  carrying the whole chain of calls that led to it (a traceback), not only
  its last line, so the log names the caller.  Owner: "Code errors should
  be noticed and fixed, we can design perfect software if we choose to."
- **Part 5 still runs after a code error.**  Timers move as normal, so a
  code error repeats at the ordinary cadence (every 30s or so), one log
  entry each time, and never spins the loop.  A code error is not a
  statement about a contact's reachability, so it does not back anyone
  off either.
- *Decided against: letting a code error stop the timers so the loop runs
  away as an alarm.*  Proposed 2026-09-23 and briefly adopted, then
  reversed by the owner: "A log line would be just as useful, and wouldn't
  potentially crash the computer..."  The September runaway wrote 200 MB
  of log into RAM-backed `/tmp` in about 18½ hours.
- **A world failure** is described as fully as the daemon can: every
  address tried for the contact (local and public), the port, what each
  attempt got back (refused, timed out, no route, a status code and its
  body), how many bytes went out before it failed, and what is queued for
  them.  Not included: when the contact last answered (see open question
  3).  Owner: "If the failure is due to
  the world, then we should try and identify exactly as much information as
  we can provide about it and give it to the user."  It reaches the owner
  through the existing problems-as-mail mechanism (`report_problem`,
  #382): an outbound failure is one file in the outbox per contact,
  rewritten in place, removed once that contact is reached again.

### Stored failures and the daemon's log live in RAM

- Stored world failures go in one file per mailbox under the daemon's
  existing RAM folder, `/tmp/rmail-progress/` (`TMPFS_PROGRESS_DIR`), named
  the same way the transfers file there is.  Each entry: action (text),
  contact (text), attempts (list of: address text, port number, result
  text, bytes sent integer), first seen and last seen (Unix time numbers),
  count (integer).  Lost on reboot, by design: a reboot's first sync
  re-checks everything anyway.
- The daemon's own log copy defaults to a per-mailbox file in the same
  folder instead of `.state/rmail.log`.  Owner: "Yeah let's move the logs
  to the /tmp/ directory."  An explicit `log_file` in the config still
  wins.

### Outbox saves during a sync (was #396)

Owner, 2026-09-23, answering #396's question: yes, honour them.

With passes this falls out of the design: a check reads the outbox
directory itself, so a file saved while a pass is acting is seen by the
next pass's check.  The only window left is a save after the final check
(the one that planned nothing).  So the change-notice drain moves from the
end of the sync to *just before the final check*: notices caused by the
daemon's own writes are all from earlier passes and are discarded, while a
notice from a save after the final check stays waiting and starts the next
sync at once.

## Suggested Implementation Steps

1. **Split each builder in two**: a check function that returns planned
   actions (plain tables: kind text, contact text, and the fields that
   kind needs) and an act function per action kind that returns a success
   or a described failure.  The seven existing builders are
   `sync_outbox`, `sync_inbox`, `sync_address_notifications`,
   `check_consent_pending`, `send_consent_responses`, `send_next_chunks`,
   `send_attachment_cancellations`; `check_transfers_file_cancellations`
   is already check-shaped.  Act functions dispatch through a table keyed
   by action kind.
2. **Move reachability recording** (`ctimer.outcome`, the gate in
   `http_post_batch_with_fallback`, `note_contact_result`) so it is read in
   part 5 of each pass; the end-of-cycle bookkeeping in `run_sync_cycle`
   becomes part 5.
3. **Write the pass loop** in `run_sync_cycle`: check → record plan → act →
   check results → record outcome, until a check plans nothing; stop with an
   error on a repeated plan; leave refused contacts out for the rest of the
   sync.
4. **Catch code errors with a traceback** (Lua's `xpcall` with
   `debug.traceback`), log one entry, and go on to part 5.  How much a
   code error takes down with it — the one action, or the rest of the
   pass — is open question 2.
5. **Stored failures file** in `/tmp/rmail-progress/`, read by every check.
6. **World-failure report** through `report_problem` (outbound), one file
   per contact, with every attempt's detail; withdrawn on success.
7. **Log default** moves from `.state/rmail.log` to `/tmp/rmail-progress/`
   in `_log_file`; update README and `docs/` where the old path is named
   (grep for `rmail.log`).
8. **Drain placement** (#396): move the outbox and contacts notice drains
   from the end of the sync to just before the final check.
9. **Tests**, each on throwaway mailboxes the way
   `scripts/test-stale-transfer-records.sh` builds them:
   - a planted record that throws: the log has one traceback entry naming
     the caller, timers still move, and the next sync comes at the ordinary
     cadence rather than back to back;
   - a contact that refuses: one outbox report with every address tried and
     each result; other contacts still deliver in the same sync; the report
     goes away when the contact answers;
   - a consent arriving mid-sync: the attachment pieces go out in a later
     pass of the same sync;
   - a repeated plan (forced by a test-only record that re-plans itself):
     the sync stops with the repeated-plan error;
   - a hook that writes a second outbox file during a sync: delivered by
     the next pass or the next sync, never after a timer wait;
   - the log file and the stored-failures file exist under
     `/tmp/rmail-progress/` and nothing is written to `.state/rmail.log`.

## Open Questions

1. **Does "don't collapse identical lines, keep the timing" apply to #371
   as a whole?**  The owner said it about crash runaways, which are now
   decided against.  #371 proposes collapsing repeated lines everywhere
   (for instance a contact that stays unreachable for a week), with
   options that keep every timestamp.
2. **How much does a code error take down?**  Recommended: only the action
   that threw — it is logged and skipped, every other planned action in
   the pass still runs, then part 5.  The alternative stops the rest of the
   pass (still running part 5), which is simpler but lets one broken record
   hold up every contact's mail, as in September.
3. **The in-memory "last success" time on each contact's timer.**  Set on
   every success and every inbound message, read nowhere, never saved.
   Owner, 2026-09-23: "I feel like that's PII and we should remove it, or
   add it to the PII removal issue file."  #348 (the PII issue) was closed
   in April as reversed and covers `.state/` files only.  Recommended:
   delete the field as dead data, here.  Put to the owner: the daemon's
   log records every successful exchange with a name and a time, which is
   the larger record — is the concern the time being kept, or being shown?

Resolved: the service log's unbounded growth during a runaway was a
question while runaways were the design; with runaways decided against, a
code error writes one entry per ordinary cycle.

## Related

- #377 (per-contact sync timers — part 5 is where its bookkeeping moves)
- #396 (outbox changes during a sync — absorbed here)
- #371 (coalesce repeated log lines — see open question 1)
- #387 (a blocking sync stalls inbound requests — several passes make a
  sync longer, which makes this worse until outbound is non-blocking)
- #382 (the daemon reports its own problems as mail)
- #348 (the April change whose leftover records set off the September
  incident)

## Origin

2026-09-23.  While fixing the stale attachment record, the owner asked why
one bad record stopped the whole mailbox.  Owner's design, in their words:
"instead of checking for work and then doing work, we need to check all the
possibilities, build a list of what we want to do, and then execute in one
final step after the necessary bookkeeping has been done. If errors are
returned, we should store them for the next sync cycle, which might be
manually triggered if the user creates or modifies a file in their outbox
for example, and then pick them up during the checking phase next time."
Refined to: "check, bookkeep on our planned actions, execute, check for
errors, bookkeep for next sync cycle about what happened", repeated "until
there's no more tasks to do".
