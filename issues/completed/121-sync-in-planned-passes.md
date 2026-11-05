# #121 — A sync runs in planned passes: check, record the plan, act, check the results, record them

## Status

**Built 2026-11-05** (see "Built" and "Decisions" at the end).  Designed
with the owner 2026-09-23; the log move was built then.  Absorbs #119,
built here too.  Open question 1 is about #118 and stays open there.

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

**Already built (2026-09-23), ahead of the rest:** the daemon's own log
copy defaults to RAM, `/tmp/rmail-progress/log-<mailbox path with dashes>`
(`_log_file`; the folder constant `TMPFS_PROGRESS_DIR` moved up beside it;
`log_handle` recreates the folder after a reboot).  It used to be
`.state/rmail.log`, on disk.  An explicit `log_file` still wins, and
`log_file = ""` still means no file copy.  Covered by
`scripts/test-log-location.sh`.  The service script separately captures
the same lines into `/tmp/<service>.log`, also RAM.  The daemon tests
clear their own logs from the shared RAM folder.

**Also built:** the unused "last success" time on each contact's timer is
deleted (owner; see Resolved, under Open Questions).

Outbox change notices that arrive during a sync are discarded by the drain
at the end of the cycle, so a file saved mid-sync waits for a timer (was
#119, see below).

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
- **A code error during part 3 ends part 3 for that pass.**  The action
  that threw, and every planned action not yet carried out, are marked as
  errors; the pass then goes on to part 4 and part 5 as usual.  The next
  pass of the same sync picks them up in its check and plans them again,
  applying a correction to the one that threw when the check can find one.
  Owner: "No it should abort the execute phase of the pass, move to the
  error phase and mark all the incomplete tasks as errors. Then, on the
  next pass, we'll pick them up and reschedule them, ideally with the
  correction applied to the erroring task. Remember, pass != sync cycle.
  We do multiple passes in a cycle."
- **This cannot loop.**  If no correction is found, the next pass plans the
  same list again (less whatever finished before the error), and when
  nothing finished, that list is identical — which is the repeated-plan
  stop above.  The sync ends with that error, and the next sync, at the
  ordinary cadence, tries again.
- *Decided against: skipping only the action that threw and running the
  rest of the pass* (proposed 2026-09-23).  The owner chose to stop the
  pass and hand everything unfinished to the next pass instead.
- **Part 5 still runs after a code error.**  Timers move as normal, so a
  code error repeats at the ordinary cadence (every 30s or so), one log
  entry each time, and never spins the loop.  A code error is not a
  statement about a contact's reachability, so it does not back anyone
  off either, and an action marked as an error only because it never ran
  says nothing about its contact either.
- *Decided against: letting a code error stop the timers so the loop runs
  away as an alarm.*  Proposed 2026-09-23 and briefly adopted, then
  reversed by the owner: "A log line would be just as useful, and wouldn't
  potentially crash the computer..."  The September runaway wrote 200 MB
  of log into RAM-backed `/tmp` in about 18½ hours.
- **A world failure** is described as fully as the daemon can: every
  address tried for the contact (local and public), the port, what each
  attempt got back (refused, timed out, no route, a status code and its
  body), how many bytes went out before it failed, and what is queued for
  them.  Not included: when the contact last answered (see Resolved,
  under Open Questions).  Owner: "If the failure is due to
  the world, then we should try and identify exactly as much information as
  we can provide about it and give it to the user."  It reaches the owner
  through the existing problems-as-mail mechanism (`report_problem`,
  #102): an outbound failure is one file in the outbox per contact,
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

### Outbox saves during a sync (was #119)

Owner, 2026-09-23, answering #119's question: yes, honour them.

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
   `debug.traceback`) around part 3 as a whole, not per action: log one
   entry, mark the action that threw and every action not yet run as
   errors, then go on to parts 4 and 5.  The next pass's check reads
   those errors and replans them.
5. **Stored failures file** in `/tmp/rmail-progress/`, read by every check.
6. **World-failure report** through `report_problem` (outbound), one file
   per contact, with every attempt's detail; withdrawn on success.
7. **Log default** moves from `.state/rmail.log` to `/tmp/rmail-progress/`
   in `_log_file`.  *Done 2026-09-23; no README or `docs/` page named the
   old path.*
8. **Drain placement** (#119): move the outbox and contacts notice drains
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

1. **Does "don't collapse identical lines, keep the timing" apply to #118
   as a whole?**  The owner said it about crash runaways, which are now
   decided against.  #118 proposes collapsing repeated lines everywhere
   (for instance a contact that stays unreachable for a week), with
   options that keep every timestamp.

Resolved:

- **How much a code error takes down:** the rest of that pass's part 3;
  everything unfinished is marked as an error and replanned by the next
  pass (see Code errors versus world errors).

- **The in-memory "last success" time on each contact's timer** (set on
  every success and inbound message, read nowhere, never saved).  Owner:
  "I feel like that's PII and we should remove it, or add it to the PII
  removal issue file."  #505 was closed in April as reversed and covers
  `.state/` files only, so it was handled here: deleted.  The two larger
  records of when contacts are talked to were settled at the same time —
  the daemon's log moves to RAM (owner: "Let's move it to RAM then"), and
  the stored failures' first/last-seen times stay, in RAM ("Sounds good").
- **The service log's unbounded growth during a runaway** was a question
  while runaways were the design; with runaways decided against, a code
  error writes one entry per ordinary cycle.

## Related

- #115 (per-contact sync timers — part 5 is where its bookkeeping moves)
- #119 (outbox changes during a sync — absorbed here)
- #118 (coalesce repeated log lines — see open question 1)
- #120 (a blocking sync stalls inbound requests — several passes make a
  sync longer, which makes this worse until outbound is non-blocking)
- #102 (the daemon reports its own problems as mail)
- #505 (the April change whose leftover records set off the September
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

## Built (2026-11-05)

On top of #120 (the sync is a coroutine of the main loop, and requests are
served while it waits).

**Passes.**  `run_sync_cycle` runs passes (`ctimer.passes`) until one
plans nothing.  A pass is `check_transfers_file_cancellations`, then the
seven steps in their old order (`ctimer.STEPS`), then the transfers file,
then part 5 (`ctimer.after_pass`).  Each step is split at its batch call:
the code before it is the step's check (part 1), the gate in
`http_post_batch_with_fallback` writes every request about to go out into
the pass's plan (part 2, `ctimer.plan_actions`), the batch is the act
(part 3), and the code after it sorts the answers (part 4).  An action is
the step, the contact, the path and a digest of what it carries, with a
readable label ("attachment pieces: attachment_chunk to owing
(picture.jpg) piece 0").  The steps run check, act and results one after
another inside a pass, not all seven checks first (decision 1).

**How passes end.**  During a sync the gate asks `ctimer.may_send`
instead of "is this contact due": a contact may be sent to if it was due
when the sync started (or, in a sync an outbox change started, is only
waiting out the floor), or was heard from or made due by a request during
the sync, and the world has not refused it since.  Any answer but ok (no
answer, busy, a refusal status) leaves the contact out for the rest of
the sync; a failed action with no contact is not tried again in it
either.  A pass that plans exactly what the pass before it planned stops
the sync with one line naming the actions: `sync stopped: pass 2 planned
exactly what pass 1 planned: ...`.  There is no cap.  A sync that sent
anything ends with `sync done: N passes, M requests`.

**Code errors.**  Each pass's parts 1–4 run under `xpcall` with a
traceback taken where the error was thrown (`ctimer.trace`; `ctimer.hold`
now uses `xpcall` too, so the traceback is not cut off at the lease
wrapper, and the steps are named in it).  A throw ends the pass's steps;
the step that threw and those after it are left for the next pass, which
plans them again from the queues they are still in.  One log entry,
`sync error in pass N, at the <step> step; ...: <message>` and the whole
traceback; the same error in a later pass of the same sync is not logged
again, and the sync stops with the repeated-plan line ("and met the same
error").  Part 5 runs after every pass, error or not: timers move, and an
action that never ran backs nobody off.

**Part 5** (`ctimer.after_pass`) is the old end-of-cycle bookkeeping, run
per pass: reached contacts to the floor (and their address-change notice
retired), unreached ones backed off once, `busy` due in 1 to 5 s, due
contacts with nothing queued back to the floor (not ones an earlier pass
already moved), the mailbox's own timer, the unreachable summary.  The
contacts heard from during the sync are settled once, when it ends.

**World failures.**  Each attempt now records the address, the port,
what it got (`connection refused`, `Network is unreachable`, `timed out
connecting`, `no response`, `status 403: <the answer's error>`, `busy`)
and the bytes sent before it failed; a request tried at several addresses
keeps every attempt.  Part 5 writes them to
`/tmp/rmail-progress/failures-<mailbox path with dashes>` (JSON: action,
contact, attempts, first_seen, last_seen, count), removing a contact's
entries once a pass reaches them with nothing failing.  A contact nothing
answered gets one file in the outbox, `CANNOT-REACH-<contact>`
(`report_problem`), naming every address tried, what each got, the bytes
sent, and what is queued for them; rewritten each time they are tried,
removed once they are reached.  The outbox step does not read it as a
message (no "missing to:" line for it).

**#119.**  The outbox and contacts change notices are drained just before
each pass's check (`ctimer.drain_notices`): what they announce is on disk
for the check that follows, so a file saved while a pass acts goes out in
the next pass.  The notices that came during the last pass are dropped
when the sync ends (decision 10); one that comes after the sync stays
waiting and starts the next sync at once, and an outbox file the phone
writes during the last pass still does (`ctimer.outbox_written`).  The
contacts tidy (`align_contacts`, #408) moved with the drain.

**Log.**  From a sync's second pass on, a line the sync's coroutine
already wrote in that sync is left out (each check reads the same files
again).  Lines from requests served meanwhile are not affected.

**Tests.**  `scripts/test-sync-passes.sh` (new), six real daemons, one
case each, with stand-in recipients:
- a planted transfer record whose piece count is text, so the pieces
  step throws: one `sync error` entry per sync with the whole traceback
  (naming `send_next_chunks` and the step), the sync stops after pass 2
  meets the same error, and only one sync in 20 s — the ordinary cadence;
- a contact nothing listens for, beside one that answers: both tried in
  the first sync, the other delivered; `CANNOT-REACH-nobody` names
  `127.0.0.1 port 59573: connection refused` and the queued message; the
  stored failure and the log are in `/tmp/rmail-progress/`, nothing in
  `.state/rmail.log`; once the contact answers it gets the message and
  the report and stored failure go;
- a consent that arrives while a sync waits on a slow recipient's piece:
  the other file's pieces go out in pass 2 of that sync (`sync done: 3
  passes`);
- a recipient that answers every piece ok but keeps it owed: the sync
  stops with the repeated-plan line naming the piece;
- an `on_send` hook that writes a second outbox file: delivered in pass 2
  of the same sync, 0.0 to 0.1 s after the first;
- the tutorial's periodic (an `on_update` hook that rewrites its own
  outbox file each time): one hand edit fires it once in 10 s.  With the
  end-of-sync drain taken out, the same case fires it 299 times in 10 s.

`scripts/lib/fake-recipient.lua` gains an `owe` file (answer every piece
ok, keep it owed) and a `piece` event.

## Decisions (2026-11-05, the owner can overturn any of these)

1. **Check, act and results run step by step inside a pass, split at
   each step's batch call, not seven check functions run before seven act
   functions.**  The steps share state files (the outbox step's offers
   become the pieces step's transfers; both keep `outbox.json` and
   `chunks-outgoing.json`), so a check made before an earlier step's
   results were in would plan from stale records and its save would
   overwrite theirs.  The plan is therefore recorded at the gate, batch by
   batch, just before each acts, and the act is the one batch sender for
   every kind of action rather than a table of act functions.  A thrown
   error in a step's check is handled exactly as one in its act.
2. **The plan is kept in memory**, not written to a file: it is one
   entry per request, chunks included.  It reaches the log when a pass
   repeats it.
3. **Any answer but ok leaves a contact out for the rest of the sync**:
   no answer, busy, and any refusal status, including a 404 that a step
   counts as done.  Their other work waits for their timer (the floor,
   30 s ± 30, after an answer).  Narrower rules would let a step that keeps
   an op after a refusal re-plan it and stop the sync as a repeated plan.
4. **Who a sync may send to**: contacts due when it starts; contacts heard
   from, or made due by a request, during it; and, when an outbox change
   started it, contacts only waiting out the floor (not backed-off ones).
   The last is what makes a message saved after the final check go at
   once (#119) rather than when its recipient's floor ends.
5. **A code error is logged once per sync**; the later pass that meets
   the same error is named in the stop line.  The entry keeps the `sync
   error` prefix the existing tests look for.
6. **A plan is the same when every action (step, contact, path, payload
   digest) is the same, in order, and so is the error, if any.**  The
   repeated-plan test forces a repeat from the recipient's side (it keeps
   asking for one piece) rather than with a test-only record in the
   daemon.  So a real recipient that keeps asking for the same piece (one
   that keeps arriving damaged) now ends the sync with the `sync stopped`
   line instead of being retried within the cycle; the next sync tries
   again at the ordinary cadence, as before.
7. **A success that leaves more to send no longer makes the contact due
   at once** (#115 follow-up `true`): the next pass sends it.  The `busy`
   follow-up stays.
8. **The report goes only to a contact nothing answered** (refused,
   unreachable, timed out, no response).  One that answered with a
   refusal is in the stored failures but gets no `CANNOT-REACH` file: the
   steps already mark such problems in the outbox file itself.  The
   report says when they were last tried, not when they last answered.
9. **The stored failures are read and rewritten by part 5, not by the
   check.**  What failed is still queued in the state files the check
   reads, so the check finds it there; the stored file is the record of
   what each attempt got.
10. **The drain runs before every check, and once more when the sync
    ends.**  Before every check rather than only the final one, because
    which check is final is known only afterwards, and a drain followed
    by a check loses nothing.  Once more at the end because the periodic
    pattern in the scripting tutorial has its `on_update` hook rewrite its
    own outbox file in every check: honoured, that notice starts the next
    sync at once, whose check fires the hook again, a loop with no wait.
    The cost: a file an editor or hook saves during the last pass (a few
    milliseconds unless a hook is slow) waits for a timer, as any file
    saved during a sync used to.  The phone's saves are flagged
    separately and still start the next sync at once.
11. **The `on_send` hook is not run for a recipient the gate will hold
    back**, since each pass's check builds the requests again.
12. **One `sync done` line per sync that sent anything**; an idle sync is
    silent.
