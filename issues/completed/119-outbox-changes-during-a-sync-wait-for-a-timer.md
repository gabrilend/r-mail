# #119 — An outbox change made during a sync waits for a timer

## Status

Answered 2026-09-23: yes, honour them.  Absorbed into #121 (a sync runs
in planned passes), whose design closes this gap by moving the drain to
just before the final check.

**Built 2026-11-05 in #121.**  The outbox and contacts notices are
drained just before each pass's check, so a file saved while a pass acts
is seen by the next pass, and one saved after the sync starts the next
sync at once.  Notices from the last pass are dropped when the sync ends,
so that a hook rewriting its own outbox file (the tutorial's periodic
pattern) cannot start syncs back to back; see #121, decision 10.  A sync an outbox change started also sends to
contacts only waiting out the floor, so such a message is not held for
its recipient's timer either.  Test: the hook case of
`scripts/test-sync-passes.sh` (a hook writes a second outbox file during
a sync; it is delivered in the next pass of that sync, 0.0 s after the
first).

**The last pass, built 2026-11-06.**  A file someone else saves during
the last pass of a sync no longer waits for a timer.  While a sync runs,
the outbox notices are sorted by when they arrive: those waiting just
before rmail writes an outbox file, or runs a hook and waits for it, are
someone else's and are kept; those waiting just after are the sync's own
and are dropped.  What is kept when the sync ends starts the next sync at
once, with a log line naming the files.  The periodic's own rewrite is
made inside its hook, so it is still dropped.  Tests: the saver and
marker cases of `scripts/test-sync-passes.sh`, and a new line in the
ticker case.  See the decisions below.

## Current Behavior

- The daemon learns about file changes from kernel file-change notices
  (inotify on Linux, kqueue on BSD/macOS) on `outbox/` and on `contacts`.
  A notice makes the main loop run a sync at once.
- A sync writes to those same files itself (problem markers in outbox
  files, recorded addresses in `contacts`).  So that its own writes do not
  trigger an endless run of syncs, the end of every sync cycle reads and
  discards every waiting notice (the drain at the bottom of the main loop,
  "Drain any inotify events caused by the sync cycle itself").
- The drain cannot tell the daemon's own writes from anyone else's.  An
  outbox file saved while a sync is running — by the owner in an editor, by
  the phone's upload, or by a hook such as the periodic pattern's
  `on_update` rewriting its own outbox message — loses its notice.  The file
  is on disk; it is picked up when the next timer comes due: ~30s while
  contacts are healthy, up to the 2h ceiling when every contact is backed
  off.
- For `contacts` the same drain is already handled: a discarded contacts
  notice runs the tidy-up (`align_contacts`) before draining again (fixed
  2026-09-22; see #408).
- Since #115's follow-up, a mailbox with no contacts keeps its own timer,
  so nothing waits forever any more; it only waits.

## Intended Behavior

Open question to the owner (2026-09-22): should outbox notices discarded by
the end-of-cycle drain be honoured, so a message saved mid-sync goes out on
the next pass instead of waiting for a timer?

## Suggested Implementation Steps

If yes:

1. At the drain, keep the outbox read's result.  If any notice was waiting,
   set a flag on the runtime table that makes the next loop pass sync
   immediately (the same effect as `outbox_changed`).
2. To stop that re-syncing forever on the daemon's own writes, compare the
   outbox directory's file set and modification times before and after the
   cycle: only a change the cycle did not make itself sets the flag.
   (Alternative: have the daemon's outbox writers record the paths they
   write, and ignore notices for exactly those paths.)
3. Test: a scratch mailbox with a hook that writes a second outbox file
   during a sync; the second file must be delivered within one loop pass,
   not after a floor-length wait.

## Related

- #121 (a sync runs in planned passes — where this is built)
- #115 (per-contact sync timers; no-contact timer follow-up)
- #408 (contacts tidy-up after the drain)

## Decisions (2026-11-06, the owner can overturn any of these)

1. **The last pass's notices are sorted by when they come, not by
   comparing the folder before and after.**  rmail writes its outbox files
   through `write_file` and runs its waited-for hooks through `run_hook`,
   so wrapping those two marks every change the sync makes itself, with no
   list of paths to keep and no snapshots of the folder.  The suggested
   before-and-after comparison cannot tell the periodic's rewrite from an
   editor's save; this can.
2. **A file saved at the very moment rmail writes one, or while a hook
   runs, is still taken for the sync's own** and waits for a timer, as
   every file saved during a sync once did.  The window is a write's
   length, or a hook's.
3. **A hook that runs in the background (`on_receive`, `on_package`) is
   someone else.**  rmail does not wait for it, so its writes are kept
   and start the next sync, like an editor's.
4. **Once in a row.**  A sync that such a save started does not start
   another for the same reason; it logs what was saved and leaves it to
   the timer.  Something that writes the outbox every time a sync runs
   gets one more sync, not a loop.
5. **A file removed, or a hidden file, starts nothing.**  rmail removes
   outbox files itself without the wrapping, and the outbox does not read
   hidden files (an editor's swap file).  A removal waits for the timer,
   as it did.  On kqueue (macOS, the BSDs), whose notices name no file and
   share one mask, every notice counts.  That path was not run here: this
   machine is Linux.
6. **Only while a sync runs.**  Outside one, the main loop reads the
   notices itself, as before.

