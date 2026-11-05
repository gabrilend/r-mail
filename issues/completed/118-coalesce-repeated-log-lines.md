# #118 — Coalesce repeated log lines into a repeat counter

## Current Behavior

A single stuck condition floods the log with identical lines, one per
sync cycle, forever.  Real capture from 2026-07-10 (one unreachable
contact, `aurelia`):

```
2026-07-10 17:25:04 unreachable contacts this cycle: aurelia
2026-07-10 17:25:04 idle, interval -> 30s
2026-07-10 17:25:26 timeout connecting to 184.3.205.26:50000
2026-07-10 17:25:04 unreachable contacts this cycle: aurelia
2026-07-10 17:25:04 idle, interval -> 30s
2026-07-10 17:25:26 timeout connecting to 184.3.205.26:50000
... (repeats every ~30s for a week)
```

Over a week this is thousands of identical lines.  The effect isn't
just clutter: it *hides real events*.  A one-off "delivered", an
`/api/sync` from the phone, a "decryption failed" — anything genuinely
new is a needle in a haystack of `timeout connecting to …`.  The
symptom that motivated this issue was a user believing "the logs don't
show any updates even though it's been running a week" — the updates
were there, drowned in repetition.

We want: when a line would be identical to the one just emitted, don't
print a new line — bump a counter on the existing entry and, on flush,
emit something like:

```
2026-07-10 17:17:51 (+8m, ×15) timeout connecting to 184.3.205.26:50000
```

## Why journald doesn't already do this

systemd-journald *has* native "last message repeated N times"
suppression — but it compares the **message text byte-for-byte**, and
`log()` (`rmail.lua:523`) bakes a wall-clock timestamp into the front
of every message:

```lua
local function log(fmt, ...)
    io.stderr:write(os.date("%Y-%m-%d %H:%M:%S ") .. string.format(fmt, ...) .. "\n")
    io.stderr:flush()
end
```

Every line is therefore unique to journald, so its dedup never fires.
The same is true of the `/tmp/rmail.log` file sink and the runit /
openrc sinks.  Fixing this in `log()` itself is the portable answer:
it covers **every** sink uniformly, and it's the one place all log
output funnels through.

## Relationship to #114

#114 already coalesces one *specific* kind of noise: N "failed to
notify X" ops in a single cycle collapse into one
`unreachable contacts: a, b, c` summary
(`note_contact_result` / `flush_unreachable_summary`, `rmail.lua:528`).

That is **semantic** grouping *within* a cycle.  This issue is
**verbatim** grouping *across* cycles — a general run-length coalescer
at the `log()` layer that catches any repeated line without knowing
what it means.  They're complementary and should both stay:
- #114 turns `fail, fail, fail` → `unreachable: aurelia` (one line/cycle).
- #118 turns that one-line-per-cycle stream → `unreachable: aurelia ×15`.

## Intended Behavior

Keep the last emitted message (the formatted string **without** its
timestamp prefix) plus a small amount of run state:

```lua
local _last_msg          -- text of the currently-repeating line (no timestamp)
local _repeat_count      -- how many times it has occurred (including the first)
local _first_ts, _last_ts -- os.time() of first and most-recent occurrence
```

`log()` becomes:

1. Format the message (without timestamp).
2. If it equals `_last_msg`: increment `_repeat_count`, update `_last_ts`,
   **do not print** (subject to the flush triggers below). Return.
3. If it differs: **flush** any pending run (emit the summary line for
   `_last_msg` if `_repeat_count > 1`), then print the new line
   normally and reset the run state to this message with count 1.

A run is also flushed by triggers other than "a different line
arrived", so a forever-repeating line still shows signs of life:

- **Count threshold** — flush every K repeats (e.g. 50) so an
  indefinitely-stuck condition emits a periodic heartbeat rather than
  going silent for hours.
- **Time threshold** — flush if the run has been open longer than T
  (e.g. 5 min) even if still repeating, so `journalctl -f` /
  `view-logs.sh` show liveness.
- **Explicit flush points** — daemon shutdown, and before any code path
  that itself reads/ships the log, so the pending tally isn't lost.

A flush emits one line; after a flush the run either ends (different
message) or continues accumulating from a fresh count (threshold
flush).  Single, non-repeated lines print exactly as they do today
(count 1 ⇒ no summary, no behavior change).

### Non-goals / known limits (v1)

- **Exact-match only.**  Lines that differ in a variable field don't
  collapse — e.g. `deleted shared zip /tmp/rmail-<uuid>.zip` has a
  unique UUID each time, and `timeout connecting to <ip>:<port>` differs
  per contact.  Collapsing "same template, different values" into
  `deleted shared zip … ×N` is a real feature but a *separate, harder*
  one (needs the call sites to log a template + args, or pattern
  extraction).  Keep v1 to verbatim matches; note templating as a
  possible follow-up.
- **Last-message-only, no interleave.**  If two conditions alternate
  (`A B A B A B`), nothing collapses, exactly like classic syslog.  A
  small LRU of recent distinct messages could catch this, but it
  reorders output and complicates timestamp bookkeeping — out of scope
  for v1.

## Suggested Implementation Steps

1. Settle the crux first (open questions): exact-match coalescing is of
   little use while the two worst repeaters carry a different address or
   id on every line.  Since this was filed, #115 and #114 removed most of
   the repetition at its source (backoff; one "unreachable contacts" line
   per cycle) — measure what still repeats before building.
2. If still wanted: the run state beside `log` in `rmail.lua`; the flush
   triggers (a different line, K repeats, T seconds, shutdown); a test that
   logs one line 120 times and finds the summary lines.

## Timestamp preservation — options to brainstorm

The whole point of coalescing is to drop the redundant *text*, but the
individual timestamps are the one thing that genuinely differs between
repeats, and we don't want to lose "when did this happen / how long has
it been stuck."  Options, roughly cheapest→richest:

1. **First-seen + span + count (recommended default).**
   `17:17:51 (+8m, ×15) timeout connecting to 184.3.205.26:50000`
   Emit the first occurrence's timestamp as the line's own time (so
   ordering in the log stays truthful), then annotate the elapsed span
   to the last occurrence and the count.  One extra field, answers "when
   did it start" and "how long / how many".  Loses the individual
   in-between times — usually fine because they're evenly spaced polls.

2. **First + last absolute timestamps.**
   `[17:17:51 … 17:25:26 ×15] timeout connecting to …`
   Like (1) but shows the end wall-clock instead of a relative span.
   Slightly more scannable across day boundaries.

3. **First + count + average interval.**
   `17:17:51 (×15, ~32s apart) timeout connecting to …`
   Adds the cadence, which makes an abnormal gap (daemon stalled, clock
   jump) visible.  Compute as span / (count-1).

4. **Bucketed distribution.**
   `×15 timeout … [17:17×2 17:18×3 17:19×2 17:20×2 …]`
   Preserves the temporal *shape* (were they bursty or steady?) at
   per-minute (or per-interval) granularity without storing every
   second.  Bounded size; good for irregular repeats.

5. **Delta-encoded exact times (lossless, compact).**
   `17:17:51 +8 +22 +8 +30 … ×15 timeout …`
   First absolute time, then integer second-deltas.  Fully
   reconstructable, far shorter than repeating the text.  Can cap the
   delta list (first N + last N, elide the middle with `…`) if a run
   gets huge.

6. **Full timestamp list (lossless, simplest).**
   `timeout … ×15 @ 17:17:51,17:17:59,17:18:21,…`
   Keep every time verbatim, text once.  Simple and lossless but the
   least compact — partly defeats the goal for long runs; only sensible
   with a hard cap + elision.

**Not decided.**  (1) is the cheapest and answers the two questions that
matter most in practice ("when did it start" / "how bad is it now"), and
(5) is attractive as an opt-in lossless mode — but this is explicitly
left open (see Open questions).  Nothing here is chosen yet; the whole
timestamp-preservation strategy is still up for grabs.

## Open questions

- Thresholds K (count) and T (time) for heartbeat flushes — what values
  keep `journalctl -f` feeling live without re-spamming?  Start K=50,
  T=5m, tune.
- Do we want a config knob to turn coalescing off entirely (raw
  firehose) for debugging?  A `log_coalesce = false` in `config`.
- Which timestamp option above (default (1)) — and is a verbose/lossless
  mode worth the code?
- Should the count-threshold flush *reset* the count to 0 or keep a
  running grand total across heartbeats (`×50 … ×100 … ×150`)?  Running
  total is more informative; reset is simpler to reason about.
- Where exactly do the "explicit flush points" go — is there a clean
  single choke point before shutdown and before log-shipping, or does
  every exit path need its own flush?
- Does coalescing interact badly with the `on_*` hook scripts or
  `view-logs.sh -F` tailing (partial line held back until flush)?  A
  held-back pending line means the *latest* repeat isn't visible until
  it either changes or hits a threshold — is that acceptable for live
  tailing, or does it need a shorter time-threshold when a tail is
  attached?
- Should exact-match comparison be on the raw formatted string, or
  should near-identical lines (same template, differing UUID/IP) be
  normalised first?  Templating is listed as a non-goal for v1 — but is
  v1 even useful without it, given the two worst offenders
  (`deleted shared zip <uuid>`, `timeout connecting to <ip>`) each vary
  per line?  **This is the crux and is unresolved.**
- Multi-line / structured log entries — do any `log()` calls emit
  embedded newlines that would break the "one message = one line"
  assumption the counter relies on?

## Origin

Filed 2026-07-10 after a week-long run whose journal was ~entirely
`timeout connecting to 184.3.205.26:50000` (a stale/unreachable
`aurelia` contact), making it look like the daemon had logged nothing
of interest when in fact real events were simply buried.

## Status

**Built 2026-11-05** (see "Built" and "Decisions" below), on top of #121.
The open questions are answered in the decisions.

2026-09-23: while designing #121, the owner decided a crashing sync's
repeated error lines are **not** collapsed: "Nah let's keep it running
away instead of collapsing identical lines. That way we have the timing
information too."  Later the same day the owner dropped runaways from
#121 altogether ("A log line would be just as useful, and wouldn't
potentially crash the computer..."), so a code error now logs once per
ordinary cycle.  Whether "keep the timing, don't collapse" still bears on
this issue (for instance a contact unreachable for a week) is open
question 1 in #121.  Answered here:
decision 3.

## Built (2026-11-05)

**What was measured first** (suggested step 1).  On #121's branch, a
mailbox on loopback with one contact whose port refuses and one message
waiting for it, run for eight minutes:

```
14:26:44 http send failed at 0/282 bytes: closed
14:26:44 backing off aurelia: retrying every 390s
14:26:44 unreachable contacts this cycle: aurelia
14:26:44 sync done: 2 passes, 1 requests
14:33:31 http send failed at 0/282 bytes: closed
14:33:31 backing off aurelia: retrying every 750s
14:33:31 unreachable contacts this cycle: aurelia
14:33:32 sync done: 2 passes, 1 requests
```

A stuck contact now writes three or four lines per attempt, and the
attempts move apart by six minutes each time until they are two hours
apart (#115), where the "backing off" line stops.  That is about 36 lines
a day, not thousands: #114 and #115 took away the flood this issue was
filed for.  What can still repeat fast is what no timer paces: a line
written for each web request (a phone or script retrying something the
daemon refuses), a contact sending a bad piece again and again, and a
code error, which #121 logs once per sync, with its traceback, every 30
seconds while the contacts are at the floor.  Those repeat word for word,
so matching whole lines is enough for them.

**The log.**  `log()` (in `rmail.lua`) formats the line, lets #121's
within-a-sync check drop it as before, and then asks `log_state.hold`.  A
line seen in the last `log_coalesce` seconds (default 300) is held: its
time is kept and nothing is written.  Any other line is written as
before, and remembered.  `log_state.write` is the old body of `log()`
(stderr first, then the file, then rotation).  The run state is one table,
`log_state`, which also took over `log_broken`, so the main chunk has no
more locals than before.

**The held line**, written when the first held repeat is `log_coalesce`
seconds old, when 50 are held, or before the daemon stops:

```
2026-11-05 10:05:00 (repeated x9: 10:00:30 +30 +30 +31 +29 +30 +30 +30 +30) timeout connecting to 184.3.205.26:50000
2026-11-05 10:30:00 (repeated x10, 19 so far: 10:05:30 +30 +30 ...) timeout connecting to 184.3.205.26:50000
```

Its own time is when it was written, so the file stays in time order.  In
the brackets: how many repeats it carries, how many there have been since
the line was last written in full (from the second such line on), the
time of the first repeat (with its date when that is another day), and
then each repeat as seconds after the one before.  Every repeat's time can
be read back to the second.

**When held repeats are written:** on every line logged and on every
wake of the main loop (at least every 3 seconds), whatever is due; before
the `--once` closing line; when the mailbox has gone (stderr and the RAM
log are not on the drive); and when a Lua error stops the daemon (`main`
now runs under `xpcall`, whose handler writes them and then the error and
its traceback as Lua would, and exits 1).

**Config:** `log_coalesce = <seconds>`; `false` or `0` writes every line
as it comes.  In the README's list of settings not in the generated
config.

**Test:** `scripts/test-log-repeats.sh` runs the real daemon and makes it
repeat "refused a web PUT request" over loopback: 120 at once (the line
once in full, then 50, 50 and 19 held, adding to 119, each listing one
time per repeat, the later ones saying how many so far), two lines in turn
(both held), `log_coalesce = false` (30 lines in full), repeats further
apart than the setting (both in full), and `--once` with the default
setting (the 9 held repeats written before the closing line).  Both the
stderr copy and the file are checked.  Breaking the holding, the `--once`
flush, or matching only the line before each fails it.

`scripts/test-listen-only-contact.sh` counts one log line per refusal, and
two of its refusals log the same words; it stops the daemon by signal
before a held repeat would be written, so it sets `log_coalesce = false`.
Every other test passes unchanged.

## Decisions (2026-11-05, the owner can overturn any of these)

1. **Built, after measuring** (the crux).  The flood is gone at its
   source, but a line written per request, per bad piece or per sync
   error can still repeat every few seconds, word for word.  Matching
   whole lines catches those; templating ("same line, different
   address") stays a possible follow-up, and is not needed for the stuck
   contact any more, whose lines are now two hours apart.
2. **A line is compared with every line seen in the last `log_coalesce`
   seconds, not only the one just before.**  A stuck contact's lines come
   as a group of three or four, so comparing with the last line alone
   would never find a repeat.  The cost is order: held repeats are
   written after lines that came between them, which their listed times
   make up for.  At most 64 different lines are remembered; past that,
   the one seen longest ago is written out and forgotten.
3. **Every repeat's time is kept** (option 5, without the elision it
   would need, because a line carries 50 repeats at most).  The owner said
   on 2026-09-23 that repeats should keep their timing ("That way we have
   the timing information too").  That was about crash runaways, now
   gone, but it is the owner's reason for not collapsing lines, and this
   meets it: the text is written once, the times all stay.  This answers
   #121's open question 1.
4. **One window, default 300 seconds, and 50 repeats a line.**  A line
   is held only when it comes within the window of its last appearance,
   and held repeats are written once the first is a window old.  So a
   line repeating every 30 seconds becomes one line every 5 minutes, a
   line repeating every two hours is written in full each time, and
   nothing held is more than about 5 minutes late in `tail -F` or
   `journalctl -f`.  The 50 matters only for bursts.  No separate
   setting for it.
5. **One setting, `log_coalesce`,** both the switch and the window:
   `false` or `0` turns it off, a number sets the seconds.
6. **Each held line lists only its own repeats, and says the running
   total too** once there is more than one held line for the same run
   ("x50, 100 so far").  The run ends when the line has not come for a
   window; next time it is written in full.
7. **Flush points:** every line logged, every main-loop wake, the
   `--once` exit, the mailbox going away, and an error that stops the
   daemon.  Nothing in the daemon reads its own log back, so there is no
   point "before the log is shipped".  A stop by signal (the service
   manager's stop, a kill) loses what is held, at most one window of
   repeats whose line was already written in full once: the daemon has no
   signal handling (that would need a library it does not carry).
8. **Live tailing and hooks:** hooks never see the log.  A tail sees a
   held repeat at most one window (plus 3 seconds) late; that is the
   trade the window sets.
9. **Lines with several lines in them** (a traceback) are one entry: they
   are compared whole, and the bracket goes before the text, on its first
   line.
10. **Whole formatted text, compared exactly**; the counter is written
    with a plain `x`, so the line reads and greps the same in every sink.
11. **#121's check comes first:** within a sync, a line it leaves out is
    not counted as a repeat either.
12. **Stacked on #121 (r-mail PR #5), not on main:** both change the
    first lines of `log()`.
