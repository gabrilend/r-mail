# #371 — Coalesce repeated log lines into a repeat counter

## Problem

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

## Relationship to #324

#324 already coalesces one *specific* kind of noise: N "failed to
notify X" ops in a single cycle collapse into one
`unreachable contacts: a, b, c` summary
(`note_contact_result` / `flush_unreachable_summary`, `rmail.lua:528`).

That is **semantic** grouping *within* a cycle.  This issue is
**verbatim** grouping *across* cycles — a general run-length coalescer
at the `log()` layer that catches any repeated line without knowing
what it means.  They're complementary and should both stay:
- #324 turns `fail, fail, fail` → `unreachable: aurelia` (one line/cycle).
- #371 turns that one-line-per-cycle stream → `unreachable: aurelia ×15`.

## Proposed design

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

Open.
