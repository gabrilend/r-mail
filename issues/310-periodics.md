# Periodics — scheduled app polling as a hook-script pattern

## Overview

"Periodics" are scheduled checks that poll other apps or data sources at
regular intervals — e.g. check the calendar app every 30 minutes and
send events to the desktop via an rmail message.

Rather than baking a scheduler into the daemon, periodics are a
**hook-script pattern**: a self-re-queuing message that ticks down on
every sync cycle and fires its payload when the timer hits zero.

## The pattern

1. A script-generated message lives in the outbox with a header field
   like `remaining_ms: N`.
2. On each sync cycle, a hook script (`on_receive` or a periodic-aware
   equivalent) reads the message, computes `elapsed = now - last_cycle`,
   subtracts that from `remaining_ms`, and either:
   - rewrites the message with the updated timer if `remaining_ms > 0`,
     or
   - runs the payload (e.g. poll the calendar, build a message to the
     desktop) and re-queues a fresh timer if the periodic repeats.
3. The daemon needs no concept of "scheduled tasks" — the message file
   itself is the state, and the hook script is the logic.

## Why this is better than a built-in scheduler

- No new daemon-side machinery (no persistent counters, no function
  pointer swapping, no config-file scheduling syntax).
- Users learn the recursive-scheduling pattern and can adapt it to any
  scheduling need, not just the shapes we anticipated.
- Per-mailbox timing falls out for free: the pattern only needs the
  sync-cycle duration, which the user controls.

## Documentation deliverables

- A minimal worked example in the scripting tutorial ("decrement a
  counter and display fizzbuzz" or similar), so users see the pattern in
  isolation before they try to apply it.
- A second, real-world example showing the calendar-poll use case.

## Dependencies

- Hook system and scripting tutorial (already present).
- #309 (Android script editor) — so phone users can write these scripts
  without an external editor. Note that #309 is now low priority and
  blocked on unresolved execution-environment questions, which makes the
  phone-side variant of periodics low priority too. The desktop-side
  variant can proceed independently of #309.

## Status

Design phase. Previously scoped as a built-in scheduler; re-scoped to
hook-script pattern.
