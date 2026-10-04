# #new-file-watchers-wake-the-sync — Saving a file wakes the daemon at once

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it.

## Current Behavior

The daemon does not poll its folders.  The kernel tells it when the
outbox or the contacts file changes, and a sync cycle runs at once
(#new-one-daemon-one-mailbox).  Two watchers:

| watched | events | so that |
|---|---|---|
| the `outbox/` folder | a file closed after writing, created, deleted, moved in | a saved message goes out without waiting for a timer |
| the `contacts` file | closed after writing, modified | a new contact or address takes effect at once; the file is lined up again (#new-the-contacts-file) |

Each watcher is a file descriptor; the main loop puts it among the
sockets it waits on (wrapped to look like a socket to `select`).  After
a cycle, events the cycle itself caused — the daemon writes markers into
outbox files, and lines up the contacts file — are read and dropped, so
they do not start the next cycle.

**Which kernel.**  Linux has inotify; macOS and the BSDs have kqueue.
Two small C modules expose the same four functions (`init`, `add_watch`,
`read`, `close`) and the same event names, so the daemon is written once.
Whichever loads is logged at start-up ("outbox watcher active via
inotify").  This is platform dispatch, not a fallback: a machine with
neither stops at start-up with both errors, rather than quietly polling
a timer-tick behind.

The kqueue module has never been compiled or run.  Its owner's note, as
written at the top of `rmail_kqueue.c`:

> I don't have a Mac.  An LLM wrote this.  It might not work.  If it
> doesn't, then... sorry?  Fix it yourself I guess.  Wish I could do
> better for you.

#384 (running on macOS) is where it gets finished.

## Intended Behavior

As above.  #396 is the open gap: an outbox change made *during* a cycle
can be drained with the cycle's own events and wait for a timer.

## Suggested Implementation Steps

1. `rmail_inotify.c` (Linux), `rmail_kqueue.c` (macOS/BSD); both built by
   `scripts/install.sh` into `libs/`.
2. `rmail.lua`: the module choice near the top (`inotify`,
   `WATCHER_KIND`), `inotify_wrap`, `start_dir_watcher`,
   `start_file_watcher`; in `main`, the watchers in the `select` set and
   the drain after each cycle.

## Related documents

- `#384`, `#396`, `#new-one-daemon-one-mailbox`
