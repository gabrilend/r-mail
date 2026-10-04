# #116 — What the daemon says, where, and how it tells the owner about problems

## Status

Completed — a blueprint written 2026-10-04 (#621) for what was built
before issue files described it, drawing on #117, #114, #102 and #121's
log move.

## Current Behavior

**Every line twice.**  Each log line — `YYYY-MM-DD HH:MM:SS` and a
sentence — goes first to standard error, always (the journal under
systemd, the terminal when run by hand), then to a plain file that can be
tailed and grepped.  The file copy is never allowed to take the journal
copy down: if it cannot be opened, one line says so and the daemon
carries on with the journal only.

**Where the file is.**  `log_file` in the config; by default
`/tmp/rmail-progress/log-<mailbox path with / as ->`, in the machine's RAM
folder, named after the mailbox so that two mailboxes on one machine
never interleave lines (#612).  It used to sit in the mailbox's `.state`
folder on disk; the owner moved it to RAM (2026-09-23, #121) because it
records every exchange with a contact by name and time, and that record
should not outlive a reboot.  `log_file = ""` keeps the journal copy
only.  At 5 MB the file is renamed `.1` (replacing the previous `.1`) and
a new one started.

**Saying less.**  Repeated news is folded: one "unreachable contacts this
cycle" line instead of a line per failed request (#114), a backoff logged
only when the interval actually changes, a stray directory warned about
once per run.  #118 plans counting repeated lines in general.

**Problems as mail** (#102).  A log is not where anyone looks when mail
stops; the mailbox is.  A problem the owner must act on is written as a
file in the mailbox, in the folder of the direction that broke: a port
that cannot be claimed is inbound news (`inbox/CANNOT-LISTEN`); a problem
on the way out goes in `outbox/`.  Each such file ends with a line saying
the daemon wrote it and will write it again if the problem persists; the
daemon removes it itself when the problem is over.  Smaller problems are
written beside the line they are about: `// UNKNOWN CONTACT`,
`// AMBIGUOUS RECIPIENT`, `// MISSING ATTACHMENT`, `// ATTACHMENT LOST`
under a `to:` or `attach:` line (#202, #314).

**Reading it.**  `scripts/view-logs.sh` follows the log of a mailbox's
service, choosing among several, and falls back to `journalctl` on a
machine whose service logs only to the journal.

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`: `_log_file` (the setting, quotes, `~`, the default),
   `log_handle`, `log_rotate`, `log` (`LOG_MAX_BYTES`); `report_problem` /
   `clear_problem`; `mark_recipient_problem`, `mark_missing_attachment`,
   `answers.lost`.
2. `scripts/view-logs.sh`.
3. Test: `scripts/test-log-location.sh` (the default place, an explicit
   one, an empty one, an unwritable one — the journal copy survives).

## Related documents

- `#117`, `#114`, `#118`, `#612`, `#102`, `#121`
- `docs/.templates/service.md`
