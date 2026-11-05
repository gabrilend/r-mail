# #215 — A hook sees every message body, whatever its size, and a hook that cannot run refuses the message

## Status

Completed 2026-11-05, on the branch `claude/215-hook-body-on-stdin`
(stacked on #216's branch, which also touches the hooks).  Tested by
`scripts/test-hook-bodies.sh`.

## Current Behavior

Two hooks may rewrite a message's text before it is written into the
inbox: `on_receive_raw` (a new message) and `on_update` (the author's
edit of one).  The daemon starts each as a program (`run_hook`, which
builds one shell command line and reads the program's output with
`io.popen`), passing the sender, the subject (or file), and **the whole
body as one argument**.  The hook's output, if not empty, replaces the
body.

Linux refuses to start a program with any single argument longer than
128 KiB (`MAX_ARG_STRLEN`: 32 pages of 4 KiB).  The network side is not
the limit — rmail reads request bodies up to 50 MB — so a body over 128
KiB:

- never starts the hook (the shell reports "Argument list too long");
- leaves the daemon reading an empty output;
- and an empty output means "keep the body as it came".

So the bigger the message, the surer it is to pass unchecked.  A
checking hook — the W client's gatekeeper strips terminal-control bytes
from strangers' notes (its `docs/055`) — is silently skipped for exactly
the messages it cannot see.  Asking the sender again changes nothing:
the same body fails the same way.

For a listen-only contact (#420) the body is capped at 64 KiB, which
keeps every such message under the limit.  Every other contact can still
send past it.

Found by the W client session, 2026-10-08.

## Intended Behavior

- **The body goes to the hook another way**: on its standard input (or
  as a file whose path is the argument — to be chosen when built), which
  has no size limit.  The sender and subject stay arguments.
- **A hook that could not be run, or that stopped with a failing exit
  status, refuses the message** rather than passing it unchanged: the
  request is answered with an error the sender's daemon retries later,
  and the log says which hook failed and why.  An empty output from a
  hook that ran and succeeded still means "keep the body".
- Existing hooks keep working: the change is announced in the scripting
  tutorial, and the default orchestrators in each mailbox's `hooks/`
  read the new way.

## Suggested Implementation Steps

1. `rmail.lua`, `run_hook`: write the body to the hook's standard input
   (two-way `io.popen` is not available in plain Lua, so likely via a
   temporary file in the mailbox's RAM folder, removed after) and return
   the output together with whether the hook ran and succeeded.
2. The four callers (`handle_deliver_message`, `handle_deliver_update`,
   and the two self-delivery paths in `sync_outbox`): a failed hook
   refuses the message.
3. `scripts/hooks/` orchestrators and the scripting tutorial
   (`docs/.templates/scripting-tutorial.md`): read the body from standard
   input.
4. Test: a 200 KiB body reaches a hook that records what it got; a hook
   that exits non-zero, or does not exist, makes the delivery fail and
   the sender retry; a small body behaves as before.

## Decisions

1. **Standard input, not a file path.**  The body goes to the hook on
   its standard input, through a private temporary file (`os.tmpname`,
   which Lua makes with mode 0600) that the shell redirects and rmail
   removes after.  A path argument would need every hook to open a file;
   stdin is what `fold`, `sed` and `cat` already read.
2. **`$3` stays, up to 64 KiB.**  A hook written to read `$3` keeps
   working for every body it could always see.  A longer body leaves `$3`
   empty, rather than cut short, so a hook can never mistake a part for
   the whole.  64 KiB is half of Linux's 128 KiB per-argument limit,
   leaving room for the shell's quoting.  The cost: an old hook that reads
   only `$3` now sees an empty body for a message over 64 KiB, and by its
   own logic may print nothing, which keeps the body unchecked, as before
   this issue.  The tutorial, the README and the shipped samples all say
   to read stdin.
3. **What counts as failing.**  Exit status 127 ("could not be run: not
   found"), 126 ("not executable"), any other non-zero status ("stopped
   with exit status N"), and a shell that would not start.  The status
   is read from a marker the shell prints after the hook's own output
   (byte 0x1E, then the number), because `io.popen`'s close reports no
   status in Lua 5.1 or LuaJIT, and `run-rmail.sh` may pick either.
4. **A refusal is a 500 with an error, logged with the hook's reason.**
   The sender's daemon reads any answer that is not success or 404 as
   "keep it and try again" (a deliver, an update), and an answer with a
   status as "reached", so the contact is not backed off as unreachable.
   Nothing is written before the hook runs, so a refusal leaves no trace
   on the receiving side.
5. **Mail to yourself is held the same way.**  A refused note to self is
   neither written nor recorded, and its outbox file is kept (it would
   otherwise be cleaned up as having "no recipients left"); the next pass
   tries again.  A refused edit of a note to self stays owed.
6. **`on_send` gets the body on stdin too, but its failure is only
   logged** and the body is sent as written.  The issue covers the two
   hooks that guard what comes in; holding outgoing mail on a broken
   `on_send` is a different choice, left as an open question below.
7. **One function.**  `run_hook` takes the body as a table at the end of
   its arguments (`{body = text}`) and returns the output, whether it
   ran and succeeded, and why not.  No new top-level local: the main
   chunk is at Lua's 200-local limit (#216's decision 8).

## Tested

`scripts/test-hook-bodies.sh` runs two real daemons on this machine:

- a short body: `$3` and stdin agree, and the hook's output is saved;
- a 100 KiB body: `$3` empty, all of it on stdin, saved as the hook
  printed it;
- a hook that exits 3, and one that runs a program that is not there:
  nothing written while it refuses, the log says why, and once the hook
  works the sender's daemon sends it again and it arrives through the
  hook;
- a note to self refused by the sender's own `on_receive_raw`: kept in
  the outbox, delivered on a later pass;
- an edit to a 200 KiB body: `on_update` sees all of it on stdin and its
  output is saved.  Before this change the hook never started for it.

Against #216's `rmail.lua` (the base) the same test fails 10 cases.  Not
covered: a refused edit of a note to yourself (the code path is the
same rule; no test drives it).

## Open questions

1. Should a failing `on_send` hold the message (not sent this pass,
   tried again), as a failing `on_receive_raw` does?  Today it is logged
   and the body goes as written.
2. Should rmail say once, in the log, when a body hook is given a body
   over 64 KiB, so an owner with an old `$3`-only hook learns why it saw
   nothing?

## Related

- #420 — the listen-only contact, whose 64 KiB cap covers website notes
  in the meantime.
- The W client project, `docs/055` ("Bodies past 128 KiB skip the
  checker").
