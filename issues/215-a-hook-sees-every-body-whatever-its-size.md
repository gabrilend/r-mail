# #215 — A hook sees every message body, whatever its size, and a hook that cannot run refuses the message

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

## Related

- #420 — the listen-only contact, whose 64 KiB cap covers website notes
  in the meantime.
- The W client project, `docs/055` ("Bodies past 128 KiB skip the
  checker").
