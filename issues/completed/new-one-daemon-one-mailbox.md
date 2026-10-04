# #new-one-daemon-one-mailbox — One daemon serves one mailbox: starting up, and the loop it runs

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it.  The foundation the rest of phase 1
stands on.

## Current Behavior

**What a mailbox is.**  A folder holding a `config` file, `inbox/`,
`outbox/`, `attachments/`, `contacts`, and `.state/` (the daemon's
records, JSON files).  One daemon process serves exactly one mailbox,
named by exactly one argument: the path of its config file.  The mailbox
is the folder that file sits in; it is written nowhere else, so it
cannot be written wrongly (#382 tells why the older forms — a mailbox
argument, a `mail =` line — were removed).  A machine can run several
mailboxes, each with its own daemon and its own port.

**Starting up**, in order:

1. Read the config: `key = value` lines, `#` comments; the words `true`
   and `false` become booleans, everything else stays text (quotes are
   kept as part of the value).  `name` (this mailbox's word for itself)
   and `port` (1–65535; there is no default) are required: a missing or
   bad one stops the daemon with the reason.
2. Make the mailbox's folders if missing; sweep the pending folder of
   anything no record holds (#404f).
3. Line up the contacts file (#new-the-contacts-file), then log the start, the JSON
   decoder in use (#403) and the encryption.
4. Start the two file watchers — the outbox folder and the contacts file
   (#new-file-watchers-wake-the-sync).
5. Claim the port: TCP on IPv4 (a failure here writes a `CANNOT-LISTEN`
   notice into the inbox, says what holds the port, and exits — nothing
   can arrive while this is broken), TCP on IPv6 if the system has it,
   and UDP on the same port for LAN discovery (#102).
6. Only then the slow, optional network work: clear an old router port
   mapping, the router security check, an automatic port forward if
   configured (#new-automatic-port-forwarding); find this machine's own addresses (#353) and queue
   an announcement of them to every contact (#new-announcing-a-new-address).

**The loop.**  One thread.  Each pass waits in `select` on: the
listening sockets, the two watchers, and every open client connection
that is waiting to read or write.  The wait is at most the time until
the earliest contact's timer comes due (#377), the next address
re-check (#379), or 3 seconds.  Then:

- a new connection gets its own coroutine running the request handler
  (#new-encrypted-frames for what travels on it); a coroutine yields when its socket would
  block and is resumed when `select` says it is ready (#104);
- every 3 seconds: if the mailbox's `.state` folder can no longer be
  opened twice running (a drive unplugged), the daemon exits; with
  `--once=SECONDS` it exits once that window has passed (a portable
  drive's visit);
- when the outbox changed, the contacts changed, or any contact is due:
  connections idle for 30 s are closed, waiting LAN-discovery packets are
  read, and **one sync cycle runs** (#new-the-sync-cycle) — inline, not as a coroutine,
  so no request is handled while it runs (the source of #387).  Errors
  inside it are caught and logged as "sync error"; the loop goes on.

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`, top: `parse_config_file`, the argument block (the
   config's folder becomes `MAIL`), the `paths` and `cfg` tables (one table
   each, not many top-level locals: Lua allows a file 200, and the daemon
   sits at the limit — #106, #201).
2. `init_runtime`: the start-up order above; `report_problem` /
   `clear_problem` for the inbox notices.
3. `main`: the `select` loop, `make_async_socket` (a socket whose reads
   and writes yield), the mailbox-gone check, `--once`.
4. Tests: `scripts/test-mailbox-selection.sh` (which config, which
   mailbox, a port already taken), `scripts/test-log-location.sh`.

## Related documents

- `#382` (the mailbox is the installation), `#new-encrypted-frames`, `#104`, `#new-file-watchers-wake-the-sync`,
  `#new-the-sync-cycle`, `#377`, `#387`
- `docs/.templates/service.md`
