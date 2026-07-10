# #374 — Set received message file mtime to the sender's creation time

## Summary

When a message is received and written to `inbox/`, its file
modification time currently becomes "now" (the moment the receiving
daemon called `write_file`).  Instead, set it to **when the message was
created on the sender's machine**, so a file-manager / `ls -lt` view of
the inbox reflects authored order, not delivery order.

## Why

The inbox is "just files."  Users sort and scan by mtime.  A batch of
messages that were composed over days but all *received* in one sync
cycle currently collapse to the same timestamp, losing the real
chronology.  Preserving the origin time makes the plain-files model
behave the way users expect from email.

## Current state

- The deliver payload (`handle_deliver_message`, `rmail.lua:1424`)
  carries `subject`, `message_id`, `body`, `attachments` — **no
  timestamp**.  The sender never transmits a creation time.
- The send-side op builds `{message_id, subject, body}` at
  `rmail.lua:3684` / `3695` — nowhere to source a timestamp from today.
- The daemon has **no LuaFileSystem** (`grep lfs` finds only a comment
  noting it deliberately avoids the dependency).  So there is no
  in-process `lfs.touch`; setting mtime means shelling out.

## Proposed mechanism

1. **Sender:** add a `created` field (Unix epoch seconds) to the
   deliver payload, sourced from the outbox file's mtime at send time.
   With no lfs, read it via `io.popen("stat -c %Y " .. shell_quote(path))`
   (GNU coreutils, which NixOS uses).
2. **Receiver:** after `write_file(target, …)` in
   `handle_deliver_message`, if `data.created` is present, apply it:
   `os.execute("touch -d @" .. tonumber(data.created) .. " " .. shell_quote(target))`.
   Same for the self-delivery branch (`rmail.lua:3355`) once #372 lands.

## The thin-client wrinkle (important)

"Created on the sender's machine" is ambiguous for the Android
thin-client.  When the phone composes a message:

- The outbox file is *uploaded* to the server; its mtime **on the
  server** is upload time, not the phone's compose time.
- So sourcing `created` from the server-side outbox mtime gives *upload*
  time, not *authoring* time.

To preserve true authoring time for phone-composed messages, the
**client** must send its intended `created` timestamp when it uploads
the outbox file (the `/api/upload` / phone-created-outbox path,
`rmail.lua:4385`), and the daemon must honor it rather than re-stat the
uploaded file.  For daemon-to-daemon sends, the outbox mtime is the
right source.

## Open questions

- Source of truth for `created`: outbox file mtime, or an explicit
  compose-time header the composer writes into the message?  Files get
  edited (mtime moves); an explicit header is more stable but needs
  composer support on every client.
- Apply to **attachments** too, or messages only?  (Issue title says
  messages; attachments may deserve the same treatment.)
- `touch -d @epoch` is GNU-specific.  Do we care about BSD/macOS daemon
  hosts (would need `touch -t` formatting)?  Probably not today, but
  note it.
- Timezone/clock-skew: `created` is absolute epoch seconds, so TZ is a
  non-issue, but a sender with a wrong clock would set a wrong mtime.
  Accept as-is, or clamp to `<= now`?
- Should received mtime ever be allowed to move *backwards* on a later
  update (#-style edit) to the same message, or only set once on first
  receipt?

## Status

Open.
