# #372 — Self-delivery silently drops attachments (loopback must still use the chunk system)

## Problem

Sending a message to your own name (`to: sorelu` on the sorelu
mailbox) delivers the **body only** — any `attach:` files are silently
dropped.  No consent form is created, no file is transferred, no error
is logged.

Confirmed from a real 2026-07-10 test.  Outbox file `Iiiiiiiiiiiiiii`:

```
to: sorelu
attach: /home/ritz/mail/attachments/.uploads/1a009c19-…/20260707_020325.jpg
attach: content://com.android.externalstorage.documents/…/20260528_153135.jpg

Abcdefg
```

The body `Abcdefg` landed in the inbox; both attachments vanished.  The
first attach was a valid 2.6 MB file already staged on the server — so
the file wasn't the problem, the delivery path was.

## Root cause

`sync_outbox` special-cases `rname == my_name` (`rmail.lua:3332`):

```lua
-- new recipient: deliver message body only
if rname == my_name then
    -- self-delivery: write directly to own inbox
    ...
    write_file(target, inbox_body)
    ...
end
```

The branch writes the body and marks the recipient delivered
(`{self = true}`).  It never inspects `attach:` lines.  Only the
`elseif contacts[rname]` branch (a real remote contact) enqueues the
`deliver` op that drives the attachment announce → consent → chunk
pipeline.  So self = no attachments, by construction.

## Why the naive fix is wrong

The tempting fix — "in the self branch, just copy the attach file into
`attachments/` locally" — is **incorrect for the thin-client case**,
which is the case that matters here.

The sorelu **server** (daemon) and the Android **client** are
different machines that share one mailbox *identity* (`sorelu`).  The
Android app is a thin client with its own, separate filesystem.  When
you "send to sorelu" from the phone:

- The attachment lives on the **phone**, not the server.
- The phone uploads it to the server's chunk/upload staging
  (`attachments/.uploads/…`) — that's how the 2.6 MB file got onto the
  server at all.
- The result must become a **proper inbox attachment on the server**:
  one that is checksum-verified, decompressed from its zip, and
  **downloadable via `/api/attachments`** so it syncs back to *every*
  own device (including the phone's separate filesystem).

A local `cp` into `attachments/` skips checksum verification, zip
handling, and — critically — may not register the attachment in the
inbox metadata the sync/download path relies on.  So the file could
land on the server yet never sync to the phone, or land unverified.

**Therefore loopback attachments must still go through the chunk
system.**  What loopback *can* skip is the interactive consent prompt
(you don't need to ask yourself for permission), but the actual
transfer + reassembly + verification must run.

## Proposed direction (not final)

Make the self-delivery branch route attachments through the existing
chunk machinery with consent **auto-accepted**, rather than skipping
them:

- Reuse `announce`/`chunks-outgoing`/reassembly so the attachment is
  compressed, checksummed, and materialised as a real inbox attachment
  exactly like a remote delivery.
- Short-circuit only the consent *handshake*: a self-transfer
  auto-consents (no `*-consent-to-download-form` written to the inbox,
  or one that's immediately auto-accepted).
- Because sender and recipient are the same daemon, the "over the wire"
  step is local — the chunk reassembly should run in-process against
  the already-uploaded `.uploads/…` staging rather than opening a TCP
  socket to ourselves.  (Exact mechanism TBD — see open questions.)

## Open questions

- Does the daemon transfer chunks to itself over a loopback socket, or
  do we add an in-process path that feeds `.uploads/…` straight into
  the reassembly/verification code without a network hop?  The latter
  is cleaner but duplicates a code path.
- Where does auto-consent live — a flag on the announce, or a
  self-detection at consent-check time (`from == my_name`)?
- Does this interact with the stale hashed `from`/`to` values in
  `consent-pending.json` / `consent-responses.json` (see below)?
- Multiple `attach:` lines (this test had two) — all must transfer, and
  the loop must not stop at the first.

## Related, separate issues surfaced by the same test

These are **not** part of this issue but were found alongside it and
should be filed/fixed separately (they're Android-client bugs; the
client "hasn't been updated in a while"):

1. **`content://` URIs reach the outbox unresolved.**  Attach #2 above
   is an Android SAF URI, not a filesystem path — the daemon can't read
   it, so it would fail even to a remote contact.  The client resolved
   attach #1 into an uploaded file but not attach #2.
2. **Garbled outbox filenames.**  `Iiiiiiiiiiiiiii` (this test) and
   `aattaacchhmmeenntt--tteesstt` (an older kuvalu test) show the client
   mangling filenames with repeated/doubled characters.
3. **Stale #348 hashing in consent state.**  `consent-pending.json` and
   `consent-responses.json` still hold `from`/`to` as
   `sha256("rmail:contact:<name>")` digests (e.g. `7e00c6e1…` =
   `kuvalu`).  The #348 reversal's `unmigrate_hashed_keys` migrates map
   *keys*, not these *field values*, so they were missed.  A
   loopback/consent fix should also resolve/migrate these.

## Origin

Filed 2026-07-10 while diagnosing "text arrived, image didn't" on a
phone → own-mailbox (`sorelu`) send.

## Status

Open.
