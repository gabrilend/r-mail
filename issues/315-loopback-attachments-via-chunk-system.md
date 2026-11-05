# #315 — Self-delivery silently drops attachments (loopback must still use the chunk system)

## Current Behavior

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

## Intended Behavior

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

## Suggested Implementation Steps

1. Answer the open questions (an in-process path or a loopback socket;
   where auto-consent lives).
2. The self-delivery branch of `sync_outbox` offers each `attach:` path to
   the mailbox itself through the answers record (#312) and the packed
   copy (#314), with consent given at once; the unpacking and filing are
   the receiver's own (#311).
3. Test: a message to oneself with two attachments; both arrive in
   `attachments/` byte for byte, and no consent form is left.

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
3. **Stale #505 hashing in consent state.**  `consent-pending.json` and
   `consent-responses.json` still hold `from`/`to` as
   `sha256("rmail:contact:<name>")` digests (e.g. `7e00c6e1…` =
   `kuvalu`).  The #505 reversal's `unmigrate_hashed_keys` migrates map
   *keys*, not these *field values*, so they were missed.  A
   loopback/consent fix should also resolve/migrate these.

## Origin

Filed 2026-07-10 while diagnosing "text arrived, image didn't" on a
phone → own-mailbox (`sorelu`) send.

## Status

Built 2026-11-05: a message to oneself brings its attached files, filed
as received attachments in-process, with no consent form.  The three
separate problems listed above (unresolved `content://` URIs, garbled
filenames from the Android client, hashed `from`/`to` values in consent
state) are not part of this and stay open.

## Decisions (2026-11-05)

Made by the builder; the owner can overturn each.

1. **In-process, not a loopback socket.**  A daemon answers nobody while
   its own sync waits on a reply (the open "blocking sync cycle stalls
   inbound" issue, and why the tests use a stand-in recipient), so it
   cannot fetch pieces from itself.  The duplicated code path the
   question feared is avoided by moving the receiver's last step --
   unpack with the zip reader under the #310 limit, file each entry
   without overwriting (#311), run `on_package` -- into
   `upload.file_received`, which a contact's transfer and a message to
   oneself both call.  What is skipped is only the wire: the file is
   still packed, the checksum read back from the packed copy, and the
   copy unpacked and filed exactly as a contact's would be, so it lands
   where `/api/attachments` serves it to every own device.
2. **No consent, by self-detection.**  A message to oneself never makes
   an offer at all, so there is no form to answer and no flag on any
   announcement.  It is the self-delivery branch of `sync_outbox` that
   knows.
3. **The hashed consent values are not touched.**  A message to oneself
   never writes `consent-pending.json` or `consent-responses.json`, so it
   neither depends on nor repairs them; that stays its own problem.
4. **Every `attach:` line, and the body waits for them.**  As for a
   contact, the body is held, with the outbox's `MISSING ATTACHMENT`
   note, until every attached path exists (a file still uploading from
   the phone, say); then the body goes, then the files, each answered
   in the record (#312) as `complete`, or `cancelled` if it can never be
   filed.  A path missing or changing at that moment is tried again next
   pass, and an `attach:` line added after delivery is filed too.
   Nothing answered is filed again.  (A `content://` URI never exists on
   the server, so it now holds the message with a note rather than being
   dropped silently -- as it would for a contact.)

Tested by `scripts/test-attachments-to-self.sh` (11 cases): the body
held until a missing file appears; a file staged under
`attachments/.uploads/` (as the phone leaves it), a folder and a plain
file filed byte for byte; no consent form; `on_package` run for each
with the message's inbox file; the record answering each `complete`;
nothing left in the pending folder; an added line filed; nothing filed
twice.  Each was shown to catch a mutant of the code it covers.
