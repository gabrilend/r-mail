# #404 — A received attachment is untrusted input, and is checked as one

## Status

Open, 2026-09-29.  Numbered in phase 4 because phase 3 is full (see
`phase-4-progress.md`); it belongs with attachments when #402 re-sorts
the phases.  The owner approved every fix below on 2026-09-29 ("yes,
everything that you mentioned"); #404e was found during the work and
added.

Done: #404a, #327 (reopened and closed), #404b, #404d, #404e — each with
its own test, all passing.  Open: #404c, whose daemon side is done and
tested but whose phone-app change has not been built (no Android SDK on
the machine it was written on).  Until the new app is installed, phone
uploads are refused.

## Current Behavior

A contact who holds a shared key can send an attachment: a request (file
name, declared size), the owner's consent, then numbered chunks of a zip
file, each carrying its own SHA-256 and the whole zip's SHA-256.  The
receiving daemon reassembles the zip in `<pending>/.pending/<id>/`,
extracts it into an `extract/` folder there, and files each entry into
`attachments/`.  The phone can read anything in `attachments/` through
`/api/attachments/<name>`, and the `on_package` hook is handed the path.

Every point below is now checked; the sub-issues describe how.  The
list is kept as the record of what a read of this path on 2026-09-29
found it trusting:

1. **Symbolic links.**  A zip can hold a link entry; `unzip` recreates it.
   A link named `photo` pointing at `~/.ssh/id_rsa` is filed into
   `attachments/`, and the phone (and the hook) then read the owner's
   private key through it.  A later entry in the same zip can also be
   written *through* a link made earlier.
2. **Unpacked size.**  Only the packed bytes are counted; a small zip can
   unpack into gigabytes (reopened as #327).
3. **Phone uploads.**  The unpacking step ignores whether `unzip`
   succeeded, joins every entry of a many-entry zip into one file, and
   never checks the chunk checksums the phone already computes.
4. **Missing checksums pass.**  A chunk with no checksum, or with no
   whole-file checksum, skips the check instead of being refused.
5. **Counts from the sender, each time.**  Every chunk says how many
   chunks there are and which one it is, and each is believed on its own.
   A file that changes while the sender is packing it is sent torn.

## Intended Behavior

Everything that arrives from a contact is treated as a claim until the
daemon has checked it:

- No link is ever created from a received zip.  In its place is a plain
  text note saying where the link pointed, so a person or an agent who
  wonders why something is missing finds the reason and can make the link
  by hand if it is valid.  Nothing in `attachments/` is served through a
  link.
- The unpacked size is measured before extraction (#327).
- A phone upload is verified chunk by chunk and as a whole, must be one
  file, and fails loudly when unpacking fails.
- Checksums are required, not optional.
- The number of chunks is fixed for a transfer, chunk numbers are checked,
  and a file that changes during packing is packed again.
- Found while doing this: attachment ids are used in folder names and in
  `rm -rf` without being checked, and chunks are accepted before the
  owner has said yes.  Both are fixed here too.

## Sub-issues

| ID | Name | Dependencies | Description |
|---|---|---|---|
| 404a | symbolic-links-become-notes | None | never recreate a link from a received zip; write a note instead; refuse to serve links |
| 327 | reject-oversized-transfers (reopened) | 404a | measure the unpacked size before extracting |
| 404b | chunk-checksums-and-counts-are-required | None | refuse chunks without checksums; fix the chunk count per transfer; check chunk numbers |
| 404c | phone-uploads-are-verified | 404a | per-chunk and whole-file checksums, one entry, checked unzip |
| 404d | files-changing-while-packed-are-packed-again | None | compare size and time before and after packing |
| 404e | attachment-ids-and-consent-are-checked-first | 404b | ids must look like ids; no chunk before consent |

Execution order: `404a → 327 → 404b → 404c → 404d → 404e`.  404a and 327
share the new unpacking step; 404b and 404e both change the chunk
handler, so they go one after the other.

## Suggested Implementation Steps

1. A stand-in contact for tests, `scripts/lib/fake-contact.lua`, that
   speaks rmail's encrypted request format with a shared key, so a test
   can send a real daemon things no honest daemon would; shared set-up for
   such tests in `scripts/lib/test-receiver.sh`.  Done.
2. The sub-issues in the order above, each with its own test script and
   commit.  Done except the phone build in #404c.
3. A control test, `scripts/test-attachment-round-trip.sh`: an honest
   attachment between two real daemons still arrives.  Done.
4. `docs/.templates/attachments.md` (the tracked source of
   `docs/attachments.md`): "What a received attachment is not allowed to
   do".  Done.

## Tests

    scripts/test-received-links.sh           #404a
    scripts/test-unpacked-size.sh            #327
    scripts/test-chunk-rules.sh              #404b
    scripts/test-phone-upload-checks.sh      #404c (daemon side)
    scripts/test-torn-pack.sh                #404d
    scripts/test-attachment-ids-and-consent.sh  #404e
    scripts/test-attachment-round-trip.sh    control: an honest transfer

Each builds its own throwaway mailboxes under `/tmp/rmail/tests/` on its
own port, so they can run together.

## Related

- #327 — reopened for the unpacked size.
- #391 — attachment pipeline audit (extract privately, then file).
- #314 — Android third-party outbox security (another trust boundary).
