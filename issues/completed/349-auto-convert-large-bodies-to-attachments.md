# Auto-convert oversized bodies to attachments

## Overview

Messages over 128 KB currently fail to send: the sender's daemon writes an
`error-<subject>` file to their own inbox explaining the limit, marks the
recipient as `error = "body_too_large"`, and skips delivery. The user has
to manually split the content or move it to an `attach:` line.

We could instead auto-wrap the large body as an attachment, send a short
stub body, and let delivery succeed transparently.

## Current behavior

`rmail.lua:2485` in the outbox sync loop:

```lua
local body_size = #(op.body or "")
if body_size > 131072 then
    -- write error-<subject> to own inbox, mark recipient error, skip
end
```

## Proposed behavior

When a body exceeds 128 KB:

1. Write the body to a temp file (`/tmp/rmail-body-<message_id>.txt`).
2. Queue it as an attachment for this message (via the existing
   `/upload/start` → chunk upload flow — same as `attach:` lines).
3. Replace `op.body` with a short stub: `"[body delivered as attachment: body.txt]"`.
4. Continue delivery normally. The recipient sees a short inbox message plus
   an attachment.

## Design questions

**Consent flow:** attachments require recipient consent (see the consent
forms in inbox). This means a large body sends a consent form first, and
the actual content only arrives after the recipient accepts. This is
different from the seamless "send and it just arrives" behavior of small
messages. Users might be surprised.

Options:
- Accept it: large bodies behave like attachments, consent required.
- Skip consent for auto-body attachments: add a flag in the upload metadata
  like `auto_body = true` that bypasses consent on the receiver.
  (Security: the body was going to be delivered anyway — no new data leaks.)
- Scale consent by size: bodies up to some larger threshold (e.g. 1 MB) skip
  consent; above that, full attachment flow.

Recommend: skip consent for `auto_body = true` attachments up to some
reasonable cap (say 10 MB), full consent flow above that.

**Hook interaction:** `on_send` receives the body as `$3`. If we auto-convert
after hooks run, the hook sees the original large body and could exceed
argument length limits (exec's `ARG_MAX` is typically 128 KB on Linux). The
current 128 KB body cap exists partly *because* of this limit.

Options:
- Run hooks on the original body, but skip `on_send` if body > ARG_MAX. Log
  a warning. Deliver as auto-attachment.
- Run hooks on the stub body (what actually gets sent). But then hooks can't
  transform the real content.
- Pass the body via a temp file path for large messages: `$3` becomes a path
  instead of the content. Breaks the hook interface contract.

Recommend: run `on_send` only when body ≤ 128 KB. Above that, log a warning
and skip the hook. Document this limitation.

**Living messages:** if an outbox file grows past 128 KB between syncs, the
update mechanism hits the same wall. Auto-attachment via `on_update` would
let living messages scale to arbitrary size. Same hook-limit caveat applies.

**Recipient UX:** what does the stub body say? Options:
- `"[body too large — delivered as attachment body.txt]"` (clear but ugly)
- Just the first N bytes of the body (lossy; confusing when truncated)
- Nothing — empty body, attachment carries everything (simplest but
  recipients seeing an empty message might think it's broken)

Recommend: stub body with clear text. Recipients running a current rmail
client could auto-merge the attachment body into the displayed message;
older clients still work, just show two items.

## Trade-offs

- **Pro:** large messages just work. No manual splitting, no error files.
- **Pro:** aligns body + attachment pathways; less user-visible limit.
- **Con:** hooks can't transform bodies above 128 KB.
- **Con:** consent flow interacts awkwardly unless we add auto_body bypass.
- **Con:** extra temp files and cleanup logic.

## Implementation sketch

- New helper: `enqueue_body_as_attachment(op)` — writes body to temp,
  registers in `chunks-outgoing.json` with `auto_body = true`, returns the
  attachment_id to include in the `/deliver` payload.
- Modify the check at `rmail.lua:2485`: call the helper instead of writing
  the error file.
- Receiver side: detect `auto_body` in attachment metadata, skip consent.
- Cleanup: temp file removed after last chunk ack, same as regular attachments.

## Motivating example

128 KB sounds large in the abstract, but it's about 1,600 lines of source
code. Someone wanting to send a patch, a config file, or any moderately
sized text file will hit the limit quickly. Falling back to an `attach:`
line works but is user-hostile for content the user thinks of as "just
text".

## Status

Implemented with the "normal consent + attachment" variant.

- **Sender side (`sync_outbox` Phase 2):** when `op.body` exceeds 128 KB,
  the daemon writes it to a temp file under `paths.pending` named
  `<outbox-file>-body.txt`, runs it through `compress_attachment` exactly
  like any other attachment, registers a `chunks-outgoing.json` entry
  marked `auto_body = true`, and queues an `attachment_request` into the
  same network batch as the deliver. The deliver itself goes out with a
  short stub body so the inbox message isn't empty.
- **Idempotent retries:** if the deliver or attachment_request network
  call fails, the next sync cycle notices an existing
  `(recipient, message_id, auto_body)` entry in `chunks-outgoing.json`
  and re-queues the attachment_request with the same `att_id` (relying
  on the receiver-side idempotency added in #346) instead of
  compressing a second copy.
- **Receiver side:** no changes. The attachment is seen as a normal
  attachment request for `body.txt` — consent form appears, user
  accepts, chunks flow, file lands in `paths.attachments`. The earlier
  stub-body message is already sitting in the inbox and points the
  user at the attachment by name.
- **Completion cleanup:** the auto-body transfer's temp file under
  `paths.pending` is removed when the transfer completes. No
  `attach:` line to strip from the outbox file (there never was one),
  so that branch of the cleanup is skipped for `auto_body` entries.
- **Hook interaction:** `on_send` receives the stub body, not the
  original oversized body. ARG_MAX would have truncated the original
  anyway. Hook authors that want to transform bodies should keep them
  under 128 KB; above that, the hook runs on the stub.
- **Compression-failure fallback:** if `compress_attachment` returns no
  zip path, the daemon writes the old `error-<subject>` file to the
  sender's inbox and marks the recipient `error = "body_too_large"`.
  Same user-facing behavior as before this issue existed.

### Design choice — no `auto_body=true` consent bypass

The issue's original recommendation was to skip consent for auto-body
attachments (and add inline body-replacement on the receiver). Went
with the simpler "reuse the existing attachment pipeline unchanged"
path instead: the receiver sees a normal consent form for `body.txt`,
and accepts (or declines) just like any other attachment. Trade-off:
large messages carry a one-round-trip consent delay. Benefit: zero
new protocol fields, zero new receiver state transitions, zero
inbox-file merging logic.

### Scope not covered

- **Living-message updates > 128 KB:** if an outbox body grows past
  128 KB *after* initial delivery, the update flow still uses the
  direct `deliver type=update` path and isn't auto-attachment-aware.
  Running an oversized update today will still fail at the
  deliver-payload cap. Fixing it needs the same auto-body pass
  duplicated into the update side, tracked in a future issue if a
  user runs into it.
- **`on_send` for oversized bodies:** as above, always runs on the
  stub. Not a regression — ARG_MAX meant the hook never saw large
  bodies anyway.
