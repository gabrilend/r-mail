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

Not started. Relates to the 128 KB body cap tip in `docs/scripting-tutorial.md`.
