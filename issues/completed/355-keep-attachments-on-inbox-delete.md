# #355 — Don't auto-delete attachments when the inbox message is deleted

## Problem

Today, deleting an inbox message cascades into deleting every
attachment that came with it. That was added in commit `8e75fbd`
("Clean up attachments when recipient deletes inbox message") with
the rationale "don't leave orphaned files on disk."

From a user's perspective this is surprising. They might delete a
message to clear their inbox but want to keep the photo, the PDF,
the source file. The "tidy up disk" goal is really the filesystem
owner's concern, not the daemon's — the user can always `rm`
their attachments if they want.

## Proposal

Remove the `delete_inbox_attachments(meta)` calls from every
delete path:

- `handle_delete` (inbox path, line ~1343): sender deleted their
  end, cascading to our inbox.
- `sync_inbox` (line ~2704): user locally deleted an inbox file,
  we're about to notify the sender.
- `self_delete_from_inbox` (line ~3348).
- Shared-device delete path (line ~3787).

Leave `inbox_state[filename].attachments` metadata alone — it's
internal state about where each attachment ended up on disk; not
PII-critical and harmless to keep until #348's PII cleanup pass
rewrites state anyway.

## Alternative: "move to trash" compromise

If orphan buildup turns out to matter in practice, the daemon could
move rather than delete — e.g. rename attachments to a hidden
`.deleted/` subdirectory in `~/mail/attachments/` on message
deletion. User reclaims space by clearing `.deleted/` manually.
Not proposing this for the first pass; just noting the option.

## Side note: chunked attachments already aren't cleaned up

`delete_inbox_attachments` only removes attachments tracked in
`inbox_state[filename].attachments`, which is populated by
`save_attachments()` — that runs only for inline attachments
bundled into a deliver payload. Chunked attachments go through
`handle_attachment_chunk` completion and never land in
`inbox_state.attachments`, so they've always survived inbox-message
deletion. This issue makes inline behave the same way, producing
the consistency we want.

## Status

Shipped.

- Removed the `delete_inbox_attachments` helper and all four call
  sites: `handle_delete` (sender-initiated), `self_delete_from_inbox`,
  `sync_inbox` (user-local delete), and the Android
  `/api/inbox/delete` handler.
- All delete paths now leave `paths.attachments` untouched. Deleting
  an inbox message removes the inbox file + clears the state entry
  + fires `on_delete` + notifies the sender as before; the
  accompanying attachment files stay in place.
- Inline and chunked attachments now behave consistently — neither
  gets cascaded out on message deletion. Chunked attachments never
  did (they weren't tracked in `inbox_state.attachments`); inline
  ones were being deleted and now aren't. The surprising asymmetry
  is gone.

### Users who want the old behavior

No built-in option. The fix is intentional: the daemon should not
silently delete user data. A future helper script or CLI command
could implement "delete message and its attachments" as an explicit
opt-in action, but it's out of scope for this issue.
