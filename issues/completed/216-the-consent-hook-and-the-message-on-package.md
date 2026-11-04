# #216 — An on_consent hook answers attachment forms, and on_package names the message

## Status

Completed 2026-11-03, on the branch `claude/216-consent-hook-and-package-message`.
Asked for by another project that carries files over rmail
(world-edit-to-execute's shared map-and-model lists, its issue 609b).

## Current Behavior

A consent form fires no hook.  A program that wants to answer forms for
the owner (the defensive patterns' "auto-consent from trusted contacts",
or a game that asked a contact for files) has to run on a timer, look for
`*-consent-to-download-form` files in the inbox, read the sender and file
from the form's text, and edit it.  Nothing tells it a form has arrived.

`on_package` gets the sender, the file name and the saved path, but not
the message the attachment came with.  A script that needs it has to
match files to messages by sender and name, and two messages from one
sender can carry files with the same name.

## Intended Behavior

- **`on_consent`**, a seventh hook, fires once per attachment request,
  just after the form is written.  It gets `$1` sender, `$2` the file name
  as the form shows it, `$3` the form's path, `$4` the message's inbox
  path (empty when the message is not in the inbox record) and `$5` the
  expected size in bytes.  The first line of its output, `accept` or
  `deny`, answers the form the way the owner would, by deleting the other
  line.  Anything else, including nothing, leaves the form for the owner.
- **`on_package` gets `$4`**: the inbox path of the message the attachment
  came with, empty when that message is no longer in the inbox record.
- Existing configs and hooks work unchanged: a config without
  `on_consent` runs no hook, and a script that reads `$1`–`$3` ignores the
  new argument.

## Suggested Implementation Steps

1. `rmail.lua`: `on_consent` in the `hooks` table; `upload.message_name`
   (the message lookup the form's "Attached to:" already did) and
   `upload.answer_form` (the line-deleting edit the phone's
   `/api/consent` already did), both shared; the hook's call at the end
   of `handle_attachment_request`; `$4` for both `on_package` calls
   (`save_attachments` and `handle_attachment_chunk`).
2. `scripts/hooks/on_consent.sh`, a no-op sample, and its config line for
   new mailboxes (`install.sh`, `make-mailbox-drive.sh`).
3. Docs: the scripting tutorial (interface, paragraphs, an example), the
   README's hook table, `attachments.md`, `defensive-patterns.md`,
   `helper-scripts.md`.
4. `scripts/test-consent-hook.sh`.

## Decisions

1. **The answer comes back on standard output, synchronously**, like
   `on_receive_raw` and `on_update`, rather than by the hook editing the
   form itself in the background.  Then the daemon applies it the one way
   forms are answered, it is in place before the request is answered, and
   it is logged.  The cost is that the sender's request waits for the
   hook, so the docs say to keep it quick.
2. **Only `accept` or `deny` count.**  Anything else (no output, a script
   that failed or doesn't exist, any other word) leaves the form for the
   owner, as if there were no hook.  A broken hook can never accept a
   file.  Other output is logged, cut to 40 characters.
3. **The answer is applied through the form**, by deleting the other
   line, so everything downstream (`check_consent_pending`, the answer to
   the sender, the phone's view) is unchanged.  The sender is made due at
   once, as the phone's Accept/Deny does, so the answer goes out on the
   next pass.
4. **It fires once, when the request first arrives.**  A retried request
   for a form that already exists is answered from the record before the
   form is written, and runs no hook.  It does not fire for the owner's
   own uploads from the phone, which have no form.
5. **The message is passed as the inbox file's path**, matching
   `on_receive`'s `$3`, and is empty when the message is not in the
   inbox record (deleted, or never arrived), rather than an internal
   message id.
6. **The size is the declared size, in whole bytes**, the same figure
   the form shows and the limits are built from (#310).
7. **New mailboxes name the sample hook** (`on_consent =
   ./hooks/on_consent.sh`), a no-op, like the other six.  Existing
   configs are not touched, so they run no `on_consent` until the owner
   adds it.
8. **Two helpers on the `upload` table, not new locals**, because the
   main chunk is at Lua's 200-local limit.  The phone's `/api/consent`
   now answers through `upload.answer_form`; its behaviour is unchanged.

## Not done here (written up only)

- **Several scripts for one hook** (a list in the config), so a program
  can add its hook without chaining the owner's.  Today a second script
  means one hook calling the other.
- **Sending without an inbox copy in view**: a hidden outbox, or subjects
  routed to a folder of their own, for mail between programs.  Today
  such mail and its consent forms show in the inbox, and on the phone,
  until the program clears them.

## Related

- #212 — the hooks (now seven moments).
- #215 — a hook sees every body whatever its size; its rule for a hook
  that cannot run (refuse the message) is not the rule here, where a hook
  that cannot run leaves the form for the owner.
- `docs/.templates/attachments.md` (The consent flow).
