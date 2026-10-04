# #212 — Hooks: the owner's scripts, run at six moments

## Status

Completed — a blueprint written 2026-10-04 (#621) for what was built
before issue files described it, drawing on #207 and #213.

## Current Behavior

A mailbox may name a script for each of six moments, in its config.
A path that is not absolute is read from the folder holding the config
(`./hooks/on_receive.sh` is this mailbox's own copy, #102); `~` is
expanded; an empty value (`""`, `''`) turns the hook off.

| hook | when | gets | its output |
|---|---|---|---|
| `on_send` | before a message or edit is sent | recipient, subject, body | replaces the body sent, if not empty |
| `on_receive_raw` | a message arrives, before it is written | sender, subject, body | replaces the body written, if not empty |
| `on_receive` | after it is written, in the background | sender, subject, path of the inbox file | ignored |
| `on_update` | an edit arrives, before it is written | sender, path, new body | replaces the body written, if not empty — print the old body to refuse an edit |
| `on_delete` | a message is deleted, either side | the other party | ignored |
| `on_package` | an attachment is saved, in the background | sender, file name, path in `attachments/` | ignored |

Arguments are passed shell-quoted.  A hook that transforms (`on_send`,
`on_receive_raw`, `on_update`) runs synchronously and its standard
output is read whole; its exit status is not checked.  A message to
oneself passes through `on_send` and then `on_receive_raw`.

Hooks are how rmail is extended without changing the daemon: the
periodics pattern (#707), shared files (#708, tried and rejected), the
defensive patterns and the scripting tutorial in the documents.  The
installer copies sample hooks into each mailbox's `hooks/` folder
(`scripts/hooks/`).

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`: `_hook_or_nil`, `_hook_path`, the `hooks` table,
   `run_hook`; the calls in `sync_outbox` (send, self-delivery),
   `handle_deliver_message`, `handle_deliver_update`, `sync_inbox` and
   `handle_delete` (delete), `save_attachments` and the chunk handler
   (package).
2. `scripts/hooks/*.sh`: the samples.

## Related documents

- `docs/.templates/scripting-tutorial.md`, `docs/.templates/defensive-patterns.md`
- `#207`, `#213`, `#707`, `#708`, `#102`
