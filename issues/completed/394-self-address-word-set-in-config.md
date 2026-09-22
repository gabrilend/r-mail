# #394 — Sending to yourself uses a word set in the config, not the mailbox name

## Status

Completed 2026-09-22.  Tested by `scripts/test-mailbox-selection.sh`
(self-address, label refusal, malformed word, and old-record cases).

## Current Behavior

Built as described under Intended Behavior:

- `self_address` (config, optional, one word) is the `to:` word for sending
  to yourself.  `name` is the label only.
- `to: <name>` (not also a contact) is marked NOT AN ADDRESS in the outbox
  file, with the word to use or a note to set `self_address`.
- Self-delivered inbox records carry `self = true` and `from =
  <self_address>`; every self path (delete, update, inbox sync) tests the
  mark, not a name.
- On startup, records from the old scheme are converted (inbox marked,
  outbox record rekeyed, outbox `to:` line rewritten); with none of the
  new word configured, the daemon stops with the line to add.
- The installer asks for the word after the label (offering `me`), writes
  it into new configs, pre-fills it on a re-run, and takes
  `--self-address=WORD`.  The config comment, README and scripting
  tutorial describe it.
- Found while testing: a mailbox with no contacts never ran its first sync,
  because per-contact timers (#377) only make a cycle due when some contact
  is due, and an outbox file written while the daemon was down raises no
  file-change event.  A self-only mailbox therefore never delivered to
  itself until something touched the outbox.  The daemon now always syncs
  on its first pass.  This also fixed two cases of
  `test-mailbox-selection.sh` that were already failing before this issue.

Before this issue, `name` doubled as the self-address, and self-delivered
records were recognised by `from` equalling it.  Owner (2026-09-22),
weighing the options: "Okay maybe we do need to keep the name. Let's keep
the label, it sounds like it has a lot of little jobs. ... Instead of a
reserved word, let's make the user define one with the name. I think
that's more clean."

## Intended Behavior

- `name` stays: it is the mailbox's label (jobs 2–4 above).
- A new config field, `self_address`, set next to `name`, is the word you
  put on a `to:` line to send to yourself. The owner chooses it (for
  example `me`). There is no built-in default word.
- `to: <self_address>` delivers into this mailbox's own inbox, exactly as
  `to: <name>` did before. The hook "sender" argument for those messages
  is the `self_address` word.
- `to: <name>` is no longer a self-address. If `name` is not also a
  contact, the outbox file is marked with a recipient problem that says
  the name is only a label and gives the word to use instead (or says to
  set `self_address` if there is none). Nothing is delivered on a guess.
- With no `self_address` set, sending to yourself is switched off; any
  attempt is marked the same way.
- A contact whose name equals `self_address` is refused as ambiguous, as
  a contact named after the mailbox was before.
- `self_address` must be one plain word (letters, digits, `-`, `_`), the
  same shape as a contact name. Anything else stops the daemon at startup
  with a message naming the config file.
- A self-delivered message is recognised by a `self` mark on its inbox
  record, not by comparing names. Changing `name` or `self_address` later
  therefore cannot orphan messages already delivered.
- Startup conversion of existing mailboxes: inbox records whose `from` is
  the mailbox's `name`, where no contact has that name, get the `self`
  mark, and outbox records for self-deliveries keyed by the old name are
  rekeyed to `self_address`. If such records exist and no `self_address`
  is set, the daemon stops at startup and says to set one. This runs once
  per record and is a conversion, not a fallback: afterwards the old name
  plays no part in self-delivery.

## Suggested Implementation Steps

1. Read `self_address` from the config in `init_runtime`; validate its
   shape; keep it in the runtime table beside `my_name`.
2. Outbox sync: match the `to:` entry against `self_address`; refuse
   `to: <name>` (not a contact) with a recipient-problem mark pointing at
   `self_address`; keep the ambiguity refusal, now against `self_address`.
3. Record self-deliveries in `inbox.json` with `self = true` and
   `from = self_address`; find them by that mark in the self-delete,
   self-update and inbox-sync paths.
4. Startup conversion of existing records, as above.
5. Installer: prompt for the self-address word after the name, write it
   into the new config, and pre-fill it on a re-run.
6. Config template comment and `docs/.templates/scripting-tutorial.md`
   (periodic pattern: `to: me` with `self_address = me`); regenerate
   `docs/` with `scripts/generate-docs.sh`.
7. Test: a scratch mailbox run once with `self_address = me`: `to: me`
   is delivered to its own inbox with the self mark; `to: <name>` is
   marked and not delivered; a mailbox without `self_address` marks
   `to: me` as unknown; a mailbox holding old-style records converts
   them on startup.

## Related

- #393 (LAN discovery no longer depends on the name).
- `docs/scripting-tutorial.md` — the periodic-task pattern.
