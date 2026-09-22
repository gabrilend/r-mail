# #394 — Sending to yourself uses a word set in the config, not the mailbox name

## Status

Built 2026-09-22 (commit 7efbdba), then **reverted the same day** at the
owner's request.  Kept as the record of a design that was tried and set
aside; the Intended Behavior and steps below describe that design, not
the running code.

Owner (2026-09-22), on the built version: "Ehhhhh let's change it back to
how it was before. More config file options for the same result I think,
which is annoying to the user. So just one field that does both
self-routing and mailbox labelling."  On the self mark and the startup
conversion: "yeah let's strip that behavior out, I don't think we need it."

## Current Behavior

- `name` is both the mailbox's label and the `to:` word for sending to
  yourself, as before this issue.  There is no `self_address` setting.
- Self-delivered messages are recognised by their inbox record's `from`
  equalling `name`, as before.
- Two changes made alongside this issue were kept, because they are not
  part of the self-address design:
  - The first-pass sync: a mailbox with no contacts never ran a sync at
    startup, because per-contact timers (#377) only make a cycle due when
    some contact is due, and an outbox file written while the daemon was
    down raises no file-change event.  The daemon now always syncs on its
    first pass.
  - LAN discovery files a found address under the local contact name
    (#393).

Why it was set aside: one field doing both jobs is fewer settings for the
same result.  The risk the split addressed -- a contact that shares the
mailbox's name -- is already refused on the `to:` line as ambiguous.

The owner's reasoning that led to the attempt: "Okay maybe we do need to
keep the name. Let's keep the label, it sounds like it has a lot of little
jobs. ... Instead of a reserved word, let's make the user define one with
the name. I think that's more clean."

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
