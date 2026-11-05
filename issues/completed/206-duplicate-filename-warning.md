# Warn about duplicate filename conflicts

## Status

**Built 2026-11-05** (see "Built" and "Decisions" at the end), on top of
#211.  Option B: the receiver picks another name and the sender is not
told.  Most of it was already built on 2026-10-13 (the owner's "the
filesystem should win", `scripts/test-inbox-never-overwrites.sh`); this
closes what was left.

## Current behavior

If you send a message to a recipient who already has a file with the
same name in their inbox, the behavior is undefined — the message may
fail silently, overwrite, or cause confusion.

## Intended behavior

Handle filename collisions gracefully, either by:
- Warning the sender about the conflict, OR
- Resolving it silently on the recipient side

This is distinct from "living messages" (issue #207), which handle
intentional updates from the original sender. This issue is about
accidental name collisions.

## Unanswered questions

### Server-side warning vs client-side resolution

**Option A: Server tells sender about conflict**
- Sender gets feedback: "Message 'foo' not delivered to bar: filename exists"
- Problem: leaks information about recipient's inbox contents
- An attacker could probe for message names to learn what someone has received
- Could be "cute" — knowing what's in someone's inbox has social value
- But also creepy? "I see you already have a message called 'love-letter'..."

**Option B: Recipient resolves silently**
- Recipient's daemon auto-renames: `foo` → `foo-2` or `foo-from-alice`
- No information leaks back to sender
- Sender doesn't know their chosen filename wasn't used
- Simpler, more private, but less transparent

**Option C: Configurable per-recipient**
- Recipient sets preference: "warn senders" vs "auto-rename"
- Most flexible, most complex
- Default matters: which is the safe default?

### What counts as a collision?

- Same subject/filename only?
- Same subject AND same sender? (different senders could have same subject)
- What about case sensitivity? `Foo` vs `foo`?

### Living message interaction

- Living messages from the SAME sender should update, not collide
- But what if Alice sends "status" and Bob also sends "status"?
- Should living messages be sender-namespaced? `alice/status` vs `bob/status`?
- Or reject the second sender's "status" as a collision?

## Suggested implementation steps

(Depends on answers to above questions)

1. Decide on collision resolution strategy
2. If server-side warning:
   - Check inbox for existing filename on receive
   - If conflict AND not a living update from same sender:
     - Return error response with reason
     - Sender's daemon writes warning to sender's inbox
3. If client-side resolution:
   - On conflict, append sender name or incrementing number
   - Log the rename somewhere (inbox log file?)

## Edge cases

- Living messages should bypass this for same-sender updates
- Recipient deletes and re-receives: UUID tracking handles this
- Multiple recipients: each resolves independently
- What if auto-renamed file ALSO conflicts? Keep incrementing?

## Source

Mail: ~/mail/inbox/rmail-improvements-too — file processed and removed

## Built (2026-11-05)

What was already there (2026-10-13, and #814 before it): a message whose
subject names a file already in the inbox is saved beside it, never over
it.  From another sender it becomes `<subject>-from-<sender>`; from the
same sender, a different message, `<subject>-<six characters of its id>`;
and whatever name is chosen, if a file holds it, `-2`, `-3` and on, with no
limit.  A hand-made file the daemon has no record of is moved aside the
same way.  An edit or delete from the original sender finds its message by
id, never by name, so it never collides.

What this adds, in `handle_deliver_message` and `save_attachments`
(`rmail.lua`):

- **Upper and lower case.**  A name is taken when the folder already holds
  it in any mix of case: the folder is listed once per message, and the
  checks above use that listing as well as `file_exists`.  A hand-made
  `Plans` makes a contact's `plans` land as `plans-2`.
- **The sender is not told.**  The answer to a delivered message was
  `{"ok": true, "filename": "<the name chosen>"}`.  The sender's daemon
  never read the name, but it told whoever sent the message whether the
  subject was already taken here.  The answer is now `{"ok": true}`.
- **The owner is told.**  When the subject's own name was taken, the log
  line says so: `delivered: <id> from bob -> hi-from-bob (hi was taken)`.
- **Attachments carried in a message** (`attachments` in a deliver
  request, which a contact may still send) were saved as
  `<name>-from-<sender>` without checking that name was free, so a
  contact's second attachment of the same name, with another message,
  wrote over its first.  The `-2`, `-3` numbering now applies there too;
  a copy re-sent with the same message still replaces its own earlier copy.

**Test:** `scripts/test-inbox-never-overwrites.sh` gains four sections:
upper and lower case (the hand-made `Plans` unchanged, mallory's `plans`
and bob's `HI` saved, no two inbox files differing only in case), the
sender not told (the answer to a message whose name was taken names no
file, and the daemon's log says the name was taken), and attachments
(three messages each carrying an attachment named `pic` leave three
files).

## Decisions (2026-11-05, the owner can overturn any of these)

1. **Option B: the receiver picks another name, and the sender is not
   told.**  The owner's rule of 2026-10-13, "the filesystem should win",
   already made it so.  Option A would tell a sender what the inbox holds,
   which this issue itself calls creepy, and Option C would add a setting
   whose safe default is B anyway.
2. **The answer to a delivered message no longer names the file** (see
   Built).  It was the one place left where a sender could learn that a
   subject was taken.
3. **A collision is the same name in the same folder, in any case.**
   `Foo` and `foo` collide.  Most of the places an inbox may be copied to
   (a Mac, a USB drive) don't tell them apart, and two files that become
   one there would lose one.  On those filesystems this was already true;
   now it is true everywhere.  Folders (#214) are part of the name: `a/hi`
   and `b/hi` do not collide.
4. **Not namespaced by sender.**  Messages from different senders share the
   inbox, and a clash is resolved with `-from-<sender>`.  Per-sender
   folders would change where every message lands, and #214's folders are
   the sender's choice of path, which stays theirs.
5. **The same sender's updates never collide**, because edits and deletes
   find their message by id (#207, #814).  A second, different message
   with the same subject gets a code from its id.
6. **A renamed name that is also taken keeps counting**, with no limit
   (as built on 2026-10-13).
7. **The owner is told in the log**, not with a notice file in the inbox.
   A file for every rename would clutter the inbox it is about, and the
   new name already carries `-from-<sender>` or a number.  The
   `on_receive` hook gets the path the message was saved under, as before.
8. **Attachments carried in a message are numbered too**, so they are no
   longer written over (see Built).  Matching ignores case only in the
   inbox.  Attachments that arrive in pieces already find a free name
   (`attachment ... name taken, saved as ...`); applying the case rule
   there too is a possible follow-up.
9. **Stacked on #211 (r-mail PR #6), not on main.**  #214, under #211,
   rewrote the same lines of `handle_deliver_message` for folders.

Noticed, not changed: #214 answers a subject it refuses with the reason,
for instance "a folder on the way that is a symbolic link", which tells
the sender a little about the inbox's folders.  That is #214's decision
and is left to it.

