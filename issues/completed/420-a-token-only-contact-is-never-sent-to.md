# #420 — A token-only contact is listened to, never sent to

## Status

Completed 2026-10-09.  Test: `scripts/test-listen-only-contact.sh`.
The owner gave the work to this session ("congrats that's your task now,
there's another project (the W client) waiting on this"); the choices it
made are under "Decided".

Filed 2026-10-04 from the ritzmenardi.com shrine, whose mailbox has
a public "door": a contact with only a token, printed on the website, that
any stranger may use once to introduce themselves (a message named JOIN
carrying their own name, address, port and private token, which the
shrine's robot writes into the contacts file as a real contact).
Seen in the robot's live test: `/mnt/mtwo/backups/ritzmenardi.com/tools/test-rmail-robot-live.sh`.

Extended 2026-10-08 with the inbound half (what such a contact may *send*),
from the W client project's documentation site
(`/mnt/mtwo/games/azeroth-core/custom-client`, its `docs/055`): every page
there seals readers' notes with one contact's token, printed in the page
(the web wrapping of #106/6d2ede2 carries them). The owner:

> "we have exactly one contact, which is the website client. It should
> refuse deletes, address changes, attachments, and anything other than a
> plain message from that contact."

The restriction belongs to the contact, not to the web wrapping: the
printed token also works in a bare frame sent straight to the port by any
program, so refusing a request only when it arrives through a browser
would protect nothing.

## Current Behavior

**Built 2026-10-09.**  A contact with `listen = true` in the contacts file
is listen-only (`contactfile.listens`, which compares the text "true").

- **The gate** — in `handle_request`, after decryption and before any
  handler, one check keyed by the sender's contact entry:
  `contactfile.listen_refusal(method, path, body)` returns false for a
  plain message, else the reason.  A plain message is `POST /deliver`
  whose JSON is an object with `type = "message"`, only the fields in
  `contactfile.LISTEN_FIELDS` (`type`, `subject`, `body`, `message_id`,
  `mtime`), a text body of at most 64 KiB, text `subject` and
  `message_id`, a number `mtime`.  Anything else is answered 403 with the
  reason, logged as "refused a request from listen-only contact <name>:
  <reason>", and no handler runs.  Both doors pass through it: a caller
  held during a sync cycle (`ctimer.answer_while_sending`) is handed to
  `handle_request` afterwards.  Bare frames and web-wrapped ones alike.
- **No timer** — its arrivals do not call `ctimer.saw_inbound`.
- **Never sent to**:
  - announcements of our address skip it in all four places that queue
    them (the public-IP change, the IPv6 change, the start-up
    announcement, and the confirmation of an address notice), and
    `sync_address_notifications` drops one queued before the mark;
  - `sync_inbox`: a deleted message from it is forgotten, with no
    deletion notice owed (as for a sender no longer in contacts);
  - `sync_outbox`: a new `to:` naming it is marked `// LISTEN-ONLY
    CONTACT` in the file and logged, like an unknown contact;
  - `http_post_batch_with_fallback`, the last step before the network,
    refuses any request whose contact is listen-only and logs it as an
    error (every builder already leaves them out; this catches one that
    does not, e.g. a recipient addressed before the mark was added).
- **Docs** — README (contacts file: listen-only contacts), the protocol
  guide ("Listen-only contacts"), the rmail-integration skill.

`scripts/test-listen-only-contact.sh`, against one daemon with a
listen-only contact `door` beside an ordinary `mallory`: plain messages
are accepted bare and web-wrapped, with and without `mtime`, at exactly
64 KiB; ten other requests (delete, edit, attachments, `auto_body`, an
unknown field, 64 KiB + 1, an attachment request, an address change,
`GET /deps`, the sealed `GET /`) and a web-wrapped delete are each 403
and logged, leaving the inbox, `.state/`, `attachments/` and the contacts
file byte for byte as they were; mallory may still delete her own
message; deleting door's message owes no notice; an outbox file to door
is marked and nothing is sent.  On the code before this change, 16 of
its cases fail.

**Before 2026-10-09** — a contact entry with only a token (`door.token =
"..."`, no `ip`) could send to us: trial decryption found its key and the
message was delivered.  But the daemon then treated it like any contact:

- the sender's daemon announces its addresses to us on start-up (#402),
  and `handle_update_address` stores them under `door` in
  `.state/pending-address.json` and the contact's addresses
  (log: `address set from door: 97.120.253.166`);
- from then on we owe `door` our own announcements and try to reach it:
  `timeout connecting to 97.120.253.166:41970`, `backing off door:
  retrying every 390s`, `unreachable contacts this cycle: door`;
- deleting a message that came through `door` owes it a deletion notice.

With one person per contact this is all correct.  A door is shared by
everyone who knocks, so "door's address" is just whoever announced last:
the shrine keeps reaching out to the latest visitor's address, sends its
own address announcements there, and fills its log with an unreachable
contact.  Nothing private leaks (every packet is sealed with the door
token, which that visitor holds anyway), but it is traffic and noise
aimed at strangers, and the next visitor's announcement silently
replaces the last.

**What a shared-token contact could send before** (2026-10-08): everything any
contact may. Anyone holding the token can

- `POST /delete` any message that contact sent, by its `message_id`
  (`handle_delete`): one visitor can delete another visitor's message if
  they learn its id;
- `POST /update-address` (above);
- deliver a `message` carrying an `attachments` field, which
  `handle_deliver_message` saves (`save_attachments`), or one marked
  `auto_body`;
- deliver every other type in the `/deliver` table: `update` (rewriting an
  earlier message's body, theirs or another visitor's, by id; matched by
  id and contact name in `handle_deliver_update`, and every visitor is the
  same contact. An update runs `on_update`, not `on_receive_raw`, so a
  checker on the raw hook alone never sees it),
  `attachment_request` (a consent form in our inbox), `attachment_response`,
  `attachment_chunk`, `attachment_cancel`, `chunk_failed`;
- use the `GET /deps` family, open to any contact.

## Intended Behavior

A contact can be marked as listen-only:

    door.token  = "the-public-door-words"
    door.listen = true

A listen-only contact:
- is accepted as a sender (trial decryption, delivery, hooks) as now;
- never has an address learned or stored for it: `/update-address` is
  refused by the gate (403, nothing changed) and `pending-address.json`
  skips it (LAN discovery, named here first, was removed by #418 before
  this was built);
- is never sent to: no announcements of our address, no sync, no
  deletion notices (a deleted inbox message from it is just deleted),
  and it never appears among unreachable contacts;
- may not be named in an outbox `to:` line; doing so is flagged like an
  unknown contact, with a note saying why;
- **may send plain messages and nothing else** (2026-10-08): a `/deliver`
  of `type = "message"` with no `attachments` field and no `auto_body` is
  handled as now (hooks included); every other request from it is
  refused with 403 and a log line naming the contact and what was
  refused, and changes nothing: `/delete`, `/update-address`, every other
  `/deliver` type, a message carrying `attachments` or `auto_body`, the
  `/deps` family, and the own-device `/api/*` family (already refused
  unless `own = true`; a listen-only contact can never be `own`).

Decided 2026-10-08/09 (the owner made this session's task; the answers
below are the choices it made, each with its reason, for the owner to
overrule):

- **The word is `listen`.**  The W client's mailbox already writes
  `website.listen = true` (its `docs/055`), ahead of rmail reading it.
- **Only by the mark.**  A contact with a token and no `ip` is not
  listen-only by default: a normal contact whose address will arrive by
  announcement is added that way today, and would never be learned.
- **What a plain message is**: a `POST /deliver` whose JSON has only the
  fields `type` (= `"message"`), `subject`, `body`, `message_id` and
  `mtime` (a number) — the W client's pages send exactly these; the
  skill's sealer sends the first four.  Any other field (`attachments`,
  `auto_body`, anything new) is refused, not ignored: an allow-list, so
  a field added to rmail later is closed to strangers until someone
  decides otherwise.
- **The body is at most 64 KiB** for a listen-only contact.  Hooks get
  the body as one program argument, which Linux caps at 128 KiB
  (`MAX_ARG_STRLEN`); a longer body never starts the checking hook, and
  an empty hook output keeps the body unchecked.  64 KiB leaves room for
  the subject and the rest of the arguments.  How hooks get bodies for
  every contact (standard input or a file) is its own matter, #215.
- A listen-only contact's arrivals do not move its timer (there is
  nothing to send it, so no timer is wanted).

## Suggested Implementation Steps

1. `contactfile.listens(c)`: the contacts file already keeps every field
   as text, so `listen = true` reads as `c.listen == "true"`.
2. An address change from a listen-only sender never reaches
   `handle_update_address`: the gate (step 6) answers it 403.  (First
   planned as "answer and change nothing"; the gate made one rule for
   every request instead.)
3. Skip listen-only contacts wherever announcements are queued
   (`pending-address.json`: the public-IP and IPv6 changes, the start-up
   announcement, the address-notice confirmation, and
   `sync_address_notifications`), when owing deletion notices
   (`sync_inbox`), and in `ctimer.saw_inbound`; refuse them at the send
   gate (`http_post_batch_with_fallback`) as the last word.
4. Outbox parsing: a `to:` naming a listen-only contact gets a
   `// LISTEN-ONLY CONTACT` note, as `// UNKNOWN CONTACT` does now.
5. Test that nothing is sent back — built with one mailbox and the
   stand-in contact rather than two mailboxes: the stand-in announces an
   address (refused, contacts file unchanged), its message is deleted
   from the inbox (forgotten, no notice), and an outbox file names it
   (marked); the log has no line of the daemon reaching out to it.
6. The inbound gate: one check where a decrypted request is dispatched
   (both doors: the main request loop and the answer-while-sending door),
   keyed by the sender's contact entry, before any handler runs. A table
   of what a listen-only contact may do (one entry: `/deliver` with
   `type = "message"`), everything else answered 403.
7. Test the gate with the stand-in contact (`scripts/lib/fake-contact.lua`)
   as a listen-only contact, bare and web-wrapped: a plain message lands;
   a delete of it, an `update` of it, a message with `attachments`, an
   `attachment_request`, an `/update-address` and a `GET /deps` are each
   refused with 403, logged, and leave the inbox, `.state/` and the
   contacts file byte for byte as they were.

## Questions answered

The three questions this issue held — listen-only by default for a
token-only contact, the word for the mark, and the body limit — are
answered under "Decided" in Intended Behavior.  The general way hooks get
bodies went to #215.

## Related

- #402 — announcing our address, and learning theirs.
- #409 — the whole address set in one announcement.
- #506 — a contact that names itself differently (also about a contact
  entry not being one person).
- #714 — the public capability URL; with it, a door is only needed for
  people who want to subscribe, not to download.
