# #506 — Notice when a contact calls itself by a different name

## Status

Built 2026-11-05: announcements carry the sender's own name, and a
difference is said once in the inbox.  Accepting a rename from the
notice itself is not built (decision 3 below).

Until then it was a pin, per the owner (2026-09-22): "for now let's just
put a pin in it and leave it as future concerns."  It was picked up on
2026-11-05 because it was assigned for that day's round; the pin was
about when, and nothing the owner said about what is changed by it.

## Current Behavior

- Every name in a `contacts` file is chosen by the person who owns that
  file.  Incoming mail is shown under that local name: the sender is
  identified by which contact's token decrypts the message, never by a
  name the sender supplies.
- No message or packet between mailboxes carries the sender's own name.
  The LAN discovery packets used to, and #417 removed it (owner,
  2026-09-22: "I'm gonna update all the machines running rmail posthaste
  so don't worry about backwards compatibility"); LAN discovery itself is
  gone since 2026-10-04 (#418).  The one remaining place
  a mailbox states its own name is the plaintext health check, which
  answers anyone who connects.
- So nothing can currently tell the owner that a contact names itself
  differently.

## Intended Behavior

Owner (2026-09-22): "We should use preferred names when possible, but we
should note when there's a discrepancy because that's just polite. So if a
message comes in addressed from suzie, but we have kyle as her contact
name, we should fix that and replace her deadname so we know who we're
actually talking to. But at the same time, we shouldn't shift user's
contacts file without their permission, aside from changing IP addresses
and stuff ... Intended behavior at this point is that a messaged addressed
from someone shows up with the name we have listed for them, not what was
sent in the message."

- Mail keeps showing under the local contact name (already true).
- When a peer's own name differs from the local name, the owner is told
  once, in a way they will see (for example a note in the inbox), and
  offered the rename.  The contacts file is not changed without the
  owner's say-so.

## Suggested Implementation Steps

To be designed.  Questions to settle first:

1. Where would the peer's own name come from?  Options: add it to the
   address announcement, which is already sent to every contact and is
   encrypted with the shared token; or read it from the health check, which
   is plaintext and unauthenticated, so anyone could answer it.
2. How is the owner told, and how do they accept the rename (a consent-form
   style inbox note, like attachments use)?

## Decisions (2026-11-05)

Made by the builder; the owner can overturn each.

1. **Where the name comes from: the address announcement**, as a `name`
   field beside `ip`/`ips`.  It is sealed with that contact's key, so
   only they can have said it, and it already goes to every contact at
   start-up and on every address change.  The health check was
   rejected: it is plaintext and anyone can answer it.  A peer older
   than this sends no name and nothing happens.  An `on_send` hook can
   rewrite or drop it like the rest of the payload.
2. **How the owner is told: `inbox/THEIR-NAME-<local name>`**, written
   once per name they announce.  `.state/their-names.json` remembers what
   was said, so a later announcement, and the one after a restart, says
   nothing new, and a deleted notice stays deleted; a *different* name is
   said again.  The notice is removed when the names agree again,
   whether the owner renamed them or they went back.  If the name is one
   the owner already uses for somebody else, the notice says so.  A name
   that could not be a contact's name (letters, digits, `-`, `_`, up to
   64) is ignored.
3. **The rename is offered as steps, not as a button.**  The owner's
   words win here: "we shouldn't shift user's contacts file without
   their permission", and since #505's reversal renaming is the owner's
   to do by hand (the README's "Renaming a contact", which the notice
   fills in with both names).  A consent-form style accept would have
   to rewrite contacts, outbox `to:` lines, contact folders and every
   state file while the daemon runs; that is a larger change than this
   issue needs and is left for if the owner asks for it.
4. **Mail is never relabelled.**  As the owner said: "a messaged
   addressed from someone shows up with the name we have listed for
   them, not what was sent in the message."

Tested by `scripts/test-their-name.sh` (14 cases) and one added case in
`scripts/test-address-announcements.sh` (the announcement names its
sender); each check was shown to catch a mutant of the code it covers.

## Related

- #417 (LAN discovery files a found address under the local contact name).
