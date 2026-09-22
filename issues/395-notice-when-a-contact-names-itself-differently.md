# #395 — Notice when a contact calls itself by a different name

## Status

Open, not started — a pin, per the owner (2026-09-22): "for now let's just
put a pin in it and leave it as future concerns."

## Current Behavior

- Every name in a `contacts` file is chosen by the person who owns that
  file.  Incoming mail is shown under that local name: the sender is
  identified by which contact's token decrypts the message, never by a
  name the sender supplies.
- No message or packet between mailboxes carries the sender's own name.
  The LAN discovery packets used to, and #393 removed it (owner,
  2026-09-22: "I'm gonna update all the machines running rmail posthaste
  so don't worry about backwards compatibility").  The one remaining place
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

## Related

- #393 (LAN discovery files a found address under the local contact name).
