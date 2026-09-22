# #395 — Notice when a contact calls itself by a different name

## Status

Open, not started — a pin, per the owner (2026-09-22): "for now let's just
put a pin in it and leave it as future concerns."

## Current Behavior

- Every name in a `contacts` file is chosen by the person who owns that
  file.  Incoming mail is shown under that local name: the sender is
  identified by which contact's token decrypts the message, never by a
  name the sender supplies.
- The one place a peer's own name travels is the LAN discovery packet
  ("RMAIL-DISCOVER <name> <port> <lan-ip>" / "RMAIL-HERE <name>
  <lan-ip>").  Since #393 the receiver files the found address under its
  local contact name and only logs the peer's own name:
  "kuvalu-mail (calls itself kuvalu) is at 192.168.1.100".
- Nothing tells the owner when those two names differ.

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

1. Where does the peer's own name come from once discovery stops carrying
   it?  Options: keep it in the discovery packet; add it to the address
   announcement, which is already sent to every contact; or ask for it in
   the existing health check, which already answers with the name.
2. Should the name be dropped from the discovery packet?  Older daemons
   parse three fields out of it, so dropping it breaks discovery with any
   contact that has not upgraded.  Sending a placeholder in that slot keeps
   old daemons working.
3. How is the owner told, and how do they accept the rename (a consent-form
   style inbox note, like attachments use)?

## Related

- #393 (LAN discovery files a found address under the local contact name).
