# #393 — LAN discovery files a found address under the contact it came from

## Status

Completed 2026-09-22.  Tested by `scripts/test-lan-discovery-names.sh`.

## Current Behavior

- A discovery packet (request or answer) is identified by the contact whose
  token decrypts it, and the found address is filed under that contact's
  local name in the LAN-peer table -- the name `do_resolve_lan_host` looks
  up.  Log: "LAN discovery: kuvalu-mail is at 192.168.1.100".
- The packets carry no name: "RMAIL-DISCOVER <port> <lan-ip>" and
  "RMAIL-HERE <lan-ip>".  A mailbox's own name never leaves its machine
  this way.
- Before this fix the packets carried the sender's own name and the
  address was filed under it, so whenever the two sides named each other
  differently the search found the peer and the lookup never saw it.
  Contacts with a `local-ip` line were unaffected.
- The packet format changed incompatibly: a daemon from before this issue
  cannot read the new packets, nor this one the old.  Owner (2026-09-22):
  "I'm gonna update all the machines running rmail posthaste so don't
  worry about backwards compatibility."

## Intended Behavior

- A discovery packet is identified by the token that decrypts it. The
  found address is recorded under that contact's local name.
- The packets carry no name at all, since nothing needs one.

## Suggested Implementation Steps

1. In `handle_udp_discovery`, store into the LAN-peer table under the
   loop's contact name for both the request and the response branch.
2. Drop the name from all three packet builders (the two senders of
   RMAIL-DISCOVER and the RMAIL-HERE reply) and from both parsers; log the
   local contact name only.
3. Test: two daemons on one machine whose contacts files name each other
   differently from their configs. After discovery, each one's LAN-peer
   table has the other under the local contact name. Run it with no
   `local-ip` lines, so discovery is the only way to find the address.

## Related

- #347 (multiple addresses per contact), #365 (LAN detection), #388
  (announce the full address set; introduced `local-ip`), #394 (a
  separate self-address word; tried and reverted — `name` still does both
  jobs).
- #395 (tell the owner when a contact calls itself by a different name;
  whether to drop the name from the discovery packet).
