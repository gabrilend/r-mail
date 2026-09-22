# #393 — LAN discovery files a found address under the contact it came from

## Status

Completed 2026-09-22.  Tested by `scripts/test-lan-discovery-names.sh`.

## Current Behavior

- A discovery packet (request or answer) is identified by the contact whose
  token decrypts it, and the found address is filed under that contact's
  local name in the LAN-peer table -- the name `do_resolve_lan_host` looks
  up.  The name written inside the packet only appears in the log:
  "LAN discovery: kuvalu-mail (calls itself kuvalu) is at 192.168.1.100".
- Before this fix the address was filed under the name inside the packet
  (the sender's own label), so whenever the two sides named each other
  differently the search found the peer and the lookup never saw it.
  Contacts with a `local-ip` line were unaffected.
- The packet format is unchanged.

## Intended Behavior

- A discovery packet is identified by the token that decrypts it. The
  found address is recorded under that contact's local name.
- The name inside the packet is only used for the log line, which shows
  both ("kuvalu-mail (calls itself kuvalu) is at 192.168.1.100"), so a
  reader can see which contact matched.
- The packet format does not change, so older daemons still interoperate.

## Suggested Implementation Steps

1. In `handle_udp_discovery`, store into the LAN-peer table under the
   loop's contact name for both the request and the response branch.
2. Update both log lines to name the contact and the self-declared name.
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
