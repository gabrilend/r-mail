# DNS hostnames in contacts file

## Overview

Allow contacts to use DNS hostnames (e.g. `kuvalu.duckdns.org`) instead of
raw IP addresses in the `.ip` field. This makes connections survive IP changes
for contacts who have dynamic DNS set up.

## Current state

LuaSocket's `connect()` already resolves hostnames, so outbound connections
would work today if you put a hostname in the `.ip` field. The problem is
inbound: the daemon identifies senders by matching the connecting IP against
`contact.ip`. A hostname string won't match a raw IP from the socket.

## What needs to change

### Sender identification
When matching an incoming connection's IP to a contact, resolve the contact's
`.ip` field if it's a hostname (not a raw IP). Cache the resolution for a few
minutes to avoid constant DNS lookups.

### LAN optimization
LAN peer cache compares raw IPs. Needs to resolve hostnames before comparing.

### IP change notifications
Contacts with DNS hostnames don't need `POST /update-address` — the daemon
can just re-resolve. The existing mechanism still works for raw-IP contacts.

### Android client
The setup screen and contacts editor should accept hostnames in addition to
IP addresses (currently the IP field uses numeric keypad with octet splitting).

## Status

Design phase. Small change — mostly a `resolve_contact_ip()` caching helper
and using it in the sender identification and LAN paths.
