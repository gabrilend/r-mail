# Simultaneous IP change: both sides lose each other permanently

## The problem

If two contacts both change IPs (or routers) while the other is offline,
neither side knows how to reach the other. Each daemon's contact file has
the other's old, now-invalid IP. All connection attempts fail. The
relationship is permanently severed with no automated recovery path.

This is a fundamental limitation of a purely peer-to-peer system with no
central directory or rendezvous point.

## Scenarios that trigger this

- Both users change ISPs or routers around the same time
- One user moves, the other's ISP rotates their IP before the first
  comes back online
- Extended outage on both sides (weeks/months) during which ISPs recycle
  both addresses
- Power outage affecting both users' networks

## Why there's no easy fix

Every solution requires some form of out-of-band channel or third party:

- **DNS**: Requires a DNS provider (third party). Solves it if both sides
  use DDNS. See issue #311.
- **Relay/rendezvous server**: A minimal server both sides check. Works,
  but adds central infrastructure dependency.
- **Mutual friend brokering**: If Alice and Bob both know Carol, she could
  reconnect them. Complex trust/protocol implications.
- **Manual re-exchange**: Users share new IPs out of band. Always works,
  never automated.

## Philosophical note

This may be an inherent trade-off of the home-server model. Central
services (email, Signal, etc.) solve this trivially because the server's
address never changes. rmail trades that convenience for independence.
The question is whether we can find a middle ground — some minimal,
opt-in mechanism that preserves the spirit of the design while making
recovery possible.

## Status

Open problem. Fundamental architectural limitation. Collecting ideas.
