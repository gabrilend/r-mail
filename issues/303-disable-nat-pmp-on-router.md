# Disable NAT-PMP on router (optional)

## Description

rmail's security check detected that the router has NAT-PMP enabled. This
allows any device on the network to open ports without authentication —
a known security risk that malware commonly exploits.

## Action

Log into the router admin panel and disable NAT-PMP (and UPnP if enabled).
Use manual port forwarding instead.

After disabling, rmail will automatically send a "resolved" message to
contacts on the next startup.

## Status

Optional — security recommendation.
