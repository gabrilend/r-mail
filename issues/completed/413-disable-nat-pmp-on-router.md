# Disable NAT-PMP on router (optional)

## Description

rmail's security check detected that the router has NAT-PMP enabled. This
allows any device on the network to open ports without authentication —
a known security risk that malware commonly exploits.

## Action

Log into the router admin panel and disable NAT-PMP (and UPnP if enabled).
Use manual port forwarding instead.

Before 2026-10-08 rmail then sent a "resolved" message to contacts on
its next start.  Since #411 it checks the router only at install and
tells no contact either way.

## Status

Optional — security recommendation.
