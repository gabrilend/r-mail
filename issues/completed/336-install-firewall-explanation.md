# #336 — Install script: explain firewalls and port-opening better

## Problem

Users who are not comfortable opening a port on their firewall have no
explanation of what the installer is asking them to do or how to verify
it. That's an uncomfortable ask for someone installing unfamiliar
software.

Separately, the line `(recommended for reproducibility)` shown during
install is not meaningful in context and should be removed.

## Fix

- Add a short firewall primer: what a port is, why the daemon needs one
  open, and the shell commands to inspect open ports on common
  platforms (e.g. `ss -tlnp`, `sudo iptables -L`, `nft list ruleset`,
  `ufw status`, `firewall-cmd --list-all`).
- Remove the `(recommended for reproducibility)` line from installer
  output.

## Source

From `issues/new-issue-please-sort`.
