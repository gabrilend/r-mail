# 205 - Redirect service logs to /tmp (RAM)

## Current Behavior

- The runit service at `/etc/sv/rmail/run` outputs directly to stdout/stderr
- This causes startup messages to appear on the pre-login TTY, blocking the username prompt
- Other init system services (systemd, openrc) also have various log configurations
- No easy way to view logs during debugging

## Intended Behavior

- All service configurations should redirect logs to `/tmp/rmail.log`
- `/tmp` is RAM-backed (tmpfs), so logs don't persist across reboots and don't cause disk wear
- A hidden symlink `.logs` in the project directory should point to the log file for convenience
- A `view-logs.sh` script should provide cross-platform log tailing

## Suggested Implementation Steps

1. Update `/etc/sv/rmail/run` to redirect output to `/tmp/rmail.log`
2. Update `scripts/install.sh` to generate run scripts that log to `/tmp/rmail.log` for all init systems:
   - runit: redirect to /tmp/rmail.log
   - systemd: use StandardOutput/StandardError to file
   - openrc: already uses output_log/error_log, change to /tmp
   - nixos: configure systemd logging
3. Create hidden symlink `.logs -> /tmp/rmail.log` in project root
4. Create `scripts/view-logs.sh` that detects the system and tails the appropriate log file

## Related Files

- `/etc/sv/rmail/run` - current runit service
- `scripts/install.sh` - service file generator
- `docs/service.md` - service documentation

## Completion Notes

All service types (runit, systemd, openrc, nixos) now log to `/tmp/rmail.log`.
Created `scripts/view-logs.sh` for cross-platform log viewing.
Created hidden symlink `.logs` in project root pointing to log file.
Updated `docs/service.md` with new logging documentation.

## Follow-up — journalctl fallback for custom systemd units (2026-04-17)

`view-logs.sh` assumed `/tmp/rmail.log` would always exist.  On installs
where the rmail systemd unit is **not** the one `install.sh` generates —
for example a NixOS `configuration.nix` that defines its own
`systemd.services.rmail` without the `StandardOutput = "append:/tmp/…"`
lines — the daemon logs to journald and the file never appears.  The
original script hung forever in its "waiting for log file" loop.

Fix: `view-logs.sh` now branches on three cases:

1. Log file exists → `tail -F` it (unchanged fast path).
2. No file, but systemd is running and `rmail.service` is active →
   `exec journalctl -u rmail.service -f`.
3. Neither → keep the original wait-for-file loop so a slow-starting
   runit / openrc install still works end-to-end.

No install.sh changes; its generated service files already use the
`/tmp/rmail.log` redirect on every supported init system.  The new
fallback is purely for users who bring their own service unit.
