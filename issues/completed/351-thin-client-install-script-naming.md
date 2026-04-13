# #351 — Thin-client install scripts: per-platform naming convention

## Request

Name the thin-client install scripts `install-thin-client-<platform>.sh`,
one per supported platform.

## Rationale

A predictable, platform-suffixed name makes it obvious which script a
user should run from `clients/<platform>/`. It also keeps the existing
`scripts/install.sh` (daemon installer) visually distinct from the
thin-client installer so the two don't get confused on shared machines.

## Scope

- `clients/linux/install-thin-client-linux.sh`
- `clients/macos/install-thin-client-macos.sh`
- `clients/windows/install-thin-client-windows.sh` (or `.ps1` if PowerShell)

Whatever the `clients/<platform>/` directory contains today should be
renamed to match. Update `docs/thin-client.md` and any README references.

## Related

- #329 — thin-client sync daemon for laptops.

## Source

From `issues/1234`.
