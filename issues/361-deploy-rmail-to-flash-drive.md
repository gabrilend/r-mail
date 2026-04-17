# #361 — Generate a portable rmail *installer* drive

## Goal

A script in the source tree that produces a USB drive someone can hand
to another person: they plug it in, read `README.md`, run `install.sh`,
and end up with rmail installed on their own machine (the host — not
the drive).

The drive is a distribution medium for the installer, nothing more.
The resulting rmail install lives wherever the user points `--mail`
at during install, same as a normal clone-and-install.

## Drive layout

Top level of the drive:

```
/README.md            # short "plug in, run ./install.sh" instructions
/install.sh           # wrapper that calls source-code/scripts/install.sh
/source-code/         # full rmail source tree
    rmail.lua
    run-rmail.sh
    scripts/
    clients/
    config/
    docs/
    helpers/
    issues/
    libs/             (optional, prebuilt)
    ...
```

- `install.sh` at the top level is a thin wrapper so the user doesn't
  have to know the internal layout. It `exec`s
  `source-code/scripts/install.sh "$@"`.
- `source-code/` holds everything else so the drive root stays tidy
  and the two "front-door" files are obvious.

## The generator script

- Lives in the source tree (e.g. `scripts/make-installer-drive.sh`).
- Detects mounted flash drives by label. All drives use the same
  label, so the expected label sits in a variable at the top of the
  script:

  ```sh
  FLASH_LABEL="RMAIL"   # adjust once
  ```

- Zero matches → clear error. Multiple matches → list and require
  `--dest <path>`.
- Copies the source tree into `source-code/` on the drive using rsync
  with `--delete`, so re-running keeps the drive in sync.
- Excludes: `.git/`, editor junk, any local mailbox the developer
  happens to have, and by default `deps/` (build artifacts). `libs/`
  is a judgement call — include if we ship prebuilt, skip otherwise.
  Start conservative: skip both; the host will build during
  `install.sh`.
- Writes the top-level `install.sh` wrapper and `README.md` fresh
  each run from templates kept in the source tree.

### Flags

- `--dry-run` — print what would be copied without writing.
- `--dest <path>` — override auto-detection.
- `--include-libs` — copy prebuilt `libs/` / `deps/` if the developer
  wants to ship a faster-install drive (host still needs matching
  glibc/arch; document the risk in the README).

### After copy

- `sync`, print the mount point and total bytes.
- Suggest the exact `udisksctl` / `umount` command, but don't
  auto-unmount without an explicit flag.

## Non-goals

- Making the drive itself *run* rmail. That's #339 — a completely
  different artifact (drive = mailbox, not distribution medium).
- Cross-platform target hosts. The resulting `install.sh` already
  targets Linux/macOS; Windows is out of scope here.

## Source

User request 2026-04-17.

## Status

Open.
