# #339 — Generate a portable rmail *mailbox* drive

## Goal

A script in the source tree that produces a USB drive which **is** a
running rmail mailbox. Plug it into any Linux host whose router
forwards the configured port, run `./run.sh` from the drive, and the
mailbox is live. Unplug it, carry it to a different machine, plug in,
run `./run.sh` — same mailbox, same contacts, same history.

Installation happens **once**, when the drive is generated. After
that, moving between hosts requires no install step.

## Drive layout

```
/run.sh                # starts the daemon pointed at this drive
/README.md             # "plug in, run ./run.sh" + router-port reminder
/source-code/          # copy of the rmail source + prebuilt libs
/mailbox-0/
    config             # mailbox config (lives inside the mailbox itself)
    contacts
    inbox/
    outbox/
    attachments/
    .state/
    scripts/           # hook scripts, referenced as ./scripts/<name>.sh
        on_receive.sh
        on_delete.sh
        ...
```

Design notes:

- **Config inside the mailbox.** No `~/.config/rmail/` use. The daemon
  accepts the mailbox directory as its CLI arg and reads
  `mailbox-0/config` directly, so the config file is self-contained on
  the drive.
- **No `mail =` line** in the config. The daemon is launched in
  "directory form", which ignores that field; hard-coding a
  mount-point-dependent path would break portability.
- **Relative hook paths.** Hooks are referenced as
  `./scripts/on_receive.sh` etc. `run.sh` `cd`s into the mailbox
  directory before exec'ing the daemon, and the daemon does not
  `chdir` during its run, so `/bin/sh -c` (which `io.popen` and
  `os.execute` go through) resolves the relative paths reliably on any
  host.

## The generator script

- Lives in the source tree (e.g. `scripts/make-mailbox-drive.sh`).
- Shares the flash-drive detection logic with #361 (same
  `FLASH_LABEL` variable at the top; extract to a helper later if
  the duplication hurts).
- Runs the normal installer against the drive as its `--mail`
  target, in silent mode — e.g.:

  ```sh
  scripts/install.sh --silent \
      --name "$USER_NAME" --port "$PORT" \
      --mail "$DRIVE/mailbox-0" \
      --config "$DRIVE/config"
  ```

  (If `install.sh` doesn't currently accept `--config <path>`, add
  that as part of this issue — it's the key piece that makes the
  drive self-contained.)

- Copies / builds the libs the daemon needs into `$DRIVE/bin/`.
- Writes `run.sh` and `README.md` from templates.

## `run.sh` on the drive

Has to work from whatever mount point the host gives it:

```sh
#!/bin/sh
DRIVE="$(cd "$(dirname "$0")" && pwd)"
exec "$DRIVE/source-code/run-rmail.sh" \
    --config "$DRIVE/config" \
    --mail   "$DRIVE/mailbox-0"
```

No hard-coded paths. `run-rmail.sh` should already honour whatever
CLI it's handed; double-check while doing this issue.

## Host requirements

Documented in the drive's `README.md`:

1. Linux host.
2. Router forwards the configured port to that host.
   (`scripts/validate-router-settings.sh` from the source tree can
   be run off the drive to verify.)
3. A working C toolchain *if* the prebuilt `bin/` artifacts don't
   match the host's glibc/arch — `run.sh` should detect that case
   and fall back to rebuilding from `source-code/` once, caching
   the result back onto the drive.

## Open questions for implementation

- How much do we trust prebuilt binaries across Linux hosts? Safest
  path is "rebuild on first run, cache back to `bin/`", accepting
  a slow first launch on each new host. Revisit if that's too
  painful in practice.
- Should the drive hold a single mailbox or support multiple
  (`mailbox-0/`, `mailbox-1/`, …) like the daemon already does on
  disk? Start with one; multi-mailbox is a later enhancement.

## Relationship to #361

#361 produces an **installer** drive — the user runs `install.sh`
off it and installs rmail onto their own machine. #339 produces a
**mailbox** drive — the drive itself is the running mailbox and
travels between hosts. Same detection logic; otherwise independent.

## Source

Originally "make installer runnable from a USB drive on all OSes"
(from `issues/new-issue-please-sort`). Rescoped 2026-04-17 per user
request to the portable-mailbox workflow; the installer-drive story
moved to #361.

## Status

Open.
