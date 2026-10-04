# Table of contents

Every document in the project, and the nine phases its issues are sorted
into.  The guides in `docs/` are generated from `docs/.templates/` by the
installer or `scripts/generate-docs.sh` (they quote this machine's real
paths), so the links below point at the templates, which are the source.

## The documents

- [README](../README.md) — what rmail is, installing it, using it
- **Guides** (`docs/.templates/`)
  - [Running rmail as a service](.templates/service.md)
  - [Ports explained](.templates/ports-explained.md)
  - [NAT traversal notes](.templates/nat-traversal-report.md)
  - [Protocol](.templates/protocol.md)
  - [Encryption and security](.templates/encryption.md)
  - [Attachments](.templates/attachments.md)
  - [Scripting tutorial](.templates/scripting-tutorial.md)
  - [Defensive patterns and traffic-analysis resistance](.templates/defensive-patterns.md)
  - [Helper scripts](.templates/helper-scripts.md)
  - [Thin client setup](.templates/thin-client.md)
  - [Android app setup](.templates/android-instructions.md)
  - [Connection suggestions](.templates/connection-suggestions.md) — a sample introduction to send someone
  - [Looking for the docs?](looking-for-docs.md) — a pointer for whoever opens `docs/` first
- **Testing**
  - [QA tester guide](../qa-tester-guide.md)
  - [QA test checklist](../q-a-tests.md)
- **Design**
  - [Shared text editor design](../clients/editor-design.md) (the thin clients)
- **Notes** (`notes/`)
  - [Audit of the documents against the code, 2026-10-02](../notes/audit-docs-against-code-2026-10-02.md)
  - [Handoff 2026-09-22: names, timers, and the two mailboxes](../notes/handoff-2026-09-22-names-timers-and-mailbox-hooks.md)
  - [Improvement ideas](../notes/r-mail-improvements.md)
  - [Progress before the phase re-sort](../notes/progress-before-the-re-sort.md)
  - [The phase renumbering map, October 2026](../notes/phase-renumbering-2026-10.map)
- **Ideas not yet filed** — [`todo`](../todo)
- **Issues** — `issues/` (open), `issues/completed/` (done); one progress
  file per phase, below

## The phases

Phases group the issues by what they are about, foundations first: each
phase stands on the ones before it, and inside a phase the issues others
build on come first.  They are not a timeline — work in phase 1 can be
the last thing finished.  Issue `NNN` is phase `N`.  Each progress file is
generated from the issue files (`scripts/generate-phase-progress.lua`);
counts come from `progress-dashboard.lua` (named in each file).

| phase | about | progress | demo |
|---|---|---|---|
| 1 | **The daemon's core** — one daemon serving one mailbox, the main loop, sealed frames, the sync cycle and its timers, the log | [phase 1](../issues/phase-1-progress.md) | `run-demo.sh 1` |
| 2 | **Messages as files** — the outbox format, sending, edits, deletes both ways, dates, hooks | [phase 2](../issues/phase-2-progress.md) | `run-demo.sh 2` |
| 3 | **Attachments and consent** — nothing moves before a yes; checked pieces; every recipient's answer | [phase 3](../issues/phase-3-progress.md) | `run-demo.sh 3` |
| 4 | **Addresses and networking** — our own address, announcing it, NAT, IPv6, the local network | [phase 4](../issues/phase-4-progress.md) | `run-demo.sh 4` |
| 5 | **Contacts, identity and saved state** — the contacts file, the mailbox's name, what is kept about people | [phase 5](../issues/phase-5-progress.md) | `run-demo.sh 5` |
| 6 | **Installation, services, drives, documents** — installing, services, portable drives, other systems | [phase 6](../issues/phase-6-progress.md) | `run-demo.sh 6` |
| 7 | **Helpers, own devices, desktop tools** — shell helpers, the door for the owner's devices, the thin client | [phase 7](../issues/phase-7-progress.md) | `run-demo.sh 7` |
| 8 | **The Android client** — the phone's copy of each mailbox, its sync, its screens | [phase 8](../issues/phase-8-progress.md) | `run-demo.sh 8` |
| 9 | **Privacy against watchers; new transports** — padding, decoys, mesh networks, routers | [phase 9](../issues/phase-9-progress.md) | `run-demo.sh 9` |

`run-demo.sh` at the project's root asks for a phase and runs that
phase's demo from `issues/completed/demos/`.
