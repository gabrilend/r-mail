# README Restructure Plan

## Goal

README.md has grown large. Split it into focused documents under a `docs/`
directory. README.md keeps the quickstart and overview; deep-dive topics move
to their own files. The plan documents (`contacts-format-plan.md`,
`attachment-consent-plan.md`) are consumed in the process — their content
either made it into the code already or belongs in the user-facing docs. Once
consumed, delete them.

---

## Target document layout

```
README.md                        # overview, quickstart, links to docs/
docs/
  configuration.md               # full config file reference
  contacts.md                    # contacts file format, arbitrary fields
  attachments.md                 # attachment workflow, consent, chunking
  hooks.md                       # replaces scripting-tutorial.md
  ports-and-networking.md        # port forwarding, UPnP, firewall, dynamic IP
  protocol.md                    # wire protocol reference (for developers)
  nat-traversal-report.md        # move existing nat-traversal-report.md here
```

`scripting-tutorial.md` is renamed and moved to `docs/hooks.md` — its content
is already complete and just needs to live in the right place.

---

## README.md after restructure

Keep in README.md:
- Project description (one paragraph)
- Directory layout (`~/mail/` tree)
- How to send a message (short example)
- How attachments work (short summary, link to docs/attachments.md for details)
- How deleting works
- Dependencies list
- Installation (`scripts/install.sh`, manual run)
- Running as a service (systemd/runit/OpenRC/NixOS — these are long but
  frequently needed; keep here or move to a service.md, decide during rewrite)
- Link section at the bottom pointing to all docs/

Remove from README.md (move to docs/):
- Full config key reference → docs/configuration.md
- Contacts file format details → docs/contacts.md
- Full attachment workflow → docs/attachments.md
- Hooks table and descriptions → docs/hooks.md (+ link: "For full docs and
  examples in bash, Lua, and C, see docs/hooks.md — hooks are a powerful
  feature worth exploring.")
- Port forwarding, firewall, UPnP/NAT-PMP, dynamic IP → docs/ports-and-networking.md
- Protocol section → docs/protocol.md
- Troubleshooting → keep a short section in README.md with the most common
  issues; move the full list to docs/troubleshooting.md or inline in each doc

---

## docs/configuration.md

All config keys in one place:

| Key                     | Default                    | Description                        |
|-------------------------|----------------------------|------------------------------------|
| `name`                  | (required)                 | your identity, must match contacts |
| `port`                  | (required)                 | port the daemon listens on         |
| `mail`                  | `~/mail`                   | root mail directory                |
| `attachments`           | `~/mail/attachments`       | where received files are saved     |
| `attachment_pending_dir`| `/tmp`                     | in-progress chunk storage          |
| `attachment_chunk_size` | `5242880` (5 MB)           | bytes per chunk                    |
| `auto_port_forward`     | `false`                    | enable UPnP/NAT-PMP                |
| `notify_ip_change`      | `true`                     | notify contacts on IP change       |
| `on_receive_raw`        | —                          | hook: path to executable           |
| `on_receive`            | —                          | hook: path to executable           |
| `on_send`               | —                          | hook: path to executable           |
| `on_delete`             | —                          | hook: path to executable           |
| `on_package`            | —                          | hook: path to executable           |

---

## docs/contacts.md

Content from README.md contacts section plus notes from contacts-format-plan.md:
- File format (`name.field = value`, comments, bare-name lines)
- The three standard fields (`ip`, `port`, `token`)
- Arbitrary fields — stored, ignored by rmail, readable by hooks via grep
- Example showing a multi-contact file with comments and alignment
- JSON migration note (auto-detected on first startup)

**Consume and delete**: `contacts-format-plan.md`

---

## docs/attachments.md

Full attachment workflow documentation. Content from README.md attachments
section (expanded) plus relevant design rationale from attachment-consent-plan.md:
- The `attach:` line syntax and per-recipient scoping (already in README)
- The consent flow in detail: what the consent file looks like, how to respond,
  what happens on accept vs. decline
- Transfer mechanics: compression, chunking, checksum verification, resumption
- Cancellation: delete the outbox file
- In-progress visibility: the STATUS file in `attachments/.pending/`
- Config keys that affect attachments (link to docs/configuration.md)
- Note that `expected_size` is reported by the sender and unverified

**Consume and delete**: `attachment-consent-plan.md`

---

## docs/hooks.md

Move and lightly edit `scripting-tutorial.md`:
- Hook interface table (already complete)
- Per-hook descriptions (already complete)
- Bash, Lua, and C examples (already complete)
- Tips section (already complete)

README.md hooks section becomes a short paragraph:
> Hooks let you run scripts in response to message events — new messages,
> sends, deletions, received attachments. See [docs/hooks.md](docs/hooks.md)
> for the full interface reference and examples in bash, Lua, and C.

**Consume and rename**: `scripting-tutorial.md` → `docs/hooks.md`

---

## docs/ports-and-networking.md

Move from README.md:
- Port forwarding explanation and table
- How to find local/public IP
- Opening the firewall (ufw/iptables/nftables)
- UPnP/NAT-PMP warning and how-to
- Dynamic IP detection and notification

---

## docs/protocol.md

Move from README.md:
- `/deliver` and `/delete` endpoint descriptions
- Payload fields
- curl test example
- Sync timing (adaptive timer)

---

## Link section in README.md

Add a `## Docs` or `## More` section near the bottom of README.md:

```markdown
## Docs

- [docs/configuration.md](docs/configuration.md) — all config keys
- [docs/contacts.md](docs/contacts.md) — contacts file format
- [docs/attachments.md](docs/attachments.md) — attachment workflow
- [docs/hooks.md](docs/hooks.md) — scripting hooks (bash, Lua, C examples)
- [docs/ports-and-networking.md](docs/ports-and-networking.md) — port forwarding, firewall, UPnP, dynamic IP
- [docs/protocol.md](docs/protocol.md) — wire protocol reference
```

---

## Files to delete after restructure

- `contacts-format-plan.md` — content consumed into docs/contacts.md
- `attachment-consent-plan.md` — content consumed into docs/attachments.md
- `scripting-tutorial.md` — moved to docs/hooks.md

`nat-traversal-report.md` is already a standalone reference doc; move it into
`docs/` without changes (update the link in README.md / ports-and-networking.md).
