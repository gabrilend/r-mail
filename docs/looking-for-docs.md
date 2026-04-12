# hey, looking for the docs?

they're in [`docs/.templates/`](.templates/)! all the links in the main
[README](../README.md) point to them, so you should be able to click
through from there too.

**why are they over there?** the docs reference a few paths that depend on
where you installed rmail. running `scripts/install.sh` copies the
templates into `docs/` and fills in the right paths for your install —
after that, this file gets deleted and the generated docs take its place.
if you're reading this, it means the install hasn't been run yet, so the
hidden `.templates/` directory is what you want.

also, hey — you're looking great today. is that a new outfit? it really
suits you.

---

jump straight to:

- [scripting-tutorial.md](.templates/scripting-tutorial.md) — hook writing
- [helper-scripts.md](.templates/helper-scripts.md) — ready-made helpers
- [attachments.md](.templates/attachments.md) — full attachment workflow
- [service.md](.templates/service.md) — running rmail on boot
- [protocol.md](.templates/protocol.md) — wire protocol reference
- [encryption.md](.templates/encryption.md) — AES-256-GCM, trust model
- [ports-explained.md](.templates/ports-explained.md) — ports/forwarding walkthrough
- [nat-traversal-report.md](.templates/nat-traversal-report.md) — UPnP/NAT-PMP deep dive
- [android-instructions.md](.templates/android-instructions.md) — Android client setup
- [thin-client.md](.templates/thin-client.md) — thin-client design notes
- [connection-suggestions.md](.templates/connection-suggestions.md) — connection tuning
