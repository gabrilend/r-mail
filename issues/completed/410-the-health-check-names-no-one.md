# #410 — The plaintext health check names no one

## Status

Completed 2026-10-04.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.5), checked by hand.
The owner: "What the hey, why did we build that behavior? We shouldn't
enable that, but I want to know why, so I know what we need to adapt the
design to handle."

## Current Behavior

A connection whose first four bytes are `GET ` is answered in plain
HTTP, without any key, with `200` and the body `{"ok":true}`.  It says
that something is listening on the port and nothing about whose mailbox
it is.  The answer exists so a person can test from outside that their
router forwards the port, without having the token;
`scripts/validate-router-settings.sh` uses it that way and needs only an
answer.

**Why it once carried the name** (git history): before 2026-03-24 rmail
spoke TLS with a pre-shared key, and `GET /` answered
`{ok = true, name = my_name}` *inside* the TLS connection — only someone
holding the key could read it.  Commit 60d309e ("Replace TLS-PSK with
custom AES-256-GCM encryption") moved encryption inside each frame and
kept `GET /` in the clear "for curl/connectivity testing"; the reply came
along unchanged.  Nobody chose to publish the name: it was harmless
inside TLS and became a leak when the encryption moved.  Nothing read it.

What the design has to keep handling: a port-forward test from outside,
without the token.  It still works, since it needs only an answer.

## Intended Behavior

As above.  The documents' claim that no name is sent in cleartext is
true.

## Suggested Implementation Steps

- `rmail.lua`, the connection handler's plaintext branch (the comment
  there tells the history above): the reply drops `name`.
- `scripts/install.sh` and `scripts/make-mailbox-drive.sh`: the comments
  on the `name` setting no longer say the health check exposes it.
- Docs corrected: README (verifying the daemon, trial decryption),
  encryption guide (how the receiver knows who sent it; the threat
  table), protocol guide (`GET /`), Android guide (testing the port).
- Test: `scripts/test-plaintext-health-check.sh` — a plain `GET /` is
  answered 200 with exactly `{"ok":true}`; the configured name appears
  nowhere in the reply, headers included; the validator's own kind of
  probe still gets an answer.

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- commit 60d309e
- `docs/.templates/encryption.md`, `scripts/install.sh`
