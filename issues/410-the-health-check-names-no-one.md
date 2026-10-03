# #410 — The plaintext health check names no one

## Status

Open, 2026-10-02.  Found by the documents-against-code audit
(`notes/audit-docs-against-code-2026-10-02.md`, §1.5), checked by hand.
The owner: "What the hey, why did we build that behavior? We shouldn't
enable that, but I want to know why, so I know what we need to adapt the
design to handle."

## Current Behavior

A connection whose first four bytes are `GET ` is answered in plain text
with `{"ok":true,"name":<this mailbox's name>}` — to anyone, no key
needed.  The encryption guide and README say no name is sent in
cleartext (encryption template 80, 97, 472; README:316); install.sh's
config comment admits it (876-878).

**Why it exists** (git history): before 2026-03-24 rmail spoke TLS with a
pre-shared key, and `GET /` answered `{ok = true, name = my_name}`
*inside* the TLS connection — only someone holding the key could read
it.  Commit 60d309e ("Replace TLS-PSK with custom AES-256-GCM
encryption") moved encryption inside each frame and kept `GET /` in the
clear "for curl/connectivity testing"; the reply came along unchanged.
Nobody chose to publish the name: it was harmless inside TLS and became
a leak when the encryption moved.  Nothing reads the name today —
`scripts/validate-router-settings.sh` sends `GET /` only to see whether
the port answers and discards the body.

What the design must handle: a person still needs a way to test that a
port forward works from outside, without the token (the reason the
plaintext answer was kept).

## Intended Behavior

The plaintext answer carries nothing about the mailbox: `{"ok":true}`
(or an empty 200).  Testing a port forward keeps working, since the
validator only needs an answer.  The documents' claim becomes true.

## Suggested Implementation Steps

1. The health check's reply drops `name`.
2. install.sh's config comment no longer says the name is exposed.
3. Test: a plain `GET /` gets an answer containing no configured name;
   `validate-router-settings.sh` still reports the port open.

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- commit 60d309e
- `docs/.templates/encryption.md`, `scripts/install.sh`
