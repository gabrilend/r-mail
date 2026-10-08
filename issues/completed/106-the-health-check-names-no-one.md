# #106 — The plaintext health check names no one

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

**How a connection's opening is told apart** (since 2026-10-08).  The
health check used to be recognised by the exact bytes `GET `; every other
opening was read as a frame's 4-byte length.  A web page cannot send bare
bytes — the browser writes a request line and headers before the body —
so a page that POSTed a sealed frame arrived as the "length" `POST` =
1,347,375,956, over the 64 MiB limit, and was dropped unread.  Found while
planning a feedback box on the HTML docs.  Now the first byte decides: a
legal length (28 bytes to 64 MiB) always starts 0x00–0x04, a web request
with a capital letter (0x41 and up), so neither can be mistaken for the
other.  A dispatch table on the method then answers:

- `GET` — the health answer above, then closed.
- `POST` — headers skipped; the body must be exactly one frame (declared
  Content-Length = 4 + the frame's own length, else `400`), read and
  trial-decrypted like any other.  The sealed answer is sent back as the
  body of a `200` web reply so a browser sees a well-formed answer; the
  connection then closes.  It opens nothing a bare frame does not.
- any other method — `405` with `Allow: GET, POST`, logged.
- capital letters with no request line — closed, nothing said.

Both places that read an opening use it: the main request loop, and the
code that answers callers while a sync cycle waits (#120).  A caller held
there keeps how it must be answered (bare frame or web reply) in its held
record, and the main loop hands that whole record on.

Not built here, and wanted before a token is ever published on a page: a
contact mark that allows only plain message delivery (today a token also
allows `/delete` and `/update-address`).

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
- `rmail.lua`, the frame-in-a-web-request section beside the frame
  readers: the opening-byte rule and the method dispatch table; sealing a
  frame is split from sending it so a frame can go out inside a web reply.
  The request loop and the busy-while-sending answerer call it.
- Test: `scripts/test-frame-in-web-request.sh` — bare frames still work
  and keep the connection; a frame in a POST is answered in a web reply
  and a message sent that way lands in the inbox; wrong key, wrong length,
  other methods and non-requests are refused.  `test-busy-while-sending.sh`
  gains a browser-style caller answered busy, and one held and answered
  after the cycle.  `scripts/lib/fake-contact.lua` gains the raw and
  web-POST ways of calling.
- Docs: protocol guide ("A frame sent from a web page", other methods);
  encryption guide (the browser's headers travel in cleartext).

## Related documents

- `notes/audit-docs-against-code-2026-10-02.md`
- commit 60d309e
- `docs/.templates/encryption.md`, `scripts/install.sh`
