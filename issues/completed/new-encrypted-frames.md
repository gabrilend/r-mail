# #new-encrypted-frames — Everything travels in sealed frames, and the key that opens one says who sent it

## Status

Completed — a blueprint written 2026-10-04 (#402) for what was built
before issue files described it (commit 60d309e, "Replace TLS-PSK with
custom AES-256-GCM encryption", 2026-03-24, and the work around it).

## Current Behavior

**Keys.**  Two contacts share a secret, the *token* (a string, written
in each other's contacts file as `name.token`).  The key is the SHA-256
of the token: 32 bytes, the same on both sides, never sent.

**A frame**, in both directions, on TCP:

    [length: 4 bytes, big-endian][nonce: 12 random bytes][ciphertext][tag: 16 bytes]

AES-256-GCM: the ciphertext is the plaintext's length, the tag proves the
whole was sealed with that key and not changed.  A frame shorter than 28
bytes or longer than 64 MB is dropped unread.  The cipher lives in a
small C module (`rmail_crypto.c`, built against OpenSSL's EVP functions):
`sha256`, `random_bytes`, `aes_gcm_encrypt`, `aes_gcm_decrypt`.  The
phone has the same in Kotlin (`crypto/Crypto.kt`).

**Who sent it.**  Nothing in a frame names its sender.  The receiver
tries each contact's key in turn (`trial_decrypt`); the one whose tag
checks out is the sender — a wrong key fails the tag, it does not yield
garbage.  No key fits: the connection is dropped and "decryption failed"
logged.  On one connection, later frames try the first frame's key
first.  Any frame from a contact makes that contact due at once on our
side (#377), so a reply goes out on the next pass.

**What is inside**: a small HTTP/1.1 request — a request line, headers,
a blank line, a body (`Content-Length` at most 50 MB; usually JSON) — and
the answer comes back the same way, sealed with the same key: a status
line, headers, a JSON body.  The paths:

| path | who may use it | what for |
|---|---|---|
| `POST /deliver` | any contact | everything about messages and attachments, by `type` (#new-a-message-is-a-file, #new-consent-before-any-byte, #407) |
| `POST /delete` | any contact | a message was deleted (#new-deletes-travel-both-ways) |
| `POST /update-address` | any contact | where the sender is now (#new-announcing-a-new-address) |
| `GET /peer-address` | any contact | where we have the caller, for a phone that lost its way (#365) |
| `GET /deps`, `/deps/<name>`, `/install-script` | any contact | the code and its dependencies (#376) |
| `GET /` | any contact | `{ok, name}` — inside the seal, so only a contact reads the name |
| `/api/...` | own devices only (`own = true`) | the phone's mailbox access (#new-the-phone-api); 403 otherwise |

**One plain exception.**  A connection whose first four bytes are `GET `
is answered unsealed with `{"ok":true}` and closed: a port-forward test
from outside, needing no token, saying nothing about the mailbox (#410).

**Sending.**  `http_post_batch` opens every request of a batch at once,
non-blocking, and waits up to 8 seconds in all for connections, sends and
answers; each answer is opened with the request's own key.  A request
that got no answer is tried at the contact's other addresses, one at a
time, and an address that worked is moved up the contact's list (#347).
`http_post_batch_with_fallback` holds back requests to contacts not yet
due (#377).  A connection is used for one request and closed.  An answer
`503 {"busy": true}` means the contact was sending to us at that moment
(#387): retried at the next cycle, with no backoff and no other address.

## Intended Behavior

As above.  What the frames do not hide — that two addresses talk, when,
and how much — is phase 9's subject (#366, #367, #401).

## Suggested Implementation Steps

1. `rmail_crypto.c`; `rmail.lua`: `derive_key`, `send_encrypted`,
   `recv_encrypted`, `encrypt_packet` / `decrypt_packet` (the same without
   a length, for LAN discovery's datagrams, #102), `trial_decrypt`,
   `parse_request_string`, `make_response_buffer`.
2. `handle_request`: the plaintext check, the frame loop, the path table
   above.
3. `http_post_batch`, `http_encrypt_and_send`,
   `http_read_encrypted_response`, `http_post_batch_raw` (other
   addresses), `http_post_batch_with_fallback` (the timer gate).
4. Tests: every `scripts/test-*.sh` that uses `scripts/lib/fake-contact.lua`
   speaks this format from outside; `test-plaintext-health-check.sh`.

## Related documents

- `docs/.templates/encryption.md`, `docs/.templates/protocol.md`
- `#410`, `#377`, `#347`, `#204` (sending all of a large frame)
