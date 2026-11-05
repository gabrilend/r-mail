# #901 — Wire-level random padding to blunt size-based traffic analysis

## Current Behavior

`docs/encryption.md` has, for a while, described a "random padding"
step inside the wire frame:

> A random amount of extra garbage data, appended after the real
> message but before the seal.  The receiver knows the real message
> length from the internal headers and ignores the padding.

No such padding exists.  The actual wire frame (see `send_encrypted`
at `rmail.lua:1826`) is exactly:

```
[4-byte BE length][12-byte nonce][ciphertext + 16-byte GCM tag]
```

No bytes added beyond the plaintext.  An observer who watches
encrypted traffic between two rmail nodes can read the length field
and infer the plaintext size to byte precision (modulo the fixed
12 + 16 = 28-byte GCM overhead).  For short, patterned messages
("ok", "on my way", "see you at 3pm") this is a meaningful signal.

Two related issues track what should happen:

- **This issue (#901)** — implement padding at the wire frame,
  transparent to callers, so every message gets some size
  obfuscation without requiring user configuration.
- **#902** — a separate user-opt-in technique that normalizes
  *large* message sizes by sending the body as a fixed-chunk
  attachment.  The two compose: #901 blunts size inference for
  small messages; #902 handles the large-message case.

The encryption.md misdescription was fixed separately in the same
sweep; this issue tracks making the doc accurate in the other
direction — actually implementing what the doc used to claim.

## Intended Behavior

### Padding inside the ciphertext, not outside it

The padding has to be inside AES-GCM so it's invisible to an
observer.  If we appended random bytes after the GCM tag (as the old
doc misleadingly implied), an observer would see them too — they'd
just not know that's what they were.  Size obfuscation requires the
padding to be sealed *with* the message.

Proposed plaintext format:

```
[4-byte BE real-length][real plaintext bytes][padding bytes]
```

`encrypt_packet` / `send_encrypted` generate random padding, prepend
the real length, concatenate, and hand the result to
`aes_gcm_encrypt`.  `decrypt_packet` / `recv_encrypted` decrypt,
read the first 4 bytes as the real length, return
`plaintext[5 .. 4 + real_length]`.  The padding is authenticated by
the GCM tag — it can't be stripped or substituted in flight without
invalidating the tag.

### How much to pad

Two reasonable options:

1. **Pad to the next power of 2** above the real plaintext size,
   capped at some max (e.g. 64 KB above that, don't pad further
   because the message is already a big attachment transfer).  This
   reveals only the power-of-2 bucket the message landed in —
   "between 32 and 64 bytes" rather than "42 bytes".  Trivial to
   implement, coarse but effective.
2. **Pad to the next 256-byte multiple, then add a random 0–255-byte
   jitter.**  Similar information loss, slightly more expensive to
   compute, slightly more confusing to reason about.

Prefer option 1.  Simple and the bucket boundaries are predictable,
which makes the implementation easier to test.

For messages ≥ 128 KB we already hit the auto-body attachment path
(#308), which hands the body off to the chunk pipeline.  Either
pass padding through there too (chunk size is fixed — each chunk is
already padded up to `cfg.chunk_size`) or skip this layer for
auto-body messages.  Skipping is fine; chunk size already normalizes.

### Caps and waste

Worst case: a 1-byte message gets padded to the next power of 2, which
is 2 bytes.  That's not useful — bump the minimum bucket up to at
least 64 bytes so the shortest messages hide in a meaningful pool.

Cap the maximum added padding at, say, 16 KB.  Beyond that the
message is already big enough that size disclosure isn't
informative, and the bandwidth waste isn't worth it.  Something like:

```
target = max(64, next_power_of_2(real_size))
target = min(target, real_size + 16384)
padding_bytes = target - real_size
```

### Backwards compatibility

This is a wire-format change.  An old daemon talking to a new
daemon would see a message whose first 4 bytes are a length that
doesn't match the remaining bytes — the old decrypt path doesn't
know about the inner length prefix.

Options:

- **Hard break, bump a protocol version byte.**  Add a
  configurable `protocol_version` field to contacts; only pad when
  both sides know the new format.  Cleanest but adds a coordination
  step for users.
- **Auto-detect on receive.**  After AES-GCM decrypt, try the new
  format (read first 4 bytes as length, check if
  `4 + real_length <= total_plaintext_len`); if it parses, use it;
  otherwise return the whole plaintext as-is (old format).  No
  user-facing coordination; a new daemon talks to an old daemon in
  the old format, and vice versa.

Auto-detect is almost certainly the right call — the cost is one
extra length check on receive.  The risk is ambiguity (an old-format
message whose first 4 bytes happen to encode a valid "inner length"
matching the remaining size).  For a random plaintext, that's a
1-in-4-billion collision for any specific length — vanishingly rare,
and if it does happen the resulting plaintext just looks garbled,
not dangerous.

## Non-goals

- **Hiding timing.**  An observer still sees *when* messages are
  sent.  Timing analysis is out of scope for wire padding; the
  decoy-traffic hooks in encryption.md (cron-based) are the right
  tool for that.
- **Hiding existence.**  The fact that two IPs are exchanging
  rmail-shaped packets remains visible.  That's a Tor/relay
  problem, not a padding problem.
- **Normalizing every possible message size identically.**
  Power-of-2 bucketing keeps a small amount of signal.  Users who
  want tighter normalization opt into #902 (body-as-attachment).

## Suggested Implementation Steps

- Touch `encrypt_packet`, `decrypt_packet`, `send_encrypted`,
  `recv_encrypted` (`rmail.lua:1862-1880`, `rmail.lua:1824-1860`).
- Generate padding bytes with `crypto.random_bytes(n)` — already in
  use for nonces.
- Add a test harness: encrypt a known plaintext at known sizes,
  verify the on-wire length lands in the expected bucket, and
  round-trip decrypts to the original plaintext.
- `docs/encryption.md` already been updated to say padding is *not*
  currently done; update again when this lands.

## Source

Identified 2026-04-19 while reviewing `docs/encryption.md`: the
"random padding" claim in the doc didn't match the code.  Doc
corrected in the same session; this issue tracks implementing the
feature the doc used to promise.

## Status

Built 2026-11-05, waiting for the owner's checks.  Every frame between two
daemons that read padding is padded inside the seal to the issue's option
1 (power of two, 64 bytes at least, 16 KiB added at most); older daemons,
the phone, the thin client and web pages are answered as before.  How the
two sides agree is below.  Test: `scripts/test-wire-padding.sh`.  Docs:
`docs/.templates/encryption.md` ("What gets sent over the wire") and
`docs/.templates/protocol.md` ("Padding").

## Decisions (2026-11-05)

Made by the builder; the owner can overturn each.

1. **Auto-detect on receive, as the issue prefers, plus a learned note for
   sending.**  Auto-detect alone tells a new receiver what it got, but not
   a new sender whether the other side can read padding: an older daemon
   reads a padded request as nonsense.  The phone app, the thin client and
   web pages would be broken the same way.  So: every request carries
   `Rmail-Pad: 1` inside the seal (older programs ignore unknown lines); an
   answer is padded when its request was padded or carried the line; a
   request is padded only to a contact that has shown it reads padding.
   No setting and nothing for the owner to coordinate — the issue's reason
   for preferring auto-detect.  The first request to a new contact goes
   unpadded; everything after it is padded.
2. **The note is `.state/wire-padding.json`: contact name -> the day it was
   learned.**  Plain names, as every state file since #505's reversal.  Read
   from the file on each request, so deleting a line by hand works at once.
   Kept on disk so a restart does not send a round of unpadded requests.
3. **Going back to an older daemon is noticed.**  An older daemon reads a
   padded request's length prefix as part of the method and answers 404,
   unpadded — which no newer daemon ever does to a padded request.  The
   contact is forgotten (logged) and the request treated like a busy
   answer: sent again shortly, unpadded, with no backoff.  If the length
   bytes happen to hold a newline the older daemon closes the connection
   instead; that looks like any failed connection, so the owner deletes
   the line by hand (said in encryption.md).  A request arriving with no
   line does *not* forget a contact: the phone may share a contact with a
   daemon, and flapping would cost more than it saves.
4. **A padded plaintext always starts with a 0 byte.**  Only plaintexts
   under 16 MiB are padded, so the length's first byte is 0; old
   plaintexts start with "POST", "GET " or "HTTP".  The receiver checks
   that byte and that the length fits — stricter than the issue's
   length-only check, so the 1-in-4-billion ambiguity cannot happen.
5. **Every frame under 16 MiB is padded, attachment pieces and auto-body
   messages (#308) too,** instead of skipping them.  The 16 KiB cap keeps
   the waste to 0.3% of a 5 MiB piece, and one rule is simpler to reason
   about than two.  The padding bytes are random (`crypto.random_bytes`,
   in 4 KiB calls, its limit), as the issue says, though zeros would be as
   hidden inside AES-GCM.
6. **The sizes are of the whole sealed plaintext, length prefix included,**
   so a frame on the wire is always a power of two plus 32 bytes (4 length
   + 12 nonce + 16 tag) below the cap — what the test checks.
7. **No new top-level names beyond one table, `wirepad`,** since
   `rmail.lua`'s main chunk is near Lua's 200-local limit.
8. **Base: built on #16 (claude/419-wake-to-sync), not on main.**  The
   change needs nothing from the chain, but `rmail.lua` has moved a long
   way on it and the framing code would conflict line by line if built
   on main.  #902 is stacked on this.
