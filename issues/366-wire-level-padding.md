# #366 — Wire-level random padding to blunt size-based traffic analysis

## Problem

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

- **This issue (#366)** — implement padding at the wire frame,
  transparent to callers, so every message gets some size
  obfuscation without requiring user configuration.
- **#367** — a separate user-opt-in technique that normalizes
  *large* message sizes by sending the body as a fixed-chunk
  attachment.  The two compose: #366 blunts size inference for
  small messages; #367 handles the large-message case.

The encryption.md misdescription was fixed separately in the same
sweep; this issue tracks making the doc accurate in the other
direction — actually implementing what the doc used to claim.

## Design

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
(#349), which hands the body off to the chunk pipeline.  Either
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
  want tighter normalization opt into #367 (body-as-attachment).

## Implementation notes

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

Open.
