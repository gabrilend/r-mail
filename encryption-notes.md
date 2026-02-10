# Encryption Notes — r-mail

## What we want

1. Encrypt all packet payloads with the shared secret key (symmetric encryption)
2. Rotate the key after each message using a derivation scheme
3. Keep N previous keys (configurable) as fallback
4. Don't store the rotation count — make it recalculatable but not obvious
5. Investigate whether this achieves "perfect encryption"


## Part 1: Symmetric encryption of packets

Currently, the shared token is sent in plaintext inside the JSON body over unencrypted HTTP. Anyone on the network path can read the message body AND steal the token.

The fix is two layers:

**Layer 1: Encrypt the payload.** The sender encrypts the entire JSON body with the shared secret before sending. The receiver decrypts before parsing. The token is no longer visible on the wire.

**Layer 2: Authenticate the payload.** Encryption alone doesn't prevent tampering. We need an HMAC (hash-based message authentication code) to verify the message wasn't modified in transit. This is called "encrypt-then-MAC" and it's the standard approach.

The packet format would become:

```
POST /deliver HTTP/1.1
Content-Type: application/octet-stream

[IV (16 bytes)][encrypted payload][HMAC (32 bytes)]
```

The receiver:
1. Extracts IV, ciphertext, and HMAC
2. Verifies HMAC (reject if invalid — someone tampered)
3. Decrypts ciphertext using the shared key + IV
4. Parses the resulting JSON as before

### Cipher choice

**AES-256-CBC** — industry standard, widely available, well understood. Needs an IV (initialization vector) per message to prevent identical plaintexts from producing identical ciphertexts. The IV is sent in the clear (not secret, just unique).

**ChaCha20-Poly1305** — modern alternative, faster in software, built-in authentication (no separate HMAC needed). Preferred by most modern protocols (WireGuard, TLS 1.3).

### Lua implementation options

Lua has no built-in crypto. Options:

1. **Shell out to openssl CLI** — `os.execute("openssl enc -aes-256-cbc ...")`
   - Pro: no new dependencies, openssl is everywhere
   - Con: slow (process spawn per encrypt/decrypt), awkward binary handling, shell injection risk

2. **LuaCrypto** — Lua binding for OpenSSL's libcrypto
   - Pro: fast, full-featured, proper API
   - Con: C dependency, may not be in all package managers
   - Availability: NixOS (lua54Packages.luacrypto), Arch (AUR), luarocks

3. **lua-openssl** — another OpenSSL binding, more comprehensive
   - Pro: more complete than LuaCrypto
   - Con: same dependency concerns

4. **Pure Lua AES** — implementations exist (e.g., aeslua)
   - Pro: no C dependencies, just drop a .lua file in libs/
   - Con: very slow for large payloads (attachments), maybe 100x slower than C

5. **LuaSec** — TLS for luasocket
   - This would encrypt the entire TCP connection (HTTPS), not individual payloads
   - Pro: well-tested, standard approach
   - Con: requires certificates, more complex setup, doesn't give us key rotation

**Recommendation:** LuaCrypto via luarocks/package manager for users who have it, with a pure-Lua fallback for minimal setups. Or just require LuaCrypto as a dependency like we require luasocket.

An alternative worth considering: just use LuaSec to upgrade from HTTP to HTTPS. This gives us encryption + authentication for free, using standard TLS. The shared secret in the contacts file becomes a pre-shared key or is used to verify a self-signed certificate. This doesn't give us key rotation (TLS handles its own key management), but it does solve the core problem of encrypted transport.


## Part 2: Key rotation scheme

### What you described

After each message, derive the next key from halves of the current key:

```
K0 = original shared secret
K1 = derive(first_half(K0), second_half(K0))
K2 = derive(first_half(K1), second_half(K1))
...
```

Since first_half + second_half = the whole key, this simplifies to:

```
K1 = hash(K0)
K2 = hash(K1) = hash(hash(K0))
K3 = hash(K2) = hash(hash(hash(K0)))
```

This is a **hash chain**. It's a real and well-studied cryptographic primitive.

### Making sender/receiver halves meaningful

To make the "first user / second user" distinction matter, we could incorporate both parties' identities:

```
K1 = hash(sender_name .. K0 .. receiver_name)
```

Now the key depends on WHO sent the message and WHO received it. A message from Alice to Bob uses a different key derivation than Bob to Alice. This creates two independent chains per contact pair:

```
Alice→Bob chain: K0, hash("alice" .. K0 .. "bob"), hash("alice" .. K1_ab .. "bob"), ...
Bob→Alice chain: K0, hash("bob" .. K0 .. "alice"), hash("bob" .. K1_ba .. "alice"), ...
```

This has a nice property: compromising one direction doesn't compromise the other.

### Security properties

**Forward secrecy (partial):** If someone learns K_n, they can compute K_{n+1}, K_{n+2}, etc. (the hash function goes forward). But they CANNOT compute K_{n-1} (hash functions are one-way). So stealing the current key doesn't reveal past messages. This is called "forward secrecy" and it's genuinely valuable.

**No backward secrecy:** Knowing the current key reveals all future keys. True backward secrecy (also called "post-compromise security") requires an interactive key exchange (like Diffie-Hellman ratchet, which Signal uses). We can't do that in a store-and-forward system like r-mail without adding interactive rounds.

**Recoverability:** If you know K0 (the original secret), you can recompute any K_n by hashing n times. You just don't know n. An attacker who learns K0 can try K0, hash(K0), hash(hash(K0)), ... until one works. This is bounded by the number of messages ever sent, which is probably small (thousands, not billions). So K0 is the real secret — the rotation makes things harder but not impossibly so.

### Does this achieve "perfect encryption"?

No, in the strict cryptographic sense. **Perfect secrecy** (Shannon, 1949) requires the key to be at least as long as the message and never reused. That's the one-time pad, and nothing else achieves it.

What this DOES achieve:
- **Computational security** — breaking it requires breaking AES or the hash function, which is infeasible with current technology
- **Partial forward secrecy** — past messages stay safe if the current key leaks
- **Key agility** — each message uses a different key, so one compromised message doesn't reveal others (going backward)
- **Obscurity of iteration count** — an attacker needs both K0 AND the rotation count to derive the current key (but can brute-force the count)

What it does NOT achieve:
- **Post-compromise security** — if K_current leaks, all future keys are compromised
- **Perfect secrecy** — mathematically impossible without one-time pads
- **Protection against K0 compromise** — if someone learns the original secret, they can derive all keys (past and future) by iterating


## Part 3: Key synchronization

The hardest part. Both sides need to agree on which key to use.

### When to rotate

Option A: **Rotate on every message.** Simple rule, but if a message is lost or delivered out of order, the sides get out of sync.

Option B: **Rotate on every successful delivery.** The sender rotates after getting a 200 OK. The receiver rotates after decrypting successfully. This is safer but still fragile — what if the 200 OK is lost? Sender didn't rotate, receiver did.

Option C: **Include a key generation number in the (encrypted) header.** The sender says "this message was encrypted with key generation 47." The receiver can compute K47 from K0 by hashing 47 times (or from a cached recent key). This eliminates sync issues but reveals the generation number to attackers (who could use it with K0).

Option D: **Try multiple keys.** Keep the last N keys. Try decrypting with each until one works. If none work, reject the message. This is what you suggested and it's the most robust approach.

### Keeping previous keys

Config option: `KEY_HISTORY = 2` (default: keep 2 previous keys)

The receiver tries decryption in order: K_current, K_current-1, K_current-2. If K_current-2 works, the receiver knows they missed some rotations and updates their current to match.

State stored per contact:
```json
{
  "alice": {
    "keys": ["current_key_hex", "previous_key_hex", "oldest_key_hex"],
    "generation": 47
  }
}
```

Wait — you said don't store the generation count. So:

```json
{
  "alice": {
    "keys": ["current_key_hex", "previous_key_hex"]
  }
}
```

The keys array is a sliding window. When we rotate, push new key to front, drop oldest if over the limit. We never record how many rotations happened.

### The recalculability question

You said the key should be "recalculatable from the original secret." This is true of hash chains — if you have K0, you can compute K1, K2, ..., K_n for any n. But without storing n, you'd have to iterate from K0 until you find a key that matches the current one.

This means:
- You CAN recover from state loss (re-derive from K0)
- You CANNOT know the generation without trying (iterate and compare)
- An attacker with K0 faces the same iteration cost (low — probably < 100,000 tries for most users)
- The rotation adds a speed bump, not a wall

If you want the iteration count to be truly unknowable, don't store the generation. Both sides just keep their sliding window of recent keys and rotate forward. If they get hopelessly out of sync, they'd need to re-derive from K0 (which means the user re-enters their original shared secret, and the daemon iterates forward until it finds one the contact's daemon accepts).


## Part 4: Implementation plan

### Config options

```lua
local ENCRYPT = true           -- encrypt all packets
local KEY_ROTATE = true        -- rotate key after each message
local KEY_HISTORY = 2          -- previous keys to keep for fallback
```

### Dependencies needed

- A crypto library (LuaCrypto, lua-openssl, or pure-Lua AES)
- A hash function (SHA-256, from the same library)
- HMAC (from the same library, or built from the hash function)

### Changes to rmail.lua

1. Add encrypt/decrypt functions using the shared secret
2. Wrap all http_post_batch payloads in encryption
3. Unwrap all received payloads in the HTTP server
4. Add key rotation logic after successful send/receive
5. Add key history to per-contact state
6. Add fallback key trial on decryption failure
7. The auth_check function changes — instead of comparing tokens in plaintext, successful decryption IS the authentication

### Changes to the protocol

The HTTP endpoints stay the same (/deliver, /delete, etc). But the body is no longer JSON — it's encrypted binary. The Content-Type changes from application/json to application/octet-stream.

The receiver:
1. Reads the raw binary body
2. Tries decrypting with current key, then previous keys
3. If decryption succeeds, parses the JSON inside
4. Successful decryption proves the sender has the right key (no separate auth_check needed)
5. Rotates key if configured

### What stays the same

The contacts file still has a "token" field per contact. This is K0 — the original shared secret. The daemon derives the current encryption key from it. The user never needs to change it (the rotation is automatic and invisible).


## Part 5: Threat model

What this protects against:
- **Network eavesdropping** — messages are encrypted on the wire
- **Token theft from sniffing** — token is never sent in plaintext
- **Replay attacks** — key rotation means a captured message can't be replayed later (wrong key)
- **Partial key compromise** — if current key leaks, past messages stay safe (forward secrecy)

What this does NOT protect against:
- **Compromise of K0** — an attacker who learns the original shared secret can derive all keys
- **Compromise of the contacts file** — K0 is stored there in plaintext
- **Server compromise** — if someone has access to your machine, they can read inbox/outbox files directly (plaintext on disk)
- **Future key compromise** — if current key leaks, all future messages are compromised until K0 is changed
- **Denial of service** — encrypted or not, someone can still flood your port

For full at-rest encryption (files on disk), that's a separate feature and much more complex.


## Open questions

- Which crypto library? LuaCrypto is the most practical but adds a C dependency. Pure Lua AES works but is slow for attachments.

- Should we encrypt the entire HTTP body or just the JSON payload? Entire body is simpler and prevents metadata leakage.

- How to handle the GET / health check? It has no auth — should it remain unencrypted? Probably yes, since it reveals nothing sensitive (just name and "ok").

- Should key rotation happen per-message or per-sync-cycle? Per-message gives more keys but increases desync risk. Per-cycle is simpler.

- The /update-address endpoint sends the new IP in the encrypted payload. If the contact's key is out of sync, they can't decrypt the address update. This could cause a permanent disconnect. Maybe address updates should use K0 (the original secret) as a fallback?

- For the "try multiple keys" approach: an attacker could send garbage messages to force the receiver to try all keys, which is computationally cheap (just 2-3 AES decryptions) but could be used for timing attacks. Probably not a real concern for r-mail's threat model.


## Part 6: The HTTPS approach (LuaSec)

### What TLS gives us for free

HTTPS is HTTP inside a TLS tunnel. TLS already provides everything from Parts 1-3:

- **AES-256 or ChaCha20** encryption (same ciphers)
- **HMAC / Poly1305** authentication (same integrity checks)
- **Diffie-Hellman key exchange** — derives session keys without ever sending them over the wire
- **Forward secrecy** — each connection uses a fresh ephemeral key. Compromising the long-term key doesn't reveal past sessions. This is BETTER than our hash chain because it provides true post-compromise security per-session.
- **Key rotation** — happens automatically on each new TLS connection. No desync risk, no key history management, no generation tracking.
- **Replay protection** — built into the TLS handshake

We would NOT need to implement: cipher selection, IV management, HMAC, key derivation, key rotation, key synchronization, fallback key trials, or any of the complexity from Parts 2-4. TLS handles all of it.

### What TLS does NOT give us

- **Application-level authentication** — TLS proves "this connection is encrypted" but not "you are alice." We still need the shared secret for that. See below for options.
- **At-rest encryption** — files on disk are still plaintext.

### How it would work with r-mail

#### Option A: Self-signed certificates + certificate pinning

Each daemon generates a self-signed TLS certificate on first startup. The certificate fingerprint goes in the contacts file:

```json
{
  "alice": {
    "host": "203.0.113.1",
    "port": 8025,
    "token": "shared-secret",
    "cert_fingerprint": "sha256:ab12cd34..."
  }
}
```

When connecting to alice, the daemon verifies her certificate fingerprint matches. This prevents man-in-the-middle attacks without needing a certificate authority. Users exchange fingerprints the same way they exchange tokens — out of band (in person, over a trusted channel).

The shared token is still sent inside the (now encrypted) payload for application-level auth.

**Pro:** Strong security model, widely used (this is how Signal, SSH, and Tor verify peers).
**Con:** Users need to exchange one more piece of info (the fingerprint). Certificate generation adds startup complexity.

#### Option B: TLS-PSK (Pre-Shared Key)

TLS supports a mode where both sides authenticate using a pre-shared key instead of certificates. The shared secret in the contacts file IS the TLS key. No certificates needed.

```json
{
  "alice": {
    "host": "203.0.113.1",
    "port": 8025,
    "token": "shared-secret"
  }
}
```

The token does double duty: TLS authentication AND application-level auth. The contacts file format doesn't change at all.

**Pro:** No certificates, no fingerprints, nothing new for users to configure. The existing token field just becomes more powerful.
**Con:** TLS-PSK is less commonly supported. LuaSec may not support it (needs investigation). If it doesn't, this option is off the table.

#### Option C: Self-signed certificates, auto-exchanged

The daemon generates a self-signed cert on first startup. When two daemons first connect (authenticated by the shared token over plain HTTP), they exchange certificate fingerprints automatically. Future connections use TLS with pinned certificates.

This is a "trust on first use" (TOFU) model, like SSH's `known_hosts`.

```
First connection:  HTTP + token auth → exchange cert fingerprints
All future connections:  HTTPS + certificate pinning
```

**Pro:** Zero extra configuration. Upgrade happens automatically.
**Con:** The first connection is unencrypted (vulnerable to interception). An attacker who intercepts the first connection can MITM all future ones. Same weakness as SSH.

### LuaSec specifics

LuaSec is the TLS library for luasocket. It wraps OpenSSL.

**Installation:**
- NixOS: `lua54Packages.luasec`
- Arch: `lua-sec` (AUR) or `luarocks install luasec`
- Void: `lua54-luasec` (if available) or luarocks
- Gentoo: `dev-lua/luasec` or luarocks

**API:**
```lua
local ssl = require("ssl")

-- Server side (accepting connections):
local params = {
    mode = "server",
    protocol = "tlsv1_3",
    key = "/path/to/server.key",
    certificate = "/path/to/server.crt",
}
local conn = ssl.wrap(client_socket, params)
conn:dohandshake()

-- Client side (connecting):
local params = {
    mode = "client",
    protocol = "tlsv1_3",
    verify = "none",  -- or "peer" with cafile
}
local conn = ssl.wrap(tcp_socket, params)
conn:dohandshake()
```

After the handshake, `conn` works like a regular luasocket — `conn:send()`, `conn:receive()`, etc. The rest of our HTTP code stays the same.

### Changes to rmail.lua

**Server side (main loop):**
```lua
-- After accepting a connection:
local client = server:accept()
local ssl_client = ssl.wrap(client, server_ssl_params)
ssl_client:dohandshake()
-- Then use ssl_client exactly like we use client now
```

**Client side (http_post_batch):**
```lua
-- After connecting:
conn:connect(req.host, req.port)
local ssl_conn = ssl.wrap(conn, client_ssl_params)
ssl_conn:dohandshake()
-- Then send/receive on ssl_conn
```

**Certificate generation (on first startup):**
```lua
-- Generate self-signed cert if none exists
if not file_exists(STATE .. "/server.key") then
    os.execute("openssl req -x509 -newkey rsa:4096 -keyout " ..
        shell_quote(STATE .. "/server.key") ..
        " -out " .. shell_quote(STATE .. "/server.crt") ..
        " -days 36500 -nodes -subj '/CN=rmail'")
end
```

This generates a cert valid for 100 years. The cert lives in .state/ alongside the other daemon files.

### Config options

```lua
local ENCRYPT = true   -- use TLS for all connections
                       -- requires luasec: luarocks install luasec
```

When ENCRYPT is false, everything works as before (plain HTTP). When true, all connections use TLS. Both sides must have ENCRYPT enabled.

The shared token continues to work as application-level auth inside the encrypted tunnel. No changes to the contacts file format.

### Recommendation

**Use LuaSec (Option A or C), not custom encryption.**

Reasons:
1. TLS is battle-tested by billions of connections daily. Custom crypto is not.
2. Forward secrecy is better (ephemeral Diffie-Hellman vs hash chain).
3. No key sync problem — TLS handles it per-connection.
4. The code changes are small — wrap sockets, generate certs.
5. One new dependency (LuaSec), same as we already depend on luasocket.
6. The custom key rotation scheme from Part 2 can be layered ON TOP of TLS later if desired — as an additional defense-in-depth measure, not the primary encryption.

The custom key rotation idea is not wasted — it's a good defense-in-depth layer. But it should sit inside the TLS tunnel as extra application-level encryption, not replace TLS as the transport layer. Belt and suspenders.

### What this means for the key rotation idea

The key rotation scheme (Part 2) becomes an optional inner layer:

```
[TLS tunnel [encrypted JSON (key-rotated AES) [plaintext JSON payload]]]
```

TLS protects the transport. The key rotation protects against a compromised TLS implementation or a future TLS vulnerability. Both would need to be broken to read a message. This is what Signal does — TLS on the outside, Signal Protocol (with its own ratchet) on the inside.

For v1 of r-mail encryption: just TLS. It solves 95% of the problem with 5% of the complexity. The inner encryption layer can come later.
