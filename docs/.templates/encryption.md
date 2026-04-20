# Encryption and security

This document explains how rmail keeps your messages private, what it
protects against, and how to set up a host that's as secure as possible.

For most use-cases, you don't need to know anything in here. rmail is already
significantly more secure than many other common softwares. I just want to
be thorough, and explain the tech as best as possible.

Also, this is written for a world where "they" can't read your mind. Which,
unfortunately, is not this one, so the tech is moot. However, I write this
software with the hopes that one day we may implement access controls or
something, to restore the sovereignty of our own minds.

If you care about the dignity of the human race, please, dedicate yourself
toward this goal.

anyway here's the tech, for future use:

---

## How rmail encrypts messages

When two rmail daemons talk to each other, everything they send is scrambled
using a shared secret — the **token** you set up in your contacts file. If
someone is watching the network traffic between you and your contact, all they
see is random-looking bytes. They can't read the message, they can't change it
without being detected, and they can't pretend to be you.

The encryption algorithm is **AES-256-GCM**, a widely trusted standard used by
governments, banks, and most of the internet. The "256" means the key is 256
bits long — there are more possible keys than there are atoms in the observable
universe, so guessing it by brute force is not realistic.

### How the token becomes a key

AES-256-GCM needs a key that's exactly 256 bits (32 bytes) long. Your token is
a human-readable string like `apple-boat-racecar-spelled-backwards-is-racecar`.
To turn it into a fixed-length key, rmail runs it through **SHA-256** — a
one-way function that takes input of any length and produces exactly 32 bytes
of output. The same input always gives the same output, but you can't work
backwards from the output to the input: SHA-256 is specifically designed so
that the only way to find an input that produces a given output is to guess
inputs and hash them until one matches. With 2^256 possible outputs, that's
not going to happen in any practical amount of time.

So your token `apple-boat-racecar-spelled-backwards-is-racecar` becomes a 32-byte
key that looks like `a7 3f 91 c4 ...`. Both sides do this independently and arrive
at the same key, which is how they can encrypt and decrypt each other's messages.

### What gets sent over the wire

When rmail sends a message, it wraps it in an encrypted frame:

1. **A length header** (4 bytes) — tells the receiver how many bytes to expect.
2. **A random nonce** (12 bytes) — a unique number generated fresh for each
   message. This ensures that even if you send the exact same message twice,
   the encrypted output looks completely different each time.
3. **The scrambled message** — your actual message content, encrypted so it
   looks like random bytes.
4. **An authentication tag** (16 bytes) — a "seal" that proves the message
   hasn't been tampered with in transit. If even one bit is changed, the
   receiver detects it and rejects the message.

The wire frame does **not** currently include random padding — an observer
who watches an encrypted rmail exchange can read the length header and infer
the message's approximate plaintext size to byte precision. That's a genuine
gap for short, patterned messages ("ok", "see you at 3pm") where the length
itself is revealing. Two follow-ups track the fix:

- **#366** — add randomized padding inside the encrypted frame so message
  sizes fall into coarse buckets instead of leaking exactly.
- **#367** — a hook-based technique for sending the body as a fixed-chunk
  attachment when you want stronger size normalization than #366 provides.

See "Mitigating traffic analysis" below for what you can do today via hooks.

### How the receiver knows who sent it

rmail doesn't send your name in cleartext. Instead, the receiving daemon tries
to decrypt the message using each contact's key, one at a time.

The "seal" (authentication tag) is what tells it whether decryption worked.
Here's how that check works: when the sender encrypts, AES-GCM produces a
16-byte tag that's a one-way function of the key, the nonce, and the
ciphertext. The sender attaches it to the ciphertext and sends the whole
thing. The receiver recomputes the same function with its candidate key and
the received (nonce, ciphertext). If the recomputed tag equals the attached
one, the candidate key was right — the message decrypted correctly and came
from that contact. If they don't match, the key was wrong, and the receiver
tries the next contact. No tag exchange ever happens; both sides derive the
tag independently from the same inputs.

An attacker sending random data will fail every tag check and be silently
rejected.

This means an observer can't even tell *which* of your contacts is messaging
you — they just see encrypted blobs going to your IP address.

### What an attacker sees

Someone watching the network between two rmail daemons sees:

- **IP addresses and ports** — they can tell which two internet connections are
  talking. This is unavoidable with any internet protocol, though it can be
  mitigated by routing traffic through Tor or a multi-hop relay system (see
  [Mitigating traffic analysis](#mitigating-traffic-analysis) below).
- **When and how much** — they can tell when messages are exchanged and
  roughly how large each one is (the length header is in cleartext; the
  plaintext size is ciphertext-size minus 28 bytes of framing).
- **Random-looking bytes** — the actual content is indistinguishable from noise.

They **cannot**:
- Read the message content.
- Change a message without the receiver noticing.
- Send fake messages without knowing the token.

### What rmail does NOT protect against

- **Token compromise.** If someone gets your token, they can read and forge
  messages for that contact. Treat tokens like passwords. Each contact pair
  should have a unique token — if one leaks, only that relationship is
  compromised.

- **Traffic analysis.** An observer can see *that* you're communicating and
  *when*, even though they can't see *what*. See
  [Mitigating traffic analysis](#mitigating-traffic-analysis) below for
  hook-based countermeasures.

- **Endpoint compromise.** If someone gains access to the machine running
  rmail, they can read everything — messages on disk are plaintext, and the
  contacts file contains your tokens. Full-disk encryption (like LUKS on Linux)
  protects against a stolen device but not against someone who can log in while
  it's running. The [recommended hosting setup](#the-ideal-setup-for-the-truly-paranoid)
  below minimizes this risk.

- **IP address exposure.** Your public IP is stored in your contacts' contacts
  files so their daemons know where to reach you. rmail does not hide your IP.

---

## Token best practices

- **Use a long, memorable token.** Pick several random words separated by
  dashes, like `marble-telescope-cinnamon-wristwatch-piano`. Five or six
  words is plenty — it's easy to type on a phone and hard to guess. Avoid
  common phrases, song lyrics, or anything someone could find by searching
  your social media.

- **Exchange tokens in person** or over a channel you already trust. Don't
  send tokens over unencrypted email, SMS, or social media DMs.

- **Use a unique token per contact.** If you and Alice use one token, and you
  and Bob use a different one, then Alice leaking her token doesn't affect
  Bob.

- **Rotate tokens** if you're concerned one may have been compromised. Both
  sides need to update their contacts file at the same time.

- **Tokens live only in your contacts file.** rmail doesn't duplicate them
  into any state file, cache, or log. If you want to audit that for yourself,
  `grep` your token string across `~/mail/` — it should appear exactly once,
  in `contacts`.

---

## Mitigating traffic analysis

Even though message content is encrypted, an observer can learn things from
*when* you communicate and *how much* data you exchange. The following hook-
based techniques can make traffic analysis harder. None of them require
modifying rmail itself — they're just scripts you configure in your config file.

### Decoy traffic (on_send hook)

If you're worried about an observer noticing when you send real messages, you
can set up a cron job that periodically creates small outbox files addressed
to a cooperating contact. The contact's `on_receive` hook silently deletes
them. From the outside, there's a steady stream of traffic at all hours, and
real messages hide in the noise.

```sh
# crontab: send a decoy every 10 minutes
*/10 * * * * echo "to: alice\n\nping" > ~/mail/outbox/decoy-$(date +\%s)
```

On Alice's side, an `on_receive` hook checks for and discards decoy messages:

```sh
#!/bin/sh
# on_receive hook: $1=sender $2=subject $3=path
if grep -q "^ping$" "$3"; then rm "$3"; fi
```

**Decoys work best when they're bidirectional.** Real conversations have
traffic going both ways, so if only your side emits decoys the pattern
sticks out. Both ends should run the same cron/hook pair, so from the
outside there's a symmetric trickle of traffic in both directions.

### Message padding (on_send hook)

The hook below pads short bodies up to a fixed target length. **Note** that
it passes messages longer than the target through unchanged — for long
messages it's a no-op, and the plaintext size still leaks. For stronger
size obfuscation see #366 (in-frame padding, under development) and #367
(body-as-attachment padding for long messages).

```sh
#!/bin/sh
# on_send hook: $1=recipient $2=subject $3=body, stdout replaces body
body="$3"
target=4096
current=${#body}
if [ "$current" -lt "$target" ]; then
    padding=$(head -c $(( target - current )) /dev/urandom | base64)
    echo "${body}"
    echo "---padding---"
    echo "${padding}"
else
    echo "${body}"
fi
```

The receiver's `on_receive_raw` hook strips the padding:

```sh
#!/bin/sh
# on_receive_raw hook: $1=sender $2=subject $3=body, stdout replaces body
echo "$3" | sed '/^---padding---$/,$d'
```

### IP address hiding

If you don't want your contacts (or an observer) to know your real IP address,
you can route rmail traffic through **Tor** using `torsocks`:

```sh
# In your service file, wrap the rmail command:
ExecStart=torsocks lua /path/to/rmail.lua /path/to/mailbox
```

This hides your IP from the contacts you communicate with (they see a Tor exit
node instead). It adds latency but is effective. Note that your contacts'
IP addresses are still visible to you in your contacts file.

A dedicated Tor-over-rmail setup guide is worth having as its own document;
for now the one-line `torsocks` wrap above is the quick answer if you already
know Tor.

For a more advanced approach, multiple rmail instances could form a relay chain
where messages hop through intermediaries before reaching the final
destination — similar to how Tor works, but using rmail's own hook system. This
is an area for future development.

---

## Recommended secure hosting setup

rmail encrypts messages while they travel over the internet, but on your
computer they're stored as regular text files. If someone breaks into the
machine running rmail, they can read everything. The setup below makes that
as difficult as possible.

### The ideal setup for the truly paranoid:

The most secure way to interact with the internet is to throw your devices into a lake.

However, that kind of approach can often feel lonely and isolating. And besides, sometimes
you need to coordinate birthday parties and exchange notes about Dungeons and Dragons.

This is why I made rmail. The most secure way to run rmail is on a **dedicated device**
that does nothing else, isolated on its own network:

```
ISP modem
    |
primary router (your home network: phones, laptops, IoT, etc.)
    |
second router (rmail network: one device, one open port)
    |
Raspberry Pi running rmail
```

Note, I don't even do this. It's overkill for me because I'm not very paranoid.
Well, I'm the kind of paranoid that's afraid of cosmic threats and pixies, not
government snoops or teenage hackers.

**How does traffic reach the Pi through two routers?**

Your contacts put the public IP and port of your *outer* (primary) router in
their contacts file — same as a single-router setup. The outer router has a
port forwarding rule that sends traffic on that port to the inner (second)
router's WAN IP address. The inner router has its own rule that forwards it
to the Pi's LAN IP. It's just two hops of port forwarding. Your contacts
don't know or care that there are two routers — they just see one IP and one
port.

**Why a second router?**

Your home network is full of devices you don't fully control — smart TVs,
IoT gadgets, guest phones. If any of them are compromised (by malware, a
firmware vulnerability, or a nosy app), the attacker is on your local network.
Putting rmail behind a second router means those devices simply cannot reach
it. The second router acts as a wall: only the one rmail port gets through.

**What if an attacker still gets onto the Pi?**

If an attacker somehow exploits rmail itself through the one open port, they
land on a machine with nothing else on it — no browser history, no SSH keys,
no personal files. The second router limits what they can reach from there.

Be honest about what they *do* get, though: control of a trusted rmail
mailbox. That's not nothing. With access to a running rmail instance an
attacker can:

- **Impersonate you to every contact.** They have your tokens (in the
  contacts file on the Pi) and can send messages as you. Social engineering
  from a trusted sender lands a lot harder than from a stranger.
- **Execute arbitrary code** via any hooks you've configured, inside the
  sandbox of the Pi.
- **Read every incoming message** for as long as they keep their foothold.
- **Silently monitor** your conversations — they don't have to *do* anything
  visible to be useful.

The isolation strategy — dedicated device, second router, read-only root
(see below) — is about making the compromise *harder to achieve* and
*easier to detect*, not about making it harmless. Once an attacker owns a
trusted endpoint, the encryption on the wire doesn't save you.

**Why a Raspberry Pi?**

- Cheap (~$35-60 depending on model), low power (~5W), silent, small.
- Runs headless — no monitor, no keyboard, easy to overlook if running in a closet.
- Plenty of power for rmail (which is single-threaded Lua processing text files).

**Why Alpine Linux?**

- **Minimal attack surface.** A base Alpine install is about 130 MB with
  around 20 running processes. A typical desktop Linux distribution runs
  hundreds of processes and includes gigabytes of software you don't need.
  Every extra program is a potential vulnerability. Alpine includes almost
  nothing by default — you add only what you need.
- **Simpler foundations.** Alpine uses musl (a small, clean C library) and
  BusyBox (a single binary that replaces dozens of common Unix tools). These
  are smaller and simpler than their counterparts on most Linux distributions
  (glibc and GNU coreutils), which means less code, less complexity, and
  historically fewer security bugs.
- **No unnecessary services.** No desktop environment, no audio system, no
  device discovery protocols broadcasting your presence on the network. Just
  the services you explicitly install.
- **Read-only root support.** Alpine can run with a read-only root filesystem,
  which is key to the integrity verification strategy described below.

### Setup outline

1. Disable UPnP and NAT-PMP on both routers before connecting anything.
2. Flash Alpine Linux to an SD card (or USB for Pi 4/5). Enable full-disk
   encryption during setup (LUKS) so a stolen SD card doesn't leak your
   messages. We plan to offer pre-built images in the future.
3. Connect the Pi to the second router's LAN port.
4. Clone rmail and run `scripts/install.sh` — it compiles all dependencies
   from source.
5. Forward your rmail port on **both** routers:
   - Primary router: external port -> second router's WAN IP
   - Second router: external port -> Pi's LAN IP
6. Verify with `scripts/validate-router-settings.sh`.
7. Consider setting up the read-only root filesystem (see below).

### Verifying remote integrity

If your rmail host is a headless Pi in a closet, how do you know it hasn't
been tampered with? This is harder than it looks: **a compromised machine can
lie about its own state**, so any check that runs on the suspect machine
itself can be subverted by an attacker who's already there. `ssh pi
'sha256sum rmail.lua'` catches a lazy attacker who didn't bother to replace
`sha256sum`; it doesn't catch anyone competent. Protocol-level probes ("send
a known input, check the response") catch accidental breakage, not
deliberate tampering — a serious attacker preserves the protocol exactly.

Two approaches that actually work:

**Read-only root filesystem (prevention, strongest).** Alpine Linux supports
running with a read-only root partition. The rmail binary, libraries, and
config live on the read-only partition. Only the mail directory (inbox,
outbox, attachments, contacts file) is on a separate writable partition. If
an attacker exploits rmail, they can read and write messages, but they
*cannot modify the rmail code itself or install additional software* — the
filesystem won't allow it. A reboot restores the original state completely.
This is the same approach used by Android and ChromeOS to prevent persistent
compromise of the operating system.

To set this up on Alpine, look into `lbu` (Alpine Local Backup) and the
diskless/data modes described in the Alpine wiki.

**External verification via a second rmail mailbox (detection).** The only
trustworthy verifier is a separate device you control. If you keep a
"monitor" rmail mailbox on your laptop or phone, you can have the Pi *send
it a periodic heartbeat* — a known-format message that only the real rmail
code would produce. Missing heartbeats, or heartbeats in the wrong format,
reach your laptop over rmail's own encrypted channel, where an attacker on
the Pi can't suppress them without cutting off the Pi from the network
(which is a visible symptom in itself).

This flips the trust question: instead of asking the Pi "are you honest?"
(which it might lie about), you're *watching whether the Pi is still
talking to you normally.* If it isn't, something's wrong.

A simple first version: a cron job on the Pi that writes a daily
timestamped outbox file to a "monitor" contact. If your monitor device goes
48 hours without a message, alert. This catches an attacker who's stopped
rmail from running; it doesn't catch an attacker who leaves rmail running
while siphoning data, but neither does anything else short of hardware
tamper-evidence.

### Simpler alternatives

Not everyone needs a dedicated device. Here are other options, roughly
ordered from most to least secure:

1. **Dedicated VM or container on an existing server.** A VM is like a
   second computer running inside your real one; a container is a lighter
   version of the same idea. Both give rmail its own isolated space —
   if something gets into the sandbox, it's stuck in there and can't
   easily reach the rest of your machine. Tools: LXC or Docker
   (containers), VirtualBox or QEMU (VMs), or systemd-nspawn on modern
   Linux. Easier than buying a Raspberry Pi, not as isolated as a
   separate physical device.

2. **Just run it on your desktop/laptop.** This is fine for most people.
   The main risk is that a browser exploit, malicious download, or
   compromised program could access your mail files or hook scripts. Use
   full-disk encryption so a stolen device doesn't leak your messages.

### What about renting a server?

A **VPS** (Virtual Private Server) is a computer you rent from a hosting
company. You get a stable public IP and avoid all the NAT/port-forwarding
hassle. But there are trade-offs:

- **The hosting company can read your disk.** Your messages are plaintext on
  their storage. You're trusting their employees, their security practices,
  and their response to law enforcement requests.
- **You don't control the hardware.** Your virtual machine shares a physical
  server with other customers. While attacks between VMs are rare, they're
  not impossible.

A rented server is convenient and fine for everyday use. For serious privacy,
keep the hardware in your home where you control physical access. Honestly,
a VPS is probably going to be even more complicated than setting it up at home,
since you'll need to deal with remote administration on top of everything else.

On one hand, external hosting in a datacenter behind locked doors with cameras
and security guards works pretty well. On the other hand, sometimes a technician
is working on the computer next to yours and they accidentally plug a flash drive
with malware into the wrong system.

What, are you never going to leave your house? "They don't even know where to
find it" omg did you hide it in the walls or something you goofball. Listen,
there's no perfect solution. Just try and be mindful and live a good life, and
nothing else really matters. Make the world a better place, leave things nicer
than you found them, and always be kind to children and animals. "that little
bastard took my wallet" heh what a rascal. I didn't know squirrels could do that.

---

## Summary

| Layer | Protection | Limitation |
|-------|-----------|------------|
| Wire encryption | AES-256-GCM, random nonces | Length header in cleartext leaks approximate plaintext size (see #366) |
| Authentication | Trial decryption with shared token | Only proves "knows the token" |
| Metadata | No unencrypted headers | IP addresses and timing visible |
| At rest | None (plaintext on disk) | Use full-disk encryption on the host |
| Host isolation | Up to you | Dedicated device + separate network is ideal |
| Integrity | Read-only root + external heartbeat monitoring | Internal self-checks can be subverted |
