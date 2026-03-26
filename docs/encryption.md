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
To turn it into a fixed-length key, rmail runs it through **SHA-256** — a one-way
function that takes input of any length and produces exactly 32 bytes of output.
The same input always gives the same output, but you can't work backwards from
the output to figure out the input. There just isn't enough information in the
256 bits (zeroes and ones) to figure out the original text.

So your token `apple-boat-racecar-spelled-backwards-is-racecar` becomes a 32-byte
key that looks like `a7 3f 91 c4 ...`. Both sides do this independently and arrive
at the same key, which is how they can encrypt and decrypt each other's messages.

### What gets sent over the wire

When rmail sends a message, it wraps it in an encrypted package:

1. **A length header** (4 bytes) — tells the receiver how many bytes to expect.
2. **A random nonce** (12 bytes) — a unique number generated fresh for each
   message. This ensures that even if you send the exact same message twice,
   the encrypted output looks completely different each time.
3. **The scrambled message** — your actual message content, encrypted so it
   looks like random bytes.
4. **Random padding** — a random amount of extra garbage data, appended after
   the real message but before the seal. The receiver knows the real message
   length from the internal headers and ignores the padding. This makes it
   harder for an observer to guess what you're sending based on message size.
5. **An authentication tag** (16 bytes) — a "seal" that proves the message
   hasn't been tampered with in transit. If even one bit is changed, the
   receiver detects it and rejects the message.

The padding means a short message like "ok" and a longer message like "see you
at 3pm" could look the same size on the wire. It's not perfect protection
against traffic analysis (an observer can still see timing and rough volume),
but it removes the easiest signal.

### How the receiver knows who sent it

rmail doesn't send your name in cleartext. Instead, the receiving daemon tries
to decrypt the message using each contact's key, one at a time. The "seal"
(authentication tag) is what tells it whether decryption worked — if the seal
checks out, the message is genuine and came from that contact. If the seal
doesn't match, the key was wrong, and it tries the next contact. An attacker
sending random data will fail every seal check and be silently rejected.

-- okay, but how do we know which seal is the correct seal? "if the seal doesn't match" doesn't
   match what? how do we exchange these seals, if we do so at all?

This means an observer can't even tell *which* of your contacts is messaging
you — they just see encrypted blobs going to your IP address.

### What an attacker sees

Someone watching the network between two rmail daemons sees:

- **IP addresses and ports** — they can tell which two internet connections are
  talking. This is unavoidable with any internet protocol, though it can be
  mitigated by routing traffic through Tor or a multi-hop relay system (see
  [Mitigating traffic analysis](#mitigating-traffic-analysis) below).
- **When and how much** — they can tell when messages are exchanged and roughly
  how large they are (though random padding makes size estimates less precise).
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

-- ideally, they'd be sending similar traffic elsewhere, including back to you.

### Message padding (on_send hook)

The random wire padding helps, but if you want even more size obfuscation,
an `on_send` hook can pad every message body to a fixed length:

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

-- how does this work if the message is longer than the amount we're padding to?
   should we recommend writing the messages separately and attach:ing them instead,
   with large padding amounts added to normalize their size? We could even do it
   with text manipulation in the hook, so an outgoing message is replaced with
   the same message included as an attachment with a: "

   -------------------------------------------------------------------------------
       end of encrypted message. what follows is random data with no meaning.
   -------------------------------------------------------------------------------
   " style message, not in the message body, but rather in the attached file, which
   is then zipped and sent as fixed-size chunks.

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

-- should we add a simple setup guide for tor? idk, I think it's pretty complex.
   maybe we could offer a separate document for it?

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

Even if an attacker somehow exploits rmail itself through that port, they land
on a machine with nothing else on it — no browser history, no SSH keys, no
personal files. And with only one port open on the second router, it's very
difficult for them to do anything useful with their foothold. They'd have to
tunnel all their activity through rmail's own encrypted protocol on that single
port, which means significantly modifying the rmail code — something an
integrity check could catch (see below). And besides, even if they did, they would
have nothing to gain

-- (except the capability to use your rmail mailbox as they please)
-- (which entails... what? what kind of damage could an attacker cause with access to
    a trusted mailbox that can send arbitrary data and execute arbitrary code on its
    own device?)

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

-- "Alpine uses a small, clean, efficient C compiler that has been audited for security.
    All of the Unix tools are stripped down to their essentials, to be focused and clear.
    Less code, more streamlined dataflow. The system is optimized like a well oiled machine."

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
been tampered with? A compromised machine can lie about its own state, so
simply asking it to checksum itself isn't reliable. Here are approaches that
actually work, ordered from most to least robust:

-- and yet later on one of the suggestions we have is to ask the system to report it's own checksum

**Read-only root filesystem (strongest)**

Alpine Linux supports running with a read-only root partition. The rmail
binary, libraries, and config live on the read-only partition. Only the mail
directory (inbox, outbox, attachments, contacts file) is on a separate 
writable partition.

If an attacker exploits rmail, they can read and write messages, but they
*cannot modify the rmail code itself or install additional software* — the
filesystem won't allow it. A reboot restores the original state completely.
This is the same approach used by Android and ChromeOS to prevent persistent
compromise of the operating system.

To set this up on Alpine, look into `lbu` (Alpine Local Backup) and the
diskless/data modes described in the Alpine wiki.

**External monitoring (practical)**

A second device you trust (your phone, your laptop) can periodically check
the Pi's integrity from the outside:

- **SSH checksum script:** Connect to the Pi over SSH, compute checksums of
  the rmail binary and libraries, compare against your local copy of the repo.
  Run this on a cron job and have it send an alert to a different rmail mailbox
  (or any notification channel) if checksums don't match.

-- could we have the verification program running on the read-only partition?
   Is it read-only just to users, but someone with sudo access could modify it?
   If the verification program could return the "valid/invalid" result to a
   separate mailbox running on your regular computer... which is more likely to
   be compromised, isn't it? okay nevermind. Though we could set it up to do
   other notification channels too. Hmmm. Not sure what to do here.

- **Protocol-level probe:** Send a known message through rmail's encrypted
  protocol and verify the response matches what the real code would produce.
  If the code has been modified, behavior would differ. This can be tested
  from outside without trusting the remote machine.

-- if rmail is modified, then the behavior wouldn't necessarily differ. In fact, a successful
   modification would entail returning the exact correct behavior.

```sh
#!/bin/sh
# Example: run on your laptop via cron, alerts via a second rmail mailbox
EXPECTED="abc123def456..."  # known checksums
ACTUAL=$(ssh pi@rmail-host 'sha256sum /path/to/rmail/rmail.lua /path/to/rmail/libs/*.so')
if [ "$ACTUAL" != "$EXPECTED" ]; then
    echo "to: myphone\n\nINTEGRITY ALERT: rmail checksums changed on $(date)" \
        > ~/mail-monitor/outbox/integrity-alert
fi
```

**Simple spot checks (baseline)**

If you don't want to automate anything, just SSH into the Pi occasionally and
eyeball `sha256sum` output against your local repo. Not as rigorous, but
catches crude modifications.

-- this won't work. we shouldn't recommend this. nobody will use this approach, and those that do
   are not going to do it correctly.

### Simpler alternatives

Not everyone needs a dedicated device. Here are other options, roughly ordered
from most to least secure:

1. **Dedicated VM or container** on an existing server. Not as isolated as
   separate hardware, but still limits blast radius.

-- can you explain this in more plain language?

2. **A separate user account** on your existing machine, with restrictive file
   permissions (`chmod 700 ~/mail`). Protects against casual snooping but not
   root compromise or a malicious program running as your user.

-- is this something we should recommend? I don't think so, because people would need
   sudo access just to write messages / read them.

3. **Just run it on your desktop/laptop.** This is fine for most people. The
   main risk is that a browser exploit, malicious download, or compromised
   program could access your mail files or hook scripts. Use full-disk
   encryption so a stolen device doesn't leak your messages.

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
| Wire encryption | AES-256-GCM, random nonces, random padding | Same key until token is rotated |
| Authentication | Trial decryption with shared token | Only proves "knows the token" |
| Metadata | No unencrypted headers | IP addresses and timing visible |
| At rest | None (plaintext on disk) | Use full-disk encryption on the host |
| Host isolation | Up to you | Dedicated device + separate network is ideal |
| Integrity | Read-only root + external monitoring | Requires additional setup |
