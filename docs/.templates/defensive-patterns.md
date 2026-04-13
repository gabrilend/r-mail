# Defensive patterns and traffic-analysis resistance

This is a guide to hook-based idioms that harden your rmail setup
beyond what the daemon does on its own.  Everything here is
opt-in: a handful of scripts you configure against the hook events
listed in [docs/scripting-tutorial.md](scripting-tutorial.md).  None
of these require changes to rmail itself.

The patterns split into two groups:

- **Traffic analysis** — hiding the *shape* of your communication
  from a network observer.  rmail encrypts message bodies, but
  timing, size, and who-talks-to-who are visible on the wire.
- **Defensive programming** — rate limits, content filtering, audit
  trails.  Bigger aperture: these protect you from things your
  contacts or their senders might do, not from outside observers.

---

## What rmail already gives you

- AES-256-GCM for message content and attachments.  The bytes are
  indistinguishable from random to an observer who doesn't have the
  token.
- Integrity: the GCM tag detects tampering in-flight.
- Sender authentication: the observer can't know *which* of your
  contacts an incoming packet came from (every contact has a
  different per-pair token), but they can see it arrived from the
  network.

That's the content-confidentiality layer.  Everything below is about
the metadata the crypto can't hide.

---

## What leaks by default

- **Timing.** Every outbox change triggers a sync cycle (and an
  `inotify` wake-up) that turns into a TCP connection within
  seconds.  An observer watching your uplink sees "Alice sent
  something" with clocked precision.
- **Size.** The ciphertext length on the wire is the plaintext
  length plus a small fixed overhead (nonce + tag).  Big messages
  produce big packets.
- **Who-talks-to-who.** Each outbox file with `to: bob` becomes a
  TCP connection to Bob's IP on Bob's port.  That relationship is
  visible to anyone on the network path.
- **Connection count.** N outbox files to the same contact produce
  N separate TCP connections within the same sync cycle; three
  ops in, three ops out.
- **Relationship dynamics.** Burstiness, back-and-forth latency,
  and active hours all show through.

The techniques below each chip away at one or two of these.

---

## Cover traffic: a heartbeat to every contact

**The idea.** Send something every sync cycle regardless of whether
you have anything real to say.  An observer then sees a constant
stream of packets to each contact — real messages blend in with the
noise.  Without this, "Alice wrote something" and "Alice didn't"
are trivially distinguishable.

**How.** Use the [periodics pattern](scripting-tutorial.md#periodic-tasks-via-self-addressed-messages)
to re-write a heartbeat outbox file on a timer.  Each rewrite is
detected as a living-message update and delivered to the recipient.

```sh
#!/bin/sh
# on_update hook that maintains a heartbeat file per contact.
# Triggered by a self-addressed heartbeat message that ticks every
# cycle; see the periodics pattern for the self-message setup.
#
# Args: $1=sender (self), $2=inbox path, $3=new body (stdout replaces it)

# Periodic self-message only — pass other updates through.
case "$2" in
    */heartbeat-tick) ;;
    *) printf '%s' "$3"; exit 0 ;;
esac

# Emit real heartbeats to every contact.  Random-looking body
# keeps ciphertext diverse; padding (below) normalises size.
for contact in $(sed -n 's/^\([^.][^.]*\)\.ip.*/\1/p' ~/mail/contacts | sort -u); do
    [ "$contact" = "$(whoami)" ] && continue
    outbox="$HOME/mail/outbox/heartbeat-to-$contact"
    cat <<EOF > "$outbox"
to: $contact
subject: heartbeat
--- heartbeat $(date +%s) $(head -c 16 /dev/urandom | base64) ---
EOF
done

printf '%s' "$3"  # pass the tick message through
```

On the receiving side, an `on_update` hook silently absorbs
heartbeats so they don't clutter the inbox:

```sh
#!/bin/sh
# on_update hook on the receiver
if printf '%s' "$3" | head -1 | grep -q '^--- heartbeat'; then
    rm "$2"  # delete the inbox copy immediately
    exit 0   # stdout empty → rmail keeps original (about to be deleted)
fi
printf '%s' "$3"
```

**Pairing up.** Cover traffic works best when *both* sides run it,
so the observer sees traffic in each direction on the same
schedule.  Agree with your contact before enabling.

**Cost.** One packet per contact per sync cycle.  At the default
sync interval (minutes), that's negligible bandwidth.

**What it doesn't hide.** The *relationship* — that you have Bob
as a contact at all.  An observer still sees your daemon making
regular connections to Bob's IP.  To hide that, you need a relay
(Tor, or an rmail-level relay chain — not implemented yet).

---

## Size padding

The ciphertext length mirrors the plaintext length.  A one-line
"ok" reply (20 bytes on the wire) and a long draft (30 KB) look
obviously different to any observer.

### Why fixed-size padding fails

The obvious fix — pad every body to 4096 bytes — breaks the moment
a real message exceeds 4096 bytes.  You can't pad a 6000-byte
message to 4000.

### Bucketed sizes

Pick a set of buckets that covers typical message sizes:

```
  1 KB, 4 KB, 16 KB, 64 KB, 128 KB
```

Pad every outgoing body to the smallest bucket that fits.  Messages
still cluster into several discrete wire sizes, but each bucket has
many real bodies inside it and an observer can't narrow further.

```sh
#!/bin/sh
# on_send hook: pad body to the next bucket size.
# Args: $1=recipient, $2=subject, $3=body. stdout replaces body.

body="$3"
len=${#body}

# Buckets in bytes.  Include 128 KB (rmail's body cap) as the
# last one; anything that would exceed it should use attachments.
for bucket in 1024 4096 16384 65536 131072; do
    if [ "$len" -le "$bucket" ]; then break; fi
done

padding_len=$(( bucket - len - 16 ))   # -16 for the padding marker
if [ "$padding_len" -le 0 ]; then
    printf '%s' "$body"  # already at or over the top bucket
else
    padding=$(head -c "$padding_len" /dev/urandom | base64 | tr -d '\n' | cut -c1-"$padding_len")
    printf '%s\n--- padding ---\n%s' "$body" "$padding"
fi
```

On the receiver, an `on_receive_raw` hook strips everything after
the marker:

```sh
#!/bin/sh
# on_receive_raw hook: trim padding before saving to inbox.
printf '%s' "$3" | sed '/^--- padding ---$/,$d'
```

### Messages larger than the top bucket

rmail caps bodies at 128 KB to keep `$3` inside the shell's
argument-length limit.  If a real message is bigger, attach it
instead — the zip-chunked attachment pipeline handles large content
natively and uses its own chunking, so the observer sees many
fixed-size chunks rather than one giant packet.  The on_send hook
could automate this: detect oversize body, write it to a temp
file, rewrite the outbox to have an `attach:` line and a short
stub body, then delete the temp file after the attachment is
queued.  (Tracked as future work in issue #349 for the daemon-
level version of this.)

### Coordinate with your heartbeat

If your heartbeat fits in the smallest bucket (1 KB) and real
messages fit in larger buckets, an observer can distinguish
heartbeat from real by size alone.  Pad heartbeats to the median
bucket your real messages use — or pad every message to the same
bucket if bandwidth allows.

---

## Timing jitter

Predictable sync intervals make it easy for an observer to align
Alice's outbound traffic with Bob's inbound and prove "Alice talked
to Bob."  Jitter the send time a little.

```sh
#!/bin/sh
# on_send hook: sleep a random 0..30 seconds before the daemon
# actually transmits.  Synchronous hook, so the daemon waits.
sleep "$((RANDOM % 30))"
printf '%s' "$3"  # body unchanged
```

**Limits.** Adding 30 seconds of latency to every outgoing packet
makes real-time conversations awkward.  Tune for your workflow.
For high-latency correspondence (daily mail, not chat) a jitter of
minutes is fine and helps correlate less.

**Better still:** a batching layer that queues real messages and
flushes them all on a fixed schedule.  That's a bigger structural
change than a hook, though, and isn't implemented today.

---

## Decoy recipients

Add an extra `to: <decoy-contact>` line to every outbox file.  The
decoy contact is a real rmail peer (running somewhere you control,
or a co-operative friend) whose `on_receive` hook silently
discards everything it receives.

```
to: bob
to: decoy
subject: weekly update
...
```

An observer sees your daemon connect to two endpoints instead of
one and can't tell which was the real recipient.  Extend to N
decoys for stronger mixing — at some point the observer only
learns "Alice talks to this set of N IPs" rather than "Alice
talks to Bob specifically."

**Caveat.** This burns bandwidth linearly in decoy count.  Two or
three decoys is usually enough to dilute the signal without being
costly.

---

## IP address hiding via Tor

If you don't want your contacts (or an observer) to see your real
IP, run rmail through `torsocks`:

```
# In your service file:
ExecStart=torsocks lua /path/to/rmail.lua /path/to/mailbox
```

The hop count adds hundreds of milliseconds, sometimes more.  Your
contacts see a Tor exit node as your address, so if you use this,
also use a DNS hostname (#311) in your contacts file on the other
side — exit-node IPs change.

**What this doesn't hide.** Your *contacts'* IPs.  They're in your
own contacts file verbatim.  If you need to hide those too (you're
running a hosted service and worried about someone seizing your
machine), encrypt your contacts file at rest — the mechanics are
out of scope for this doc but `age` or `gpg` pipelines work.

**A proper rmail-level relay chain** — messages hop through
intermediate rmail daemons to reach the final recipient, each hop
re-encrypted — would hide the whole relationship graph from
observers at any single point.  This is a substantial design and
is not implemented.

---

## Other defensive hook patterns

Non-traffic-analysis defenses worth knowing about.

### Rate limiting per sender

Drop messages from a sender that arrive faster than some threshold.
Catches accidental loops and intentional flooding.

```sh
#!/bin/sh
# on_receive_raw hook: cap one message per sender per 10 seconds.
# Returns empty stdout on drop — rmail keeps the original body,
# so "drop" isn't quite right; use on_receive to actually delete.

counter=/tmp/rmail-ratelimit-$1
now=$(date +%s)
last=$(cat "$counter" 2>/dev/null || echo 0)
if [ $((now - last)) -lt 10 ]; then
    # Too fast — log and keep body unchanged (drop via on_receive)
    echo "$(date) rate limit: $1" >> ~/mail/.ratelimit.log
fi
echo "$now" > "$counter"
printf '%s' "$3"
```

### Attachment type filtering

Refuse attachments by extension or content-type.  Pairs well with
the consent prompt — don't accept the transfer in the first place.

```sh
#!/bin/sh
# Standalone: reject executables by extension in the consent prompt.
# Wire this into the attachment-consent helper flow — see
# helpers/raccept.sh and helpers/rdeny.sh.
filename="$2"
case "$filename" in
    *.exe|*.bat|*.scr|*.cmd|*.ps1)
        helpers/rdeny.sh "$3"  # $3 is the consent file path
        ;;
    *)
        helpers/raccept.sh "$3"
        ;;
esac
```

### Audit log

Append every event to a tamper-evident log (hash chain).  Useful
for forensic review after a suspected compromise.

```sh
#!/bin/sh
# on_receive hook: append a hash-chained audit entry.
log=~/mail/.audit-log
prev=$(tail -1 "$log" 2>/dev/null | awk '{print $NF}')
entry="$(date -u +%FT%TZ) receive from=$1 subject=$2 prev=${prev:-genesis}"
hash=$(printf '%s' "$entry" | sha256sum | cut -c1-16)
echo "$entry hash=$hash" >> "$log"
```

Each entry's hash includes the previous entry's hash — any
edit breaks the chain from that point on.  Combine with regular
off-host backups of the log (to a machine the attacker can't
reach) to make tampering detectable.

### Auto-consent from trusted contacts

Skip the consent prompt for attachments from specific contacts.
See `scripts/hooks/on_receive.sh` and the auto-consent example in
[helper-scripts.md](helper-scripts.md#raccept-sh--accept-a-package-request).

### Encrypted backup on receipt

Copy inbox files into a local gpg-encrypted archive so a later
local-disk compromise doesn't expose plaintext history.

```sh
#!/bin/sh
# on_receive hook: backup to encrypted archive.
# $1=sender, $2=subject, $3=inbox file path.
archive=~/mail/.archive.tar.gz.gpg
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cp "$3" "$tmp/$1--$(date +%s)--$2"
tar -cf - -C "$tmp" . | gpg --batch --yes --passphrase-file ~/.rmail-archive-pass \
    --symmetric --cipher-algo AES256 --output "$archive.new"
mv "$archive.new" "$archive"
```

Pair with a policy of periodically wiping inbox contents once they
exist in the archive (manual `rm`, or a cron job targeting files
older than some threshold).

---

## Combining patterns

Heartbeat + bucketed size padding + 30s jitter + two decoy contacts
approximates a constant-rate traffic pattern where every outgoing
packet looks roughly identical to every other one from outside.
An observer sees your daemon sending ~one packet per contact per
N minutes at bucket-rounded sizes with jittered timing.

Real messages hide inside this pattern.  The observer still knows
you have rmail and who your contacts are (IPs in packet headers
are clear), but not when you wrote anything or what you said.

---

## What none of this fixes

- **The contact relationship itself.**  Your contacts file is
  plaintext and lists IPs; every packet you send declares "I know
  this IP."  Cover traffic hides timing but not existence.
- **Compromise at either endpoint.**  If Alice's or Bob's machine
  is taken over, everything that was decrypted there is readable.
- **Compelled disclosure of tokens.**  If an adversary gets your
  token by any means — subpoena, coercion, shoulder-surfing — they
  can impersonate you until you rotate it.
- **Global passive adversary.**  A watcher seeing all traffic on
  the internet (rare in practice, extant at some nation-state
  scales) can correlate timing across hops even through Tor or
  relay chains.  rmail's countermeasures assume a *local* network
  observer, not a global one.

---

## Further reading

- [encryption.md](encryption.md) — cryptographic primitives and
  threat model
- [scripting-tutorial.md](scripting-tutorial.md) — hook interface,
  worked examples, periodics pattern
- [helper-scripts.md](helper-scripts.md) — pre-built helpers you
  can call from defensive hooks
