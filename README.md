# r-mail

File-based messaging. Messages are plain text files on disk — write them with whatever editor you like, and a background daemon syncs everything over HTTP.

## How it works

Each person runs an `rmail` daemon. It watches two directories:

```
~/mail/
  inbox/         # received messages appear here
  outbox/        # write files here to send
  attachments/   # received attachments
  contacts       # address book and shared secrets
  .state/        # sync tracking (managed by daemon)
```

To send a message, create a file in `outbox/`. The filename becomes the subject:

```
to: alice

Hey, want to grab coffee tomorrow?
```

You can send to multiple people — one `to:` per line:

```
to: alice
to: bob
to: charlie

Meeting at 3pm tomorrow.
```

Each recipient gets their own independent copy. They only see the message body, not who else received it.

The daemon picks it up and delivers it to each recipient's inbox as a plain text file.

Deleting works both ways:

- **Recipient deletes** from inbox — the sender's copy has that `to:` line removed.
- **Sender deletes** the outbox file — all recipients are notified to automatically remove it.
- **Sender removes a `to:` line** — that specific recipient's copy is deleted, others are unaffected.

When all `to:` lines are gone (everyone deleted or was removed), the outbox file is cleaned up automatically.

There is no history for deleted messages. If you'd like such functionality, check out the [scripting hooks](docs/scripting-tutorial.md), which enable whatever behavior you'd like, including backing up old messages.

### Attachments

Add `attach:` lines to send files. Each recipient receives all `attach:` lines that appear below their `to:` line:

```
to: alice
to: bob
attach: /path/to/photo.jpg

Here's the photo from yesterday.
```

In this example, only alice receives the photo:

```
to: alice
attach: /path/to/photo.jpg
to: bob

Here's the photo from yesterday. Sorry bob, you don't get to see it.
```

Before any data is transferred, the recipient gets a consent request in their inbox:

```
alice wants to send you an attachment.

  File:          photo.jpg
  Expected size: 3.2 MB
  Available:     47.3 GB on this drive
  After:         47.3 GB remaining (71% of capacity)

Delete one line and leave your choice behind for the system to read:

accept
deny
```

Leave either `accept` or `deny` to make your choice. Once accepted, the file is transferred in compressed chunks and appears in `~/mail/attachments/` when complete. Interrupted transfers resume automatically on the next sync cycle.

For full details on the attachment workflow, per-recipient targeting, configuration, and resumption behaviour, see [docs/attachments.md](docs/attachments.md).

## Dependencies

- **Lua** 5.1+ (5.4 recommended)
- **LuaSocket** — TCP networking for Lua
- **OpenSSL** — AES-256-GCM encryption
- **zip / unzip** — file compression for attachment transfer

Run `./scripts/install.sh` to compile all dependencies from source into the r-mail directory.

## Installation

```sh
git clone https://github.com/gabrilend/r-mail.git
cd r-mail
./scripts/install.sh
```

`install.sh` compiles all dependencies from source into `libs/`, and generates your config and contacts files. It will ask whether to compile Lua locally or use your system version.

To run manually:

```sh
./run-rmail.sh
```

To run rmail automatically on boot, see [docs/service.md](docs/service.md).

## Configuration

### Config file

`~/.config/rmail/config` controls your identity and settings:

```
name = yourname
port = 8025
mail = ~/mail
```

The generated config file contains a comment above every available key explaining what it does.

### Contacts file

`~/mail/contacts` is a line-oriented file listing the people you communicate with. Lines starting with `//` or `#` are comments. Text must be within "quotes" but numbers are okay on their own.

```
alice.ip    = 203.0.113.1
alice.port  = 8025
alice.token = "some-shared-secret"
```

| Field   | Meaning                                                 |
|---------|---------------------------------------------------------|
| `ip`    | their router's public IP address                        |
| `port`  | the mailbox their router uses to talk to their computer |
| `token` | shared secret password (same on both sides)             |

Both sides must have the same token for a given contact pair. Pick something long and random, but pick something different for each contact. I like to do words separated by dashes, like "apple-box-racecar-spelled-backwards-is-racecar"

You can add arbitrary fields (e.g. `alice.phone = "555-1234"`) — rmail stores them but ignores them. Hook scripts can read them directly. See [docs/scripting-tutorial.md](docs/scripting-tutorial.md).

## Ports

Each person runs their daemon on a single port. Unless provided, the install script generates a random port in the 50000–65000 range. That one port handles both sending and receiving — all your contacts deliver to the same port.

The only thing your contacts need from you is your **router's public IP** and the **port number** you'd like your router to "route" the messages to. These two numbers are what goes in their contacts file.

Local/LAN IP addresses are never shared with contacts, but you will need your local IP when setting up port forwarding on your router — the router needs to know which machine on the Local Area Network (LAN) to send traffic to. If multiple people are behind the same router, each person needs a unique port:

| Person | Router forward config      | What contacts put in their file |
|--------|----------------------------|---------------------------------|
| Alice  | port 8025 → 192.168.1.10   | 203.0.113.1, port 8025          |
| Bob    | port 8026 → 192.168.1.20   | 203.0.113.1, port 8026          |

If everyone is on separate networks, they can all use the same port number. Only your router cares about the port number. It's like filling out a paper slip and registering a name to your specific mailbox with your mailman when you first move in to a new place, but for a computer instead of a house.

Not sure why any of this is necessary? See [docs/ports-explained.md](docs/ports-explained.md) for a plain-language walkthrough.

To find your **local IP** (for router port forwarding):

```
ip addr show | grep 'inet '
```

To find your router's **public IP** (what your contacts put in their file):

```sh
curl -s ifconfig.me           && echo "" || true
curl -s icanhazip.com         && echo "" || true
curl -s api.ipify.org         && echo "" || true
curl -s checkip.amazonaws.com && echo "" || true
```

All four should print the same IP. If they agree, that's your router's public IP.

### Opening the firewall

Your OS firewall also needs to allow traffic on your port. To check which firewall you're running:

```
which ufw && echo "you have ufw"      || \
which nft && echo "you have nftables" || \
which iptables && echo "you have iptables"
```

Then open the port in your computer's firewall:

```sh
# Be sure to change 8025 in these examples to whatever port you'd like to use.

# ufw
sudo ufw allow 8025/tcp

# nftables
tcp dport 8025 accept

# iptables
sudo iptables -A INPUT -p tcp --dport 8025 -j ACCEPT
```

Note that your router AND your OS must have an open port in their firewalls. There are two firewalls.

To verify that the port is open, run this from a computer on the network:

```
ss -tlnp | grep 8025
```

To verify the daemon is reachable:

```
curl http://localhost:8025/
```

This returns `{"ok":true,"name":"yourname"}` if everything is working. You can also test from another machine using the public IP of your router instead of `localhost` to confirm port forwarding is set up correctly.

Once the firewall is open, run the connectivity check to verify your router settings:

```sh
./scripts/validate-router-settings.sh
```

This checks whether your router supports hairpin NAT (needed for contacts on the same router to talk to each other) and whether UPnP is enabled in the router settings (a security concern). It reads your port from the config file automatically.

### Automatic port forwarding (UPnP / NAT-PMP)

> **WARNING: Automatic port forwarding uses UPnP or NAT-PMP, which are
> fundamentally insecure protocols. Any device on your local network can open
> any port on your router without authentication. Malware commonly exploits
> this. Manual port forwarding is strongly recommended instead.**

If you cannot access your router's admin panel (shared housing, restrictive ISP, etc.), rmail can attempt automatic port forwarding.

1. Run `./scripts/install.sh` — it offers to compile `upnpc` and `natpmpc` from source.

2. Enable in `~/.config/rmail/config`:

   ```
   auto_port_forward = true
   ```

3. Restart rmail. It tries UPnP first, then NAT-PMP. If successful, the mapping is renewed every 30 minutes.

**Security check:** On every startup, rmail probes your router for UPnP and NAT-PMP. If either protocol is available (meaning your router has insecure protocols active), rmail sends a one-time warning message to all your contacts advising them not to send sensitive information until you fix it.

**Disabling UPnP/NAT-PMP on your router** (recommended):

Log into your router's admin panel and disable:
- UPnP
- NAT-PMP
- PCP (unless using authenticated PCP, which almost no routers support)

Then set up a manual port forward for your rmail port. See [docs/nat-traversal-report.md](docs/nat-traversal-report.md) for a detailed analysis of these protocols and their security implications.

To find your router's admin panel, first get your default gateway address:

```sh
ip route show default | awk '{print $3}'
```

Then enter that address into your web browser's address bar. Every router's admin interface is different, because of course they are. The username and password are usually printed on a sticker on the bottom of the router.

## Encryption

All connections use AES-256-GCM encryption. Every message delivery and deletion notification is sent over an encrypted channel using the shared token from each contact pair as the key. Both sides must have the same token.

The protocol:
- Each packet is `[4-byte length][12-byte random nonce][ciphertext][16-byte GCM auth tag]`
- The AES key is `SHA256(token)` — a 32-byte key derived from the contact's token
- The server identifies the sender by trial decryption: it tries each contact's key until the GCM auth tag validates. No identity label is sent in cleartext — only destination IP and port are visible to an observer.

`rmail_crypto.so` (compiled from source by `./scripts/install.sh`) provides the AES-GCM and SHA-256 primitives via OpenSSL.

## Dynamic IP

If your ISP changes your public IP, the daemon detects it automatically. On each startup it checks your public IP using multiple services (`ifconfig.me`, `icanhazip.com`, `api.ipify.org`, `checkip.amazonaws.com`). If a change is detected, it verifies with a second service before acting — so a single service returning a bad result won't trigger a false update.

Once confirmed, the daemon notifies all your contacts. If a contact is offline, the notification is retried on each sync cycle until they acknowledge it. Their daemons update your entry in their contacts file and drop a notification in their inbox so they know what happened.

On first startup it just saves the current IP without notifying anyone.

## Hooks

Hooks let you run scripts in response to message events. Configure them in `~/.config/rmail/config`:

| Hook            | `$1`       | `$2`       | `$3`               | stdout        |
|-----------------|------------|------------|--------------------|---------------|
| `on_send`       | recipient  | subject    | message body       | replaces body |
| `on_receive_raw`| sender     | subject    | message body       | replaces body |
| `on_receive`    | sender     | subject    | path to inbox file | ignored       |
| `on_delete`     | other party| —          | —                  | ignored       |
| `on_package`    | sender     | filename   | path to saved file | ignored       |

- **`on_send`** — runs once per recipient. message only sends after the script finishes. stdout replaces the body for that recipient only.
- **`on_receive_raw`** — runs to completion before the message is written. stdout replaces the saved body.
- **`on_receive`** — runs in the background after the message is on disk.
- **`on_delete`**  — runs in the background when a message is deleted from inbox or outbox.
- **`on_package`** — runs in the background after an attachment is fully received and saved.

Hooks are a powerful feature — any executable works, in any language. For full documentation and examples in bash, Lua, and C, see [docs/scripting-tutorial.md](docs/scripting-tutorial.md).

## Troubleshooting

**"dkjson.lua not found"** — make sure `libs/dkjson.lua` exists next to `rmail.lua`. If you moved the script, move the `libs/` directory with it.

**"luasocket not found"** — run `./scripts/install.sh` to compile it locally.

**"rmail_crypto.so not found"** — run `./scripts/install.sh` to compile it from source. OpenSSL headers are required.

**"zip not found" or "unzip not found"** — run `./scripts/install.sh` to compile Info-ZIP from source. Both are required for attachment transfer.

**Messages not sending** — this is almost always a port issue. Check these in order:
1. Is the recipient's daemon actually running?
2. Is your daemon actually running?
3. Is the port forwarded on their router to their machine's local IP?
4. Is the port open in their OS firewall?
5. Is the `ip`/`port` in your contacts file correct (public IP, not local IP)?
6. Do both sides have the same token?
7. Did you wait long enough for the daemon to try sending the messages again?
8. Is there a script on the `on_send` hook that is stuck in a loop, exiting with an error, or outputting an empty body to stdout?

If the port isn't open or forwarded, the connection will either time out (packets silently dropped) or be refused. Either way, the message stays in your outbox and the daemon retries on the next sync cycle.

**Attachment stuck waiting** — check the recipient's inbox for a consent file. The transfer won't start until they delete the `deny` line and leave `accept` for their daemon to read.

**Port already in use** — another instance may be running, or change `port` in `~/.config/rmail/config` to something not in use by another application.

## Docs

- [docs/attachments.md](docs/attachments.md) — full attachment workflow, consent, configuration
- [docs/scripting-tutorial.md](docs/scripting-tutorial.md) — scripting hooks with examples in bash, Lua, and C
- [docs/service.md](docs/service.md) — running rmail automatically on boot, multiple instances
- [docs/protocol.md](docs/protocol.md) — wire protocol reference, sync timing
- [docs/ports-explained.md](docs/ports-explained.md) — plain-language explanation of ports and port forwarding
- [docs/nat-traversal-report.md](docs/nat-traversal-report.md) — deep dive on UPnP, NAT-PMP, and port forwarding security
