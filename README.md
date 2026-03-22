# r-mail

File-based messaging. Messages are plain text files on disk — write them with whatever editor you like, and a background daemon syncs everything over HTTP.

## How it works

Each person runs an `rmail` daemon. It watches two directories:

```
~/mail/
  inbox/         # received messages appear here
  outbox/        # write files here to send
  attachments/   # received attachments
  contacts       # your identity, address book, shared secrets
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

The daemon picks it up and delivers it to each recipient's inbox as a plain text file (without the `to:` headers).

Deleting works both ways:

- **Recipient deletes** from inbox — the sender's copy has that `to:` line removed.
- **Sender deletes** the outbox file — all recipients are notified to automatically remove it.
- **Sender removes a `to:` line** — that specific recipient's copy is deleted, others are unaffected.

When all `to:` lines are gone (everyone deleted or was removed), the outbox file is cleaned up automatically.

### Attachments

Add `attach:` lines to send files. Each recipient receives all `attach:` lines that appear below their `to:` line:

```
to: alice
to: bob
attach: /path/to/photo.jpg

Here's the photo from yesterday.
```

Both alice and bob get `photo.jpg`. To send an attachment to only some recipients, put it between their `to:` line and the next:

```
to: alice
to: sarah
attach: /path/to/notes.pdf
to: bob

Alice and Sarah get the PDF, bob just gets the message body.
```

Before any file is transferred, the recipient sees a consent request appear in their inbox:

```
alice wants to send you an attachment.

  File:          photo.jpg
  Expected size: 3.2 MB
  Available:     47.3 GB on this drive
  After:         47.3 GB remaining (71% of capacity)

Delete one of these lines to make your choice:

yes
no
```

Delete `no` to accept, or `yes` to decline. Once accepted, the file is transferred in chunks over the same encrypted channel as messages. When complete, the consent file is replaced with a confirmation and the attachment appears in `~/mail/attachments/`.

Interrupted transfers resume automatically — the receiver keeps whatever chunks have already arrived and the sender picks up where it left off on the next sync cycle.

To cancel a transfer in progress, delete the outbox file. This notifies all recipients and stops any ongoing chunk transfer.

## Dependencies

- **Lua** 5.1+ (5.4 recommended)
- **LuaSocket** — TCP networking for Lua
- **LuaSec** — TLS-PSK encryption, must be compiled with PSK support
- **zip / unzip** — file compression for attachment transfer (Info-ZIP)

Run `scripts/install.sh` to compile all dependencies from source into the local `libs/` directory.

## Configuration

The daemon creates `~/mail/inbox`, `~/mail/outbox`, and `~/mail/.state` on startup if they don't exist. The install script creates both the config file and a contacts file with your identity pre-filled.

### Config file

`~/.config/rmail/config` controls your identity and settings. The most important field is `name`, which must match your key in the contacts file:

```
name = yourname
port = 8025
mail = ~/mail

# optional — shown with their defaults:
# attachments          = ~/mail/attachments
# attachment_pending_dir = /tmp
# attachment_chunk_size  = 5242880
```

`attachment_pending_dir` is where partially-received chunks are stored while a transfer is in progress. The default is `/tmp`, so the OS clears them automatically on reboot. Set it to a persistent path (e.g. `~/mail/attachments`) if you want interrupted transfers to survive a restart.

### Contacts file

`~/mail/contacts` is a line-oriented file listing the people you communicate with. Lines starting with `//` or `#` are comments. Your own identity lives in the config file — the contacts file is just an address book.

```
alice.ip    = 203.0.113.1
alice.port  = 8025
alice.token = "some-shared-secret"
```

| Field   | Meaning                              |
|---------|--------------------------------------|
| `ip`    | their router's public IP address     |
| `port`  | port their daemon listens on         |
| `token` | shared secret (same on both sides)   |

Both sides must have the same token for a given contact pair. Pick something long and random.

You can add arbitrary fields (e.g. `alice.phone = "555-1234"`) — rmail stores them but ignores them. Hook scripts can read them directly with grep. See `scripting-tutorial.md`.

## Ports

Each person runs their daemon on a single port. Unless provided, the install script generates a random port in the 50000–65000 range. That one port handles both sending and receiving — all your contacts deliver to the same port.

The only thing your contacts need is your **router's public IP** and your **port number**. That's what goes in their contacts file. Local/LAN IP addresses are never shared with contacts.

You will need your local IP however, when setting up port forwarding on your router — the router needs to know which machine on the Local Area Network (LAN) to send traffic to. If multiple people are behind the same router, each person needs a unique port:

| Person | Router forward config      | What contacts put in their file |
|--------|----------------------------|---------------------------------|
| Alice  | port 8025 → 192.168.1.10   | 203.0.113.1, port 8025          |
| Bob    | port 8026 → 192.168.1.20   | 203.0.113.1, port 8026          |

If everyone is on separate networks, they can all use the same port number. Only your router cares about the port number. It's like registering a mailbox with your mailman when you first move in to a new place, but for a specific computer.

To find your **local IP** (for router port forwarding):

```
ip addr show | grep 'inet '
```

To find your **public IP** (what your contacts put in their file):

```
curl ifconfig.me
```

### Opening the firewall

Your OS firewall also needs to allow traffic on your port. To check which firewall you're running:

```
which ufw && echo "you have ufw"      || \
which nft && echo "you have nftables" || \
which iptables && echo "you have iptables"
```

Then open the port:

```sh
# ufw
sudo ufw allow 8025/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 8025 -j ACCEPT

# nftables (add to your ruleset)
tcp dport 8025 accept
```

To verify that the port is open, run this from a computer on the network:
```
-ss -tlnp | grep 8025
```


To verify the daemon is reachable:

```
curl http://localhost:8025/
```

This returns `{"ok":true,"name":"yourname"}` if everything is working. You can also test from another machine using the public IP to confirm port forwarding is set up correctly.

### Automatic port forwarding (UPnP / NAT-PMP)

> **WARNING: Automatic port forwarding uses UPnP or NAT-PMP, which are
> fundamentally insecure protocols. Any device on your local network can open
> any port on your router without authentication. Malware commonly exploits
> this. Manual port forwarding is strongly recommended instead.**

If you cannot access your router's admin panel (shared housing, restrictive ISP, etc.), rmail can attempt automatic port forwarding.

1. Run `scripts/install.sh` — it offers to compile `upnpc` and `natpmpc` from source.

2. Enable in `~/.config/rmail/config`:

   ```
   auto_port_forward = true
   ```

3. Restart rmail. It tries UPnP first, then NAT-PMP. If successful, the mapping is renewed every 30 minutes.

**How it works:**
- On startup, rmail creates a port mapping on your router via UPnP or NAT-PMP
- The mapping is renewed periodically before it expires
- On next startup, stale mappings from previous runs are cleaned up
- If the mapping fails, rmail continues but logs a warning

**Security check:** On every startup, rmail probes your router for UPnP and NAT-PMP. If either protocol is available (meaning your router has insecure protocols active), rmail sends a one-time warning message to all your contacts advising them not to send sensitive information until you fix it.

**Disabling UPnP/NAT-PMP on your router** (recommended):

Log into your router's admin panel and disable:
- UPnP
- NAT-PMP
- PCP (unless using authenticated PCP, which almost no routers support)

Then set up a manual port forward for your rmail port. See [nat-traversal-report.md](nat-traversal-report.md) for a detailed analysis of these protocols and their security implications.

## Installation

```sh
git clone https://github.com/gabrilend/r-mail.git
cd r-mail
scripts/install.sh
```

`install.sh` compiles all dependencies from source into `libs/`, and generates your config and contacts files. It will ask whether to compile Lua locally or use your system version.

To run manually:

```sh
lua rmail.lua
# or, if you compiled Lua locally:
deps/lua/bin/lua rmail.lua
```

## Running as a service

`install.sh` detects your init system and offers to set up the service automatically. If you need to do it manually, the formats are below. Replace `/path/to/lua` with either `deps/lua/bin/lua` (local) or your system lua (`which lua`), and `/path/to/rmail` with the directory you cloned into.

### systemd

**User service** — no root required, starts on login:

```ini
# ~/.config/systemd/user/rmail.service
[Unit]
Description=rmail messaging daemon
After=network.target

[Service]
Type=simple
ExecStart=/path/to/lua /path/to/rmail/rmail.lua
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now rmail
journalctl --user -u rmail -f
# to keep running after logout:
loginctl enable-linger
```

**System service** — starts at boot, requires root:

```ini
# /etc/systemd/system/rmail.service
[Unit]
Description=rmail messaging daemon
After=network.target

[Service]
Type=simple
User=YOURUSER
ExecStart=/path/to/lua /path/to/rmail/rmail.lua
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now rmail
journalctl -u rmail -f
```

### runit

```sh
# /etc/sv/rmail/run
#!/bin/sh
exec /path/to/lua /path/to/rmail/rmail.lua 2>&1
```

```sh
sudo mkdir -p /etc/sv/rmail
sudo mv rmail-run /etc/sv/rmail/run
sudo chmod +x /etc/sv/rmail/run
sudo ln -s /etc/sv/rmail /var/service/
```

### OpenRC

```sh
# /etc/init.d/rmail
#!/sbin/openrc-run

description="rmail messaging daemon"
command="/path/to/lua"
command_args="/path/to/rmail/rmail.lua"
command_user="YOURUSER"
command_background=true
pidfile="/run/rmail.pid"
output_log="/var/log/rmail.log"
error_log="/var/log/rmail.log"
```

```sh
sudo mv rmail-init /etc/init.d/rmail
sudo chmod +x /etc/init.d/rmail
sudo rc-update add rmail default
sudo rc-service rmail start
tail -f /var/log/rmail.log
```

### NixOS

NixOS uses systemd internally but service files placed in `/etc/systemd/system/` are overwritten on every `nixos-rebuild`. Instead, `install.sh` generates a `rmail.nix` file — move it into place and import it:

```sh
sudo cp rmail.nix /etc/nixos/rmail.nix
```

Add to `/etc/nixos/configuration.nix`:

```nix
imports = [ ./rmail.nix ];
```

Then rebuild:

```sh
sudo nixos-rebuild switch
journalctl -u rmail -f
```

## Protocol

JSON over HTTP, two endpoints:

**`POST /deliver`** — deliver a message:

```json
{"from": "alice", "token": "secret", "type": "message", "subject": "hello", "message_id": "uuid", "body": "text"}
```

**`POST /delete`** — notify of a deletion:

```json
{"from": "alice", "token": "secret", "message_id": "uuid"}
```

Auth is a shared secret per contact pair, checked against the contacts file.

You can test delivery with curl:

```
curl -X POST http://localhost:8025/deliver \
  -H 'Content-Type: application/json' \
  -d '{"from":"alice","token":"your-shared-secret","type":"message","subject":"test","message_id":"test-1","body":"hello from curl"}'
```

Be sure to fill in the correct IP and port number where it says `localhost:8025`.

## Sync timing

The daemon checks for outbox/inbox changes on an adaptive timer:

- Starts at **5 minutes**
- Had work: interval **shrinks by 4 min** (floor: 1 min)
- No work: interval **grows by 6 min** (no ceiling, resets on restart)

This means the daemon is responsive when you're actively messaging and backs off when idle.

## Dynamic IP

If your ISP changes your public IP, the daemon detects it automatically. On each startup it checks your public IP using multiple services (`ifconfig.me`, `icanhazip.com`, `api.ipify.org`, `checkip.amazonaws.com`). If a change is detected, it verifies with a second service before acting — so a single service returning a bad result won't trigger a false update.

Once confirmed, the daemon notifies all your contacts. If a contact is offline, the notification is retried on each sync cycle until they acknowledge it. Their daemons update your entry in their contacts file and drop a notification in their inbox so they know what happened.

On first startup it just saves the current IP without notifying anyone.

## Encryption

All connections are encrypted with TLS-PSK (Pre-Shared Key). Every message delivery and deletion notification is sent over TLS using the shared token from each contact pair as the key. Both sides must have the same token.

LuaSec with PSK support is required — run `scripts/install.sh` to compile it.

## Hooks

Hooks let you run scripts in response to message events. Configure them in `~/.config/rmail/config`:

| Hook            | `$1`       | `$2`       | `$3`               | stdout        |
|-----------------|------------|------------|--------------------|---------------|
| `on_receive_raw`| sender     | subject    | message body       | replaces body |
| `on_receive`    | sender     | subject    | path to inbox file | ignored       |
| `on_send`       | recipient  | subject    | message body       | replaces body |
| `on_delete`     | other party| —          | —                  | ignored       |
| `on_package`    | sender     | filename   | path to saved file | ignored       |

- **`on_receive_raw`** — synchronous, runs before the message is written. stdout replaces the saved body. Use for filtering or transformation.
- **`on_receive`** — runs in background after the message is on disk. Use for notifications, backups.
- **`on_send`** — synchronous, runs once per recipient. stdout replaces the body for that recipient only. Use for per-recipient transformation.
- **`on_delete`** — runs when a message is deleted from inbox or outbox.
- **`on_package`** — runs in background after an attachment is fully received and saved.

See `scripting-tutorial.md` for full documentation and examples in bash, Lua, and C.

## Troubleshooting

**"dkjson.lua not found"** — make sure `libs/dkjson.lua` exists next to `rmail.lua`. If you moved the script, move the `libs/` directory with it.

**"luasocket not found"** — run `scripts/install.sh` to compile it locally.

**Messages not sending** — this is almost always a port issue. Check these in order:
1. Is the recipient's daemon actually running?
2. Is your daemon actually running?
3. Is the port forwarded on their router to their machine's local IP?
4. Is the port open in their OS firewall?
5. Is the `ip`/`port` in your contacts file correct (public IP, not local IP)?
6. Do both sides have the same token?
7. Did you wait long enough for the daemon to try sending the messages again?

If the port isn't open or forwarded, the connection will either time out (packets silently dropped) or be refused. Either way, the message stays in your outbox and the daemon retries on the next sync cycle.

**"luasec not found" or "not compiled with PSK support"** — run `scripts/install.sh` to compile LuaSec with PSK support from source. System packages often don't include PSK.

**"zip not found" or "unzip not found"** — run `scripts/install.sh` to compile Info-ZIP from source. Both are required for attachment transfer.

**Attachment stuck waiting** — check the recipient's inbox for a consent file. The transfer won't start until they delete the `no` line to accept. If the consent file is missing, the daemon may not have run a sync cycle yet.

**Port already in use** — another instance may be running, or change `port` in `~/.config/rmail/config` to something not in use by another application.
