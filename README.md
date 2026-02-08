# r-mail

File-based messaging. Messages are plain text files on disk — write them with whatever editor you like, and a background daemon syncs everything over HTTP.

## How it works

Each person runs an `rmail` daemon. It watches two directories:

```
~/mail/
  inbox/       # received messages appear here
  outbox/      # write files here to send
  contacts     # your identity, address book, shared secrets
  .state/      # sync tracking (managed by daemon)
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
- **Sender deletes** the outbox file — all recipients are notified to remove it.
- **Sender removes a `to:` line** — that specific recipient's copy is deleted, others are unaffected.

When all `to:` lines are gone (everyone deleted or was removed), the outbox file is cleaned up automatically.

## Dependencies

- **Lua** 5.1+ (5.4 recommended)
- **LuaSocket** — TCP networking for Lua

`dkjson` is bundled in `libs/` — no need to install it separately.

If a dependency is missing, the daemon will tell you exactly what's needed and where to put it.

## Configuration

Before starting the daemon, set up `~/mail/`:

```
mkdir -p ~/mail/inbox ~/mail/outbox ~/mail/.state
```

Create `~/mail/contacts`. The first entry is always `"me"` — your name and port. The rest are your contacts:

```json
{
  "me": {
    "name": "yourname",
    "port": 8025
  },
  "alice": {
    "host": "192.168.1.10",
    "port": 8025,
    "token": "some-shared-secret"
  }
}
```

Both sides must have the same token for a given contact pair. Pick something long and random.

## Ports

Each person runs their daemon on a single port (default `8025`). That one port handles both sending and receiving — all your contacts deliver to the same port.

The only thing your contacts need is your **router's public IP** and your **port number**. That's what goes in their contacts file. Local/LAN IP addresses are never shared with contacts.

You will need your local IP when setting up port forwarding on your router — the router needs to know which machine on the LAN to send traffic to. If multiple people are behind the same router, each person needs a unique port:

| Person | Router forward config      | What contacts put in their file |
|--------|----------------------------|---------------------------------|
| Alice  | port 8025 → 192.168.1.10   | 203.0.113.1, port 8025          |
| Bob    | port 8026 → 192.168.1.20   | 203.0.113.1, port 8026          |

If everyone is on separate networks, they can all use the same port number. Only your router cares about the port number. It's like a mailbox for a specific computer.

## Installation

### NixOS

A NixOS module is included. It handles Lua + LuaSocket, the systemd service, and the firewall port.

Add to your `configuration.nix`:

```nix
imports = [
  /path/to/r-mail/mail.nix
];
```

Edit `mail.nix` to set `User` to your username if it isn't `ritz`. Then rebuild:

```
sudo nixos-rebuild switch
systemctl status rmail
journalctl -u rmail -f
```

### Arch Linux

Install Lua and LuaSocket:

```
sudo pacman -S lua lua-socket
```

Open the firewall port (if using `ufw`):

```
sudo ufw allow 8025/tcp
```

Or with raw iptables:

```
sudo iptables -A INPUT -p tcp --dport 8025 -j ACCEPT
```

Clone the repo and run:

```
git clone https://github.com/YOURUSER/r-mail.git
cd r-mail
lua rmail.lua
```

To run as a systemd service, create `/etc/systemd/system/rmail.service`:

```ini
[Unit]
Description=rmail messaging daemon
After=network.target

[Service]
Type=simple
User=YOURUSER
ExecStart=/usr/bin/lua /path/to/r-mail/rmail.lua
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```
sudo systemctl daemon-reload
sudo systemctl enable --now rmail
journalctl -u rmail -f
```

### Void Linux

Install Lua and LuaSocket:

```
sudo xbps-install -S lua54 lua54-luasocket
```

Open the firewall port (if using `ufw`):

```
sudo ufw allow 8025/tcp
```

Or with raw iptables:

```
sudo iptables -A INPUT -p tcp --dport 8025 -j ACCEPT
```

Clone the repo and run:

```
git clone https://github.com/YOURUSER/r-mail.git
cd r-mail
lua rmail.lua
```

To run as a runit service, create the service directory:

```
sudo mkdir -p /etc/sv/rmail
```

Create `/etc/sv/rmail/run`:

```sh
#!/bin/sh
exec chpst -u YOURUSER lua /path/to/r-mail/rmail.lua 2>&1
```

Make it executable and enable:

```
sudo chmod +x /etc/sv/rmail/run
sudo ln -s /etc/sv/rmail /var/service/
sv status rmail
```

### Gentoo

Install Lua and LuaSocket:

```
sudo emerge dev-lang/lua dev-lua/luasocket
```

Open the firewall port (if using `iptables`):

```
sudo iptables -A INPUT -p tcp --dport 8025 -j ACCEPT
```

Or with `nftables`, add to your ruleset:

```
tcp dport 8025 accept
```

Clone the repo and run:

```
git clone https://github.com/YOURUSER/r-mail.git
cd r-mail
lua rmail.lua
```

To run as an OpenRC service, create `/etc/init.d/rmail`:

```sh
#!/sbin/openrc-run

description="rmail messaging daemon"
command="/usr/bin/lua"
command_args="/path/to/r-mail/rmail.lua"
command_user="YOURUSER"
command_background=true
pidfile="/run/rmail.pid"
output_log="/var/log/rmail.log"
error_log="/var/log/rmail.log"
```

Make it executable and enable:

```
sudo chmod +x /etc/init.d/rmail
sudo rc-update add rmail default
sudo rc-service rmail start
tail -f /var/log/rmail.log
```

## Protocol

JSON over HTTP, two endpoints:

**`POST /deliver`** — deliver a message:

```json
{"from": "alice", "token": "secret", "subject": "hello", "message_id": "uuid", "body": "text"}
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
  -d '{"from":"alice","token":"your-shared-secret","subject":"test","message_id":"test-1","body":"hello from curl"}'
```

## Sync timing

The daemon checks for outbox/inbox changes on an adaptive timer:

- Starts at **5 minutes**
- Had work: interval **shrinks by 4 min** (floor: 1 min)
- No work: interval **grows by 6 min** (no ceiling, resets on restart)

This means the daemon is responsive when you're actively messaging and backs off when idle.

## Troubleshooting

**"dkjson.lua not found"** — make sure `libs/dkjson.lua` exists next to `rmail.lua`. If you moved the script, move the `libs/` directory with it.

**"luasocket not found"** — install it with your package manager or `luarocks install luasocket`.

**Messages not sending** — this is almost always a port issue. Check these in order:
1. Is the recipient's daemon actually running?
2. Is ... ....   your daemon actually running?
3. Is the port forwarded on their router to their machine's local IP?
4. Is the port open in their OS firewall?
5. Is the host/port in your contacts file correct (public IP, not local IP)?
6. Do both sides have the same token?
7. Did you wait long enough for the daemon to try sending the messages again?

If the port isn't open or forwarded, the connection will either time out (packets silently dropped) or be refused. Either way, the message stays in your outbox and the daemon retries on the next sync cycle.

**Port already in use** — another instance may be running, or change the port in your contacts file under `"me"` to something not in use by another application.
