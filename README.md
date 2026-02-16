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

Attachments are base64-encoded and sent inline with the message. The recipient gets them in `~/mail/attachments/`.

Removing an `attach:` line from the outbox file deletes that attachment from the recipient's side.

## Dependencies

- **Lua** 5.1+ (5.4 recommended)
- **LuaSocket** — TCP networking for Lua
- **LuaSec** (optional) — required for TLS-PSK encryption, must be compiled with PSK support

Run `scripts/install-deps.sh --help` to compile all dependencies (including LuaSec with PSK) from source into the local `libs/` directory.

## Configuration

The daemon creates `~/mail/inbox`, `~/mail/outbox`, and `~/mail/.state` on startup if they don't exist.

Create `~/mail/contacts`. The first entry is always `"me"` — your name and port. The rest are your contacts:

```json
{
  "me": {
    "name": "yourname",
    "port": 8025
  },
  "alice": {
    "host": "203.0.113.1",
    "port": 8025,
    "token": "some-shared-secret"
  }
}
```

Both sides must have the same token for a given contact pair. Pick something long and random.

## Ports

Each person runs their daemon on a single port. Unless provided, the install script generates a random port in the 50000–65000 range. That one port handles both sending and receiving — all your contacts deliver to the same port.

The only thing your contacts need is your **router's public IP** and your **port number**. That's what goes in their contacts file. Local/LAN IP addresses are never shared with contacts.

You will need your local IP however, when setting up port forwarding on your router — the router needs to know which machine on the Local Area Network (LAN) to send traffic to. If multiple people are behind the same router, each person needs a unique port:

| Person | Router forward config      | What contacts put in their file |
|--------|----------------------------|---------------------------------|
| Alice  | port 8025 → 192.168.1.10   | 203.0.113.1, port 8025          |
| Bob    | port 8026 → 192.168.1.20   | 203.0.113.1, port 8026          |

If everyone is on separate networks, they can all use the same port number. Only your router cares about the port number. It's like registering a mailbox when you first move in to a new place, but for a specific computer.

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

1. Run `scripts/install-deps.sh` — it offers to compile `upnpc` and `natpmpc` from source.

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

**Security check:** On every startup, rmail probes your router for UPnP and NAT-PMP regardless of whether `auto_port_forward` is enabled. If either protocol is available (meaning your router has insecure protocols active), rmail sends a one-time warning message to all your contacts advising them not to send sensitive information until you fix it.

To suppress this check (because you've manually configured your router and verified it's secure):

```
manual_port_forward = true
```

**Disabling UPnP/NAT-PMP on your router** (recommended):

Log into your router's admin panel and disable:
- UPnP
- NAT-PMP
- PCP (unless using authenticated PCP, which almost no routers support)

Then set up a manual port forward for your rmail port. See [nat-traversal-report.md](nat-traversal-report.md) for a detailed analysis of these protocols and their security implications.

## Installation

### NixOS

Add to your `configuration.nix` (change the user, path, and port to match your setup):

```nix
{ config, pkgs, ... }:

let
  rmailPort = 8025;  # must match your contacts file
  luaEnv = pkgs.lua5_4.withPackages (ps: [ ps.luasocket ]);
in {
  networking.firewall.allowedTCPPorts = [ rmailPort ];

  systemd.services.rmail = {
    description = "rmail messaging daemon";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "YOURUSER";
      Group = "users";
      ExecStart = "${luaEnv}/bin/lua /path/to/r-mail/rmail.lua";
      Restart = "on-failure";
      RestartSec = 5;
    };
  };
}
```

be sure to fill in the correct value where it says YOURUSER.

If you need encryption, run `scripts/install-deps.sh` to compile LuaSec with PSK support — the NixOS `luasec` package may not include it.

Then rebuild:

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

Clone the repo and run:

```
git clone https://github.com/gabrilend/r-mail.git
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

be sure to insert the correct value for YOURUSER. Then, enable and start:

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

Clone the repo and run:

```
git clone https://github.com/gabrilend/r-mail.git
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

be sure to put your username where it says YOURUSER above, then make it executable and enable:

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

Clone the repo and run:

```
git clone https://github.com/gabrilend/r-mail.git
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

be sure to fill in your username where it says YOURUSER. Then, make it executable and enable:

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

be sure to fill in the correct ip and port number where it says `localhost:8025`

## Sync timing

The daemon checks for outbox/inbox changes on an adaptive timer:

- Starts at **5 minutes**
- Had work: interval **shrinks by 4 min** (floor: 1 min)
- No work: interval **grows by 6 min** (no ceiling, resets on restart)

This means the daemon is responsive when you're actively messaging and backs off when idle.

## Dynamic IP

If your ISP changes your public IP, the daemon detects it automatically. On each startup it checks your public IP using multiple services (`ifconfig.me`, `icanhazip.com`, `api.ipify.org`, `checkip.amazonaws.com`). If a change is detected, it verifies with a second service before acting — so a single service returning a bad result won't trigger a false update.

Once confirmed, the daemon notifies all your contacts. Their daemons update your entry in their contacts file and drop a notification in their inbox so they know what happened.

On first startup it just saves the current IP without notifying anyone.

## Encryption

rmail supports TLS-PSK (Pre-Shared Key) encryption for all peer connections. When enabled, every message delivery and deletion notification is sent over TLS using the shared token from each contact pair as the key.

To enable:

1. Run `scripts/install-deps.sh` to compile LuaSec with PSK support
2. Set `encrypt = true` in `~/.config/rmail/config`
3. Restart rmail

Both sides of a contact pair must have encryption enabled and the same token. If one side has encryption on and the other doesn't, connections will fail (messages stay in the outbox and retry on the next sync cycle).

## Hooks

Hooks let you run scripts in response to message events. Configure them in `~/.config/rmail/config`:

- **`on_receive_raw`** — runs before a received message is written to disk. Your script's stdout replaces the message body. Use for content filtering or non-urgent remote code execution.
- **`on_receive`** — runs after a message is saved to inbox. Use for notifications or backups.
- **`on_package`** — runs after an attachment is saved. Use for notifications or processing.
- **`on_send`** — runs once per recipient before sending. Called as `script <tmpfile> <recipient_name>`. Your script's stdout replaces the body for that recipient.
- **`on_delete`** — runs when a message is deleted by either side.

Each hook receives a temp file path as its first argument containing the event data. See the config file comments for details on what each temp file contains.

## Troubleshooting

**"dkjson.lua not found"** — make sure `libs/dkjson.lua` exists next to `rmail.lua`. If you moved the script, move the `libs/` directory with it.

**"luasocket not found"** — install it with your package manager or `luarocks install luasocket`.

**Messages not sending** — this is almost always a port issue. Check these in order:
1. Is the recipient's daemon actually running?
2. Is your daemon actually running?
3. Is the port forwarded on their router to their machine's local IP?
4. Is the port open in their OS firewall?
5. Is the host/port in your contacts file correct (public IP, not local IP)?
6. Do both sides have the same token?
7. Do both sides have the same encryption setting? TLS-PSK must be enabled manually if you want to have Transport Level Security with a Pre Shared Key.
8. Did you wait long enough for the daemon to try sending the messages again?

If the port isn't open or forwarded, the connection will either time out (packets silently dropped) or be refused. Either way, the message stays in your outbox and the daemon retries on the next sync cycle.

**"luasec not found" or "not compiled with PSK support"** — run `scripts/install-deps.sh` to compile LuaSec with PSK support from source. (highly recommended) - System packages often don't include PSK.

**Port already in use** — another instance may be running, or change the port in your contacts file under `"me"` to something not in use by another application.
