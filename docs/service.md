# Running rmail as a service

rmail only sends and receives messages while the daemon is running. If you close
your terminal or log out, the daemon stops and your outbox won't be delivered
until you start it again. Setting it up as a service means it starts automatically
and stays running in the background.

`install.sh` detects your init system and offers to set this up automatically.
The manual formats are below. Replace `/path/to/lua` with either
`deps/lua/bin/lua` (local) or your system lua (`which lua`), and
`/path/to/rmail` with the directory you cloned into.

## Logging

All service configurations log to `/tmp/rmail.log`. Since `/tmp` is typically
RAM-backed (tmpfs), logs don't persist across reboots and don't cause disk wear.

To view logs in real-time:

```sh
./scripts/view-logs.sh
# or directly:
tail -f /tmp/rmail.log
```

A hidden symlink `.logs` in the project root also points to the log file.

---

## systemd

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

---

## runit

```sh
# /etc/sv/rmail/run
#!/bin/sh
export HOME=/home/YOURUSER
exec chpst -u YOURUSER /path/to/lua /path/to/rmail/rmail.lua >>/tmp/rmail.log 2>&1
```

```sh
sudo mkdir -p /etc/sv/rmail
sudo mv rmail-run /etc/sv/rmail/run
sudo chmod +x /etc/sv/rmail/run
sudo ln -s /etc/sv/rmail /var/service/
```

Logs: `tail -f /tmp/rmail.log` or `./scripts/view-logs.sh`

---

## OpenRC

```sh
# /etc/init.d/rmail
#!/sbin/openrc-run

description="rmail messaging daemon"
command="/path/to/lua"
command_args="/path/to/rmail/rmail.lua"
command_user="YOURUSER"
command_background=true
pidfile="/run/rmail.pid"
output_log="/tmp/rmail.log"
error_log="/tmp/rmail.log"
```

```sh
sudo mv rmail-init /etc/init.d/rmail
sudo chmod +x /etc/init.d/rmail
sudo rc-update add rmail default
sudo rc-service rmail start
```

Logs: `tail -f /tmp/rmail.log` or `./scripts/view-logs.sh`

---

## NixOS

NixOS uses systemd internally but service files placed in `/etc/systemd/system/`
are overwritten on every `nixos-rebuild`. Instead, `install.sh` generates a
`rmail.nix` file — move it into place and import it:

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

---

## Running multiple instances

You can run more than one rmail daemon on the same machine — for example, to
maintain separate inboxes for different identities, or to test two peers locally.
Each instance needs:

1. **Its own config file** pointing to a different `mail` directory and `port`:

   ```
   # ~/.config/rmail/config-work
   name = alice-work
   port = 8026
   mail = ~/mail-work
   ```

2. **Its own port** — each daemon listens on one port. They cannot share a port.

3. **Its own mail directory** — `inbox/`, `outbox/`, `contacts`, and `.state/`
   are all relative to the `mail` setting in the config.

To run a second instance pointing at a different config:

```sh
lua rmail.lua --config ~/.config/rmail/config-work
```

For a systemd user service, duplicate the unit file and set
`ExecStart=... rmail.lua --config /path/to/config-work`.

If both instances are behind the same router, each needs its own port forwarding
rule — see the Ports section in README.md.
