# Running rmail as a service

rmail only sends and receives messages while the daemon is running. If you close
your terminal or log out, the daemon stops and your outbox won't be delivered
until you start it again. Setting it up as a service means it starts automatically
and stays running in the background.

`install.sh` detects your init system and offers to set this up automatically.
The manual formats are below. Replace `/path/to/lua` with either
`deps/lua/bin/lua` (local) or your system lua (`which lua`), and
`/path/to/rmail` with the directory you cloned the code into, not the location of your mailbox.

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

systemd offers two modes:

- **User service** — runs as your user, starts on login, no root required.
  Survives logout if you enable lingering (`loginctl enable-linger`). Good for
  single-user machines or when you don't have root.
- **System service** — runs at boot regardless of who's logged in. Requires
  root to install. Better for shared machines or headless servers where no one
  logs in interactively.

### User service

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

### System service

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
`rmail.nix` file that defines the service declaratively. The generated file
looks like this (yours will have your actual paths and port filled in):

```nix
{ config, ... }:

let
  rmailPort = 8025;
in {
  networking.firewall.allowedTCPPorts = [ rmailPort ];

  systemd.services.rmail = {
    description = "rmail messaging daemon";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "youruser";
      Group = "users";
      ExecStart = "/path/to/lua /path/to/rmail/rmail.lua /path/to/mail";
      Restart = "on-failure";
      RestartSec = 5;
    };
  };
}
```

Use the auto-generated version (`rmail.nix` in the project root) — it has your
paths and port pre-filled. Copy it into place:

```sh
sudo cp rmail.nix /etc/nixos/rmail.nix
```

Add it to your imports in `/etc/nixos/configuration.nix`:

```nix
imports = [
  ./hardware-configuration.nix
  ./rmail.nix
  # ... any other imports you have
];
```

Then rebuild:

```sh
sudo nixos-rebuild switch
journalctl -u rmail -f
```

---

## Running multiple instances

Each rmail daemon manages one mailbox. You can run several daemons on the same
machine for different purposes — for example, one mailbox for personal messages,
one for automated notifications from scripts, and one for file synchronization
between devices. Since all configuration lives in the config file, running
multiple daemons is just a matter of pointing each one at a different config:

```sh
lua rmail.lua --config ~/.config/rmail/config-personal
lua rmail.lua --config ~/.config/rmail/config-notifications
lua rmail.lua --config ~/.config/rmail/config-sync
```

Each instance needs:

1. **Its own config file** pointing to a different `mail` directory and `port`:

   ```
   # ~/.config/rmail/config-notifications
   name = alice-notifications
   port = 8026
   mail = ~/mail-notifications
   ```

2. **Its own port** — each daemon listens on one port. They cannot share a port.

3. **Its own mail directory** — `inbox/`, `outbox/`, `contacts`, and `.state/`
   are all relative to the `mail` setting in the config.

To run each instance as a service, create one service file per config. The
setup is the same as for a single instance — just duplicate the service file
and change the `--config` path:

**systemd:**

```sh
# Duplicate and edit: change --config path in ExecStart
cp ~/.config/systemd/user/rmail.service ~/.config/systemd/user/rmail-notifications.service
systemctl --user daemon-reload
systemctl --user enable --now rmail-notifications
```

**runit:**

```sh
# Create a new service directory with its own run script
sudo mkdir -p /etc/sv/rmail-notifications
# Copy and edit the run script, changing the --config path
sudo cp /etc/sv/rmail/run /etc/sv/rmail-notifications/run
sudo ln -s /etc/sv/rmail-notifications /var/service/
```

**OpenRC:**

```sh
# Copy and edit the init script, changing command_args
sudo cp /etc/init.d/rmail /etc/init.d/rmail-notifications
sudo rc-update add rmail-notifications default
```

**NixOS:** Add another `systemd.services` block in your nix config, or
generate a second `rmail.nix` by running `install.sh` again with the second
config.

If both instances are behind the same router, each needs its own port forwarding
rule to direct traffic to each specific instance — see the Ports section in
README.md.
