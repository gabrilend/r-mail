# Running rmail as a service

rmail only sends and receives messages while the daemon is running. If you close
your terminal or log out, the daemon stops and your outbox won't be delivered
until you start it again. Setting it up as a service means it starts automatically
and stays running in the background.

`install.sh` detects your init system and offers to set this up automatically.
The manual formats are below. Three things in them need replacing:

**`/path/to/lua`** — your system lua (`which lua`), or the one the installer
compiled, at `deps/lua/bin/lua` inside the checkout.

**`/path/to/rmail`** — the directory you cloned the code into. One checkout
serves every mailbox on the machine; there is no per-mailbox copy of the
daemon. Which mailbox a given daemon serves is decided entirely by its
second argument.

**`/path/to/mailbox`** — the mailbox this service serves. `config` inside it
is what the daemon is handed, and the mailbox served is the directory that
file sits in. The argument is not optional: a daemon started without it stops
with a usage message, because a machine can hold several mailboxes and there
is nothing sensible to assume.

A mailbox holds its own config and its own hook scripts, but not the program.
The exception is a mailbox on removable media, which carries a trimmed copy
under `source-code/` because there is no checkout at the far end of a USB
cable — see the portable-drive generator.

**`SERVICE-NAME`** — the mailbox path with its slashes turned into dashes and
`rmail-` in front, so `/home/ritz/mail` gives `rmail-home-ritz-mail`. Every
file a service owns is named after it, so two mailboxes on one machine never
write to each other's log or pidfile.

## Logging

Each service logs to its own file in `/tmp`, named after the service:
a mailbox at `/home/ritz/mail` is served by `rmail-home-ritz-mail` and logs to
`/tmp/rmail-home-ritz-mail.log`. One file per service rather than one shared
file, because two daemons appending to the same file interleave their lines
with nothing recording which of them wrote any given one.

Since `/tmp` is typically RAM-backed (tmpfs), logs don't persist across reboots
and don't cause disk wear.

To view logs in real-time:

```sh
./scripts/view-logs.sh
# or directly, naming the service whose log you want:
tail -f /tmp/rmail-home-ritz-mail.log
```

`view-logs.sh` lists the logs it finds and asks which one, skipping the
question when there is only one. There is no `.logs` symlink in the project
root any more: it named a single log file, and with one service per mailbox
there is no single log to name.

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
ExecStart=/path/to/lua /path/to/rmail/rmail.lua /path/to/mailbox/config
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
ExecStart=/path/to/lua /path/to/rmail/rmail.lua /path/to/mailbox/config
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
exec chpst -u YOURUSER /path/to/lua /path/to/rmail/rmail.lua /path/to/mailbox/config >>/tmp/SERVICE-NAME.log 2>&1
```

```sh
sudo mkdir -p /etc/sv/rmail
sudo mv rmail-run /etc/sv/rmail/run
sudo chmod +x /etc/sv/rmail/run
sudo ln -s /etc/sv/rmail /var/service/
```

Logs: `tail -f /tmp/SERVICE-NAME.log` or `./scripts/view-logs.sh`

---

## OpenRC

```sh
# /etc/init.d/rmail
#!/sbin/openrc-run

description="rmail messaging daemon"
command="/path/to/lua"
command_args="/path/to/rmail/rmail.lua /path/to/mailbox/config"
command_user="YOURUSER"
command_background=true
pidfile="/run/SERVICE-NAME.pid"
output_log="/tmp/SERVICE-NAME.log"
error_log="/tmp/SERVICE-NAME.log"
```

```sh
sudo mv rmail-init /etc/init.d/rmail
sudo chmod +x /etc/init.d/rmail
sudo rc-update add rmail default
sudo rc-service rmail start
```

Logs: `tail -f /tmp/SERVICE-NAME.log` or `./scripts/view-logs.sh`

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
      ExecStart = "/path/to/lua /path/to/rmail/rmail.lua /path/to/mailbox/config";
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

Each rmail daemon manages one mailbox. You can run several on the same machine
for different purposes — one mailbox for personal messages, one for automated
notifications from scripts, one for file synchronisation between devices.

**Run `install.sh` again, and answer with the second mailbox.** That is the
whole procedure. The installer derives everything that has to differ from the
mailbox path you give it:

| What | Where | Example for `/home/ritz/notes/rmail` |
|---|---|---|
| config file | inside the mailbox | `~/notes/rmail/config` |
| hook scripts | inside the mailbox | `~/notes/rmail/hooks/` |
| the daemon | the one checkout, shared | `/path/to/rmail/rmail.lua` |
| service name | `rmail-` plus the mailbox path, slashes to dashes | `rmail-home-ritz-notes-rmail` |
| log file | the service name | `/tmp/rmail-home-ritz-notes-rmail.log` |
| generated unit | the service name | `rmail-home-ritz-notes-rmail.service` |

Everything a mailbox needs is inside it, so nothing has to be derived to keep
two mailboxes apart — two directories are already two directories. The service
name is the exception, and only because service names genuinely do share one
namespace per machine. Pass `--service-name=NAME` if you want something
shorter than the derived one.

Before writing anything, the installer reports whether the service name it is
about to use already belongs to a different mailbox, and refuses if so. It
does not look at your other mailboxes to do this, and it does not look at them
for anything else either — a mailbox knowing about its neighbours is what the
old shared config directory forced, and it is gone.

### What each instance needs, and what the installer does about it

1. **Its own config file** — derived from the mailbox path, so this is
   automatic.

2. **Its own port** — two daemons cannot share one. The installer checks the
   port you choose against every other mailbox on the machine and asks again
   on a collision.

3. **Its own identity name** — enforced as an error, not a warning. This one
   matters more than it looks. The daemon decides whether a message is for
   itself by comparing the recipient against its own identity, *before* any
   contacts lookup, so a name that is both your identity and a contact means
   two different things at once.

   The daemon now refuses that rather than picking. A `to:` line naming
   something that is both gets an `// AMBIGUOUS RECIPIENT` note written into
   the outbox file beside it, and the message stays where you left it,
   undelivered, until you rename one of the two. Before that refusal existed,
   the identity reading simply won: the message went into the sender's own
   inbox, was logged as delivered and marked satisfied, the contact never
   heard anything, and nothing reported an error.

4. **Its own mail directory** — `inbox/`, `outbox/`, `contacts` and `.state/`
   are all relative to the `mail` setting in its config.

### Starting a daemon by hand

The daemon takes one positional argument: the path to a config file.

```sh
lua /path/to/rmail/rmail.lua ~/mail/config
lua /path/to/rmail/rmail.lua ~/notes/rmail/config
```

There is no `--config` flag. Earlier versions of this document showed one, and
every command in this section failed as a result.

### Which mailbox the helper scripts talk to

The `config` symlink in the project root points at whichever mailbox was
installed first, and later installs leave it alone rather than repointing it.
Helper scripts run from the project root use that one. To reach another
mailbox, name its config file.

If both instances are behind the same router, each needs its own port forwarding
rule to direct traffic to each specific instance — see the Ports section in
README.md.
