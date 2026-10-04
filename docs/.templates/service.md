# Running rmail as a service

rmail only sends and receives messages while the daemon is running. If you close
your terminal or log out, the daemon stops and your outbox won't be delivered
until you start it again. Setting it up as a service means it starts automatically
and stays running in the background.

`install.sh` detects your init system and offers to set this up automatically.
The manual formats are below. A copy of this guide built by the installer shows
only your machine's service manager; `docs/.templates/service.md` in the
repository has all four.

Each example below is the installer's own template
(`scripts/.templates/services/`), filled in with example values by
`scripts/fill-guide-examples.lua` — so it is exactly the file the installer
would write. In a copy of this guide built by the installer, the paths are
already your real ones. What each value is:

**`/home/you/programs/email`** — the directory you cloned the code into. One
checkout serves every mailbox on the machine; there is no per-mailbox copy of
the daemon. Which mailbox a given daemon serves is decided entirely by its
second argument.

**`/home/you/programs/email/deps/lua/bin/lua`** — the Lua the installer
compiled, inside the checkout; or your system's Lua (`which lua`).

**`/home/you/mail`** — the mailbox this service serves. `config` inside it is
what the daemon is handed, and the mailbox served is the directory that file
sits in. The argument is not optional: a daemon started without it stops with
a usage message, because a machine can hold several mailboxes and there is
nothing sensible to assume.

**`YOURUSER`** — the user the daemon runs as, and whose mailbox it is.

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

<!-- {{{ manager: systemd -->
## systemd

systemd offers two modes:

- **User service** — runs as your user, starts on login, no root required.
  Survives logout if you enable lingering (`loginctl enable-linger`). Good for
  single-user machines or when you don't have root.
- **System service** — runs at boot regardless of who's logged in. Requires
  root to install. Better for shared machines or headless servers where no one
  logs in interactively.

### User service

`~/.config/systemd/user/SERVICE-NAME.service`:

<!-- {{{ example: systemd-user.service -->
```ini
[Unit]
Description=rmail messaging daemon (/home/you/mail)
After=network.target

[Service]
Type=simple
ExecStart=/home/you/programs/email/deps/lua/bin/lua /home/you/programs/email/rmail.lua /home/you/mail/config
Restart=on-failure
RestartSec=5
StandardOutput=append:/tmp/SERVICE-NAME.log
StandardError=append:/tmp/SERVICE-NAME.log

[Install]
WantedBy=default.target
```
<!-- }}} example -->

```sh
systemctl --user daemon-reload
systemctl --user enable --now SERVICE-NAME
tail -f /tmp/SERVICE-NAME.log
# to keep running after logout:
loginctl enable-linger
```

### System service

`/etc/systemd/system/SERVICE-NAME.service`:

<!-- {{{ example: systemd-system.service -->
```ini
[Unit]
Description=rmail messaging daemon (/home/you/mail)
After=network.target

[Service]
Type=simple
User=YOURUSER
ExecStart=/home/you/programs/email/deps/lua/bin/lua /home/you/programs/email/rmail.lua /home/you/mail/config
Restart=on-failure
RestartSec=5
StandardOutput=append:/tmp/SERVICE-NAME.log
StandardError=append:/tmp/SERVICE-NAME.log

[Install]
WantedBy=multi-user.target
```
<!-- }}} example -->

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now SERVICE-NAME
tail -f /tmp/SERVICE-NAME.log
```

---
<!-- }}} manager: systemd -->

<!-- {{{ manager: runit -->
## runit

`/etc/sv/SERVICE-NAME/run` (the installer writes it as `SERVICE-NAME-run` in
the checkout):

<!-- {{{ example: runit-run -->
```sh
#!/bin/sh
# rmail runit service for the mailbox at /home/you/mail
# Logs go to RAM-backed /tmp: no disk wear, gone on reboot.
export HOME=/home/YOURUSER
exec chpst -u YOURUSER /home/you/programs/email/deps/lua/bin/lua /home/you/programs/email/rmail.lua /home/you/mail/config >>/tmp/SERVICE-NAME.log 2>&1
```
<!-- }}} example -->

```sh
sudo mkdir -p /etc/sv/SERVICE-NAME
sudo cp SERVICE-NAME-run /etc/sv/SERVICE-NAME/run
sudo chmod +x /etc/sv/SERVICE-NAME/run
sudo ln -s /etc/sv/SERVICE-NAME /var/service/
```

Logs: `tail -f /tmp/SERVICE-NAME.log` or `./scripts/view-logs.sh`

---
<!-- }}} manager: runit -->

<!-- {{{ manager: openrc -->
## OpenRC

`/etc/init.d/SERVICE-NAME` (the installer writes it as `SERVICE-NAME-init` in
the checkout):

<!-- {{{ example: openrc-init -->
```sh
#!/sbin/openrc-run
# rmail openrc service for the mailbox at /home/you/mail
# Logs to RAM-backed /tmp.

description="rmail messaging daemon (/home/you/mail)"
command="/home/you/programs/email/deps/lua/bin/lua"
command_args="/home/you/programs/email/rmail.lua /home/you/mail/config"
command_user="YOURUSER"
command_background=true
pidfile="/run/SERVICE-NAME.pid"
output_log="/tmp/SERVICE-NAME.log"
error_log="/tmp/SERVICE-NAME.log"
```
<!-- }}} example -->

```sh
sudo cp SERVICE-NAME-init /etc/init.d/SERVICE-NAME
sudo chmod +x /etc/init.d/SERVICE-NAME
sudo rc-update add SERVICE-NAME default
sudo rc-service SERVICE-NAME start
```

Logs: `tail -f /tmp/SERVICE-NAME.log` or `./scripts/view-logs.sh`

---
<!-- }}} manager: openrc -->

<!-- {{{ manager: nixos -->
## NixOS

NixOS uses systemd internally but service files placed in `/etc/systemd/system/`
are overwritten on every `nixos-rebuild`. Instead, `install.sh` generates a
`SERVICE-NAME.nix` file that defines the service declaratively. When you use
the system's Lua it looks like this:

<!-- {{{ example: nixos-system-lua.nix -->
```nix
{ config, pkgs, ... }:
# rmail NixOS service for the mailbox at /home/you/mail
# Logs to RAM-backed /tmp. One service per mailbox; the name carries the
# mailbox path so a second mailbox adds a service rather than replacing this.

let
  rmailPort = 8025;
in {
  networking.firewall.allowedTCPPorts = [ rmailPort ];

  systemd.services."SERVICE-NAME" = {
    description = "rmail messaging daemon (/home/you/mail)";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      Type = "simple";
      User = "YOURUSER";
      Group = "users";
      ExecStart = "${pkgs.lua5_4}/bin/lua /home/you/programs/email/rmail.lua /home/you/mail/config";
      Restart = "on-failure";
      RestartSec = 5;
      StandardOutput = "append:/tmp/SERVICE-NAME.log";
      StandardError = "append:/tmp/SERVICE-NAME.log";
    };
  };
}
```
<!-- }}} example -->

With a Lua the installer compiled, the first line is `{ config, ... }:` and
`ExecStart` names that Lua by its path instead of `${pkgs.lua5_4}`
(`nixos-own-lua.nix`).

Use the auto-generated version — `<service name>.nix` in the project root,
e.g. `rmail-home-you-mail.nix` (see "Running multiple instances" for how the
service name is made); it has your paths and port pre-filled. The installer
prints the exact commands at the end; they are:

```sh
sudo cp rmail-home-you-mail.nix /etc/nixos/rmail-home-you-mail.nix
```

Add it to your imports in `/etc/nixos/configuration.nix`:

```nix
imports = [
  ./hardware-configuration.nix
  ./rmail-home-you-mail.nix
  # ... any other imports you have
];
```

Then rebuild, and follow the log — the service writes to a file in `/tmp`
named after the service, not to the journal:

```sh
sudo nixos-rebuild switch
tail -f /tmp/rmail-home-you-mail.log
```

The daemon also keeps its own rotating log in RAM,
`/tmp/rmail-progress/log-<mailbox path, slashes to dashes>` (5 MB plus one
older copy; the `log_file` setting moves it).

---
<!-- }}} manager: nixos -->

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
   are all inside the folder that holds its config file (#102: the mailbox is
   the installation; there is no `mail` setting any more).

### Restarting every mailbox after an update

One checkout serves every mailbox, so updating the checkout updates them all —
but only once each is restarted. A running daemon keeps the program it loaded
when it started.

```sh
/home/you/programs/email/restart-mailboxes.sh                # every listed mailbox
/home/you/programs/email/restart-mailboxes.sh kuvalu-notes   # just this one, this once
```

The list of service names sits at the top of that script, and belongs to this
machine: the script is built by the installer from
`scripts/.templates/restart-mailboxes.sh`, for this machine's service manager
only, and git ignores it. Each time the installer sets up a mailbox's service
it adds that name to the list (`restart-mailboxes.sh --add NAME` does the same
by hand). Run with the list empty, it asks for each mailbox's service name (one
per line, a blank line to finish) and saves them into the script.

Re-running the installer is how rmail is updated, so its last step offers to
restart every listed mailbox (`--restart-mailboxes` / `--no-restart-mailboxes`
answer it in advance). It is not offered while a listed service is not yet
installed — on runit, OpenRC, NixOS and a systemd system service, a service
the installer writes is installed by the commands it prints for you to run.
`restart-mailboxes.sh --check` asks the same question by hand. Every name is checked before anything is restarted, and each
service is checked to be running afterwards. Restarting a runit, OpenRC,
NixOS or systemd system service goes through `sudo`; a systemd user service
does not need it.

To rebuild it (say, after changing service manager):
`scripts/make-restart-script.sh --force <runit|systemd|openrc|nixos>`. That
empties the list.

### Starting a daemon by hand

The daemon takes one positional argument: the path to a config file.

```sh
lua /path/to/rmail/rmail.lua ~/mail/config
lua /path/to/rmail/rmail.lua ~/notes/rmail/config
```

There is no `--config` flag. Earlier versions of this document showed one, and
every command in this section failed as a result.

### Which mailbox the helper scripts talk to

There is no default mailbox: the installer makes no `config` link in the
project root. Name the mailbox (or its config or contacts file) when you run a
helper script, e.g. `helpers/rfield.sh ~/notes/rmail/contacts alice phone` or
`scripts/validate-router-settings.sh ~/notes/rmail`.

If both instances are behind the same router, each needs its own port forwarding
rule to direct traffic to each specific instance — see the Ports section in
README.md.
