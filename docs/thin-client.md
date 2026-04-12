# Thin client setup

The thin client keeps a local mailbox directory in sync with your home
rmail daemon. You read and write message files with whatever tools you
already use — vim, nano, VS Code, Notepad, cat, anything. The client
handles syncing in the background.

This is designed for laptops and desktops that can't run their own rmail
daemon reliably (changing IPs, no port forwarding, sleeping machines).
Your home daemon stays the authoritative source — the thin client is
just a window into it.

---

## How it works

```
Home daemon (always-on, static IP, port-forwarded)
    ~/mail/inbox/      ← contacts deliver messages here
    ~/mail/outbox/     ← daemon delivers these to contacts
    ~/mail/contacts    ← who you talk to

         ↕ AES-256-GCM encrypted TCP

Thin client (laptop, coffee shop, anywhere)
    ~/mail-remote/inbox/      ← copies appear here
    ~/mail-remote/outbox/     ← write a file here to send it
    ~/mail-remote/contacts    ← edit here, changes push home
```

The sync cycle runs on two triggers:

- **File change** — you save an outbox file or edit contacts, the client
  detects it immediately (via inotify on Linux, kqueue on macOS,
  ReadDirectoryChangesW on Windows) and syncs within seconds.
- **Interval timer** — every 5 minutes (configurable), the client checks
  the home daemon for new inbox messages, since the daemon can't push to
  you.

Between syncs, the client sleeps — zero CPU usage.

---

## Prerequisites

You need an rmail daemon running on a home computer with:

- A public IP address (or a hostname that resolves to one)
- Port forwarding configured for the rmail port
- A device entry in the contacts file with `own = true`:
  ```
  mylaptop.token = "your-shared-secret"
  mylaptop.own   = true
  ```

See the main [README](../README.md) for daemon setup.

---

## Installation

### Linux

```sh
cd clients/linux
./install.sh
```

The install script checks for each dependency (Lua, OpenSSL, etc.) and
offers to build anything missing from source. You only need a C compiler
(`gcc` or `cc`) — everything else is downloaded and compiled locally.

If you don't have a C compiler:
- Debian/Ubuntu: `sudo apt install build-essential`
- Fedora: `sudo dnf install gcc`
- Arch: `sudo pacman -S gcc`
- NixOS: `nix-shell -p gcc`

### macOS

```sh
cd clients/macos
./install.sh
```

Requires Xcode Command Line Tools (provides `clang`):
```sh
xcode-select --install
```

OpenSSL is needed for encryption. macOS ships LibreSSL which may not have
the right headers. If the install script can't find OpenSSL, it will offer
to build it from source, or you can install it via Homebrew first:
```sh
brew install openssl lua
```

### Windows

```cmd
cd clients\windows
install.bat
```

Requires MinGW (provides `gcc`). Install via:
- [mingw-w64.org](https://www.mingw-w64.org/)
- Or: `winget install mingw`

OpenSSL for Windows:
- `winget install OpenSSL`
- Or download from [slproweb.com](https://slproweb.com/products/Win32OpenSSL.html)

If OpenSSL is installed but the script can't find it, set the path:
```cmd
set OPENSSL_DIR=C:\Program Files\OpenSSL-Win64
install.bat
```

The install script runs from `cmd.exe` — no PowerShell required.

---

## Usage

### Start the client

**Linux / macOS:**
```sh
./run.sh --host YOUR_HOME_IP --port 8025 --token YOUR_TOKEN
```

**Windows:**
```cmd
run.bat --host YOUR_HOME_IP --port 8025 --token YOUR_TOKEN
```

Or run interactively (prompts for host, port, token):
```sh
./run.sh
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | (required) | Home daemon IP or hostname |
| `--port` | 8025 | Home daemon port |
| `--token` | (required) | Device token (must match contacts file on home) |
| `--dir` | `~/mail-remote` | Local mailbox directory |
| `--interval` | 300 | Seconds between sync cycles (for incoming mail) |

### Read messages

Messages appear in `~/mail-remote/inbox/`. Read them with anything:
```sh
ls ~/mail-remote/inbox/
cat ~/mail-remote/inbox/hello-from-alice.txt
```

### Send a message

Write a file to `~/mail-remote/outbox/`:
```sh
cat > ~/mail-remote/outbox/hello.txt << 'EOF'
to: alice

Hey, this is a message from my laptop.
EOF
```

The client detects the new file and syncs it to your home daemon, which
delivers it to alice on the next sync cycle.

### Edit contacts

```sh
vim ~/mail-remote/contacts
```

Changes sync back to the home daemon automatically.

---

## Running as a service

To keep the client running in the background:

### Linux (systemd)

```ini
# ~/.config/systemd/user/rmail-client.service
[Unit]
Description=rmail thin client
After=network.target

[Service]
Type=simple
ExecStart=/path/to/clients/linux/run.sh --host YOUR_IP --port 8025 --token YOUR_TOKEN
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now rmail-client
```

### macOS (launchd)

```xml
<!-- ~/Library/LaunchAgents/com.rmail.client.plist -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rmail.client</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/clients/macos/run.sh</string>
        <string>--host</string>
        <string>YOUR_IP</string>
        <string>--port</string>
        <string>8025</string>
        <string>--token</string>
        <string>YOUR_TOKEN</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

```sh
launchctl load ~/Library/LaunchAgents/com.rmail.client.plist
```

### Windows (Task Scheduler)

1. Open Task Scheduler (`taskschd.msc`)
2. Create Basic Task: "rmail thin client"
3. Trigger: "When I log on"
4. Action: Start a program
   - Program: `C:\path\to\clients\windows\run.bat`
   - Arguments: `--host YOUR_IP --port 8025 --token YOUR_TOKEN`
5. Check "Open the Properties dialog" and set:
   - "Run whether user is logged on or not" (optional)
   - Under Settings: "If the task fails, restart every 1 minute"

---

## Troubleshooting

### "connection failed"

- Is the home daemon running? Check with `systemctl status rmail` on the
  home machine.
- Is the port forwarded? See [android-instructions.md](android-instructions.md)
  troubleshooting section — the same network checks apply.
- Is the token correct? Must match exactly (case-sensitive) between the
  client's `--token` and the contacts file entry on the home daemon.

### "decryption failed"

Wrong token. The token you pass to the client must match the `token` field
in the home daemon's contacts file for your device entry.

### "sync error" but connection works

Check the home daemon's logs (`tail -f /tmp/rmail.log`). The daemon logs
all API requests with status codes.

### No file watcher (interval-only sync)

If the install script couldn't build the platform watcher (inotify/kqueue/
ReadDirectoryChangesW), the client falls back to interval-only sync.
Outbox changes won't be detected immediately — they'll sync on the next
interval tick. Re-run `install.sh --force` to retry building the watcher.
