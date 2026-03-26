# Android app setup

This guide walks you through installing the rmail Android app and connecting
it to your home server. No app store account is required — you build the app
from source and install it directly.

---

## Vocabulary

Some terms you'll see in this guide and in the app:

| Term | What it means |
|------|--------------|
| **daemon** | The rmail program running on your home computer. It runs in the background and handles sending and receiving messages. Also called the "home server." |
| **mailbox** | A directory on your home computer containing your inbox, outbox, contacts, and attachments. Each daemon manages one mailbox. |
| **token** | A shared secret (like a password) that two rmail users agree on. It's used to encrypt all communication between them. Each contact pair has a unique token. |
| **contacts file** | A text file listing the people you communicate with, along with their IP addresses, ports, and tokens. |
| **own device** | A contacts entry with `own = true` — this marks the entry as one of your own devices (like your phone) rather than another person. Own devices can sync with the daemon. |
| **port** | A number (like 8025) that identifies which program on a computer should receive incoming network traffic. Think of the IP address as the street address and the port as the apartment number. |
| **port forwarding** | A setting on your router that says "when traffic arrives on this port, send it to this specific computer on the local network." Required for anyone outside your home to reach your daemon. |
| **public IP** | Your router's address on the internet. This is what your contacts put in their contacts file. Everyone on your home network shares the same public IP. |
| **LAN IP** / **local IP** | Your computer's address on your home network (usually starts with 192.168). Only visible to devices on the same network. |

---

## Prerequisites

Before setting up the Android app, you need:

1. **A working rmail daemon** on a home computer. Follow the main
   [README](../README.md) to install and configure it.
2. **Your home computer's public IP address.** You can find this by running any
   of these commands on the home computer:
   ```
   curl -s ifconfig.me
   curl -s icanhazip.com
   ```
   Or just search "what is my IP" in a web browser on that network.
3. **The port** your daemon listens on. Check your config file — it's the
   `port = NNNN` line.
4. **A device token.** Pick a token for your phone (a series of words separated
   by dashes works well, like `pineapple-rocket-tuesday-blanket`), then add it
   to the contacts file on your home computer:
   ```
   myphone.token = "pineapple-rocket-tuesday-blanket"
   myphone.own   = true
   ```
   The `own = true` part is important — it tells the daemon this is your device,
   not another person.

   You can have whatever you want as the `myphone` name. If you have multiple
   android devices, they'll each need a unique name.

---

## Installing the app

The app is not on the Play Store or F-Droid (yet). You build it from source
and install it over USB.

### What you need

- A computer with **Git** and **Java 17+** installed (the Android build tool
  needs Java).

-- you can install these dependencies by running the install script with the --android-deps flag.
   todo...

- An **Android phone** with USB debugging enabled.
- A **USB cable** to connect the phone to the computer.

### Enable USB debugging on your phone

1. Open **Settings > About phone**.
2. Tap **Build number** seven times. You'll see "You are now a developer."
3. Go back to **Settings > System > Developer options** (location varies by
   phone manufacturer — search "developer" in Settings if you can't find it).
4. Enable **USB debugging**.
5. When you plug in the USB cable and the computer tries to connect, your phone
   will ask "Allow USB debugging?" — tap **Allow**.

### Build and install

```sh
git clone https://github.com/gabrilend/r-mail.git
cd r-mail
./scripts/compile-android.sh
```

This compiles the app and installs it on your connected phone.

If you have multiple phones connected, specify which one:

```sh
./scripts/compile-android.sh --push -s YOUR_DEVICE_SERIAL
```

You can find your device serial with:

```sh
adb devices
```

### F-Droid

F-Droid support is a work in progress. Once available, you'll be able to
install directly from the F-Droid app store without building from source.

---

## Connecting to your home server

Open the rmail app. If this is your first time, you'll see the setup screen.
If you've already set up a mailbox, tap the **+** button on the mailbox list
screen to add another one. Or don't, your loss.

### Fill in the connection details

1. **Home router IP** — Your home router's public IP address (the one your
   contacts use to reach you). If your phone is currently on the same WiFi as
   your home server, the app will try to detect this automatically.

2. **Device token** — The token you added to the contacts file on your home
   computer in the `myphone.token = "..."` line. Type it exactly as it appears
   (without the quotes — the app adds those).

3. **Port** — The port your daemon listens on. If you don't remember it, tap
   **Detect port**. This scans for your daemon using the token you entered.
   Detection only works when your phone is on the same WiFi network as your
   home server.

4. Tap **Connect**.

The app will sync with your home server and the mailbox name will appear
automatically (it comes from the `name = ...` line in your daemon's config
file).

### Finding your router's IP

If you're not sure what your public IP is:

- **From the home computer:** Run `curl -s ifconfig.me` in a terminal.
- **From your phone (on the same WiFi):** The setup screen shows "Your
  router's public IP" in the Network Info section at the bottom.
- **From any browser on the home network:** Search "what is my IP" — the first
  result is your public IP.

### Finding your port

Your port is in the rmail config file on the home computer. To find it, run
this command (it searches for the line starting with "port" and prints it):

```sh
grep '^port' ~/.config/rmail/config-*
```

Or look at the output from when you ran `scripts/install.sh` — it prints your
port at the end.

If you can't find it, just use the **Detect port** button in the app (make
sure your phone is on the same WiFi).

If you can't connect and you think it's a port issue, make sure you've
correctly forwarded the port from your router to your computer, and that you've
opened the port in your operating system's firewall. See the
[Troubleshooting](#troubleshooting) section below.

---

## Using the app

### Mailbox list

The first screen shows your configured mailboxes. Tap one to open it.

- **+** (top right) — add a new mailbox.
- **Three dots** on each mailbox — shows connection details (host, port, ID).

### Inbox / Outbox / Files

The main screen has three tabs at the bottom:

- **Inbox** — messages you've received.
- **Outbox** — messages you've sent (or are sending).
- **Files** — attachments on your home server. Tap to download to your android.

The top bar has:

- **Back arrow** (left) — return to the mailbox list.
- **Sync button** (right) — manually trigger a sync. The spinning icon means
  a sync is in progress.
- **Three-dot menu** (right) — access Contacts and Settings.

### Composing a message

Tap the **pencil button** (floating, above the tabs) to compose.

- **To** — select a recipient from the dropdown (populated from your contacts
  file). Tap **+** to add more recipients.
- **Attachments** — tap **+** to attach a file. Image attachments show a
  thumbnail preview.
- **Subject** — optional. Becomes the filename in the recipient's inbox.
- **Message body** — the main text. When you tap here, the header fields
  scroll away to give you more space. Press the Android back button to dismiss
  the keyboard and see the headers again.

Tap the **send arrow** to send. The app saves immediately and navigates to
your outbox. Attachments upload in the background.

### Contacts

The contacts screen shows your contacts file and lets you edit it (when
connected). Your public address is shown at the top for reference when giving
your details to a new contact.

If you're not connected to your home server, the contacts file is read-only.
An **(i)** button appears offering to compose a message to yourself with the
new contact details — you can update the contacts file from your computer
later.

If you have multiple mailboxes (home server daemons), they will each have
their own config and contacts files. You can switch mailboxes in the android
app if you want to.

---

## Troubleshooting

Work through these in order — each step rules out a category of problems.

### 1. Is the daemon running?

On the home computer, check if the rmail process is running:

```sh
# systemd (most Linux distros, NixOS)
systemctl status rmail

# runit (Void Linux, some Alpine setups)
sv status rmail

# OpenRC (Alpine Linux, Gentoo)
rc-service rmail status

# manual check (works everywhere)
ps aux | grep rmail
```

If it's not running, start it. Check the logs for errors.

### 2. Is the phone on the internet?

Open a web browser on your phone and load any website. If that doesn't work,
fix your network connection first, you silly goose.

### 3. Can the phone reach the home server?

Open a browser on your phone and go to:

```
http://YOUR_PUBLIC_IP:YOUR_PORT/
```

For example: `http://184.3.201.206:8025/`

You should see something like `{"ok":true,"name":"yourname"}`. If you see
this, the connection works.

**If it times out or refuses to connect:**

- **Is the port forwarded?** Log into your router's admin panel. To find it,
  run this on any computer on the network:
  ```sh
  ip route show default | awk '{print $3}'
  ```
  That prints your router's address — open it in a browser. The username and
  password are usually on a sticker on the bottom of the router. Once logged
  in, look for "port forwarding" in the settings and make sure your rmail port
  is forwarded to the home computer's local IP.

  If I were you, I'd change the default username and password, and replace the
  sticker with a post-it that has random gibberish on it so you need to factory
  reset your router anytime you want to change something.

- **Is the firewall open?** On the home computer:
  ```sh
  # Check which firewall you have:
  which ufw && echo "you have ufw" || \
  which nft && echo "you have nftables" || \
  which iptables && echo "you have iptables"

  # Then open the port:
  sudo ufw allow YOUR_PORT/tcp                                    # ufw
  sudo nft add rule inet filter input tcp dport YOUR_PORT accept  # nftables
  sudo iptables -A INPUT -p tcp --dport YOUR_PORT -j ACCEPT       # iptables
  ```

- **Are you on mobile data?** Port forwarding issues often only appear from
  outside the home network. If you're on WiFi at home, try switching to
  mobile data to test the external path.

### 4. Is the token correct?

The token in the app must exactly match the token in the contacts file on the
home server. Check both:

- **On the phone:** Settings > Device token.
- **On the server:** `grep myphone ~/mail/contacts` (replace `myphone` with
  whatever you named the entry).

The token is case-sensitive. Make sure there are no extra spaces.

### 5. Is `own = true` set?

Your device's contacts entry must have `own = true`. Without this, the daemon
rejects API requests from the phone with a 403 error. Check:

```sh
grep -A1 myphone ~/mail/contacts
```

You should see both `token` and `own` lines.

"own" doesn't have to be in quotes. Neither does "true". It's pretty weird
that "true" and "false" aren't words, isn't it? This is because "true" is
actually 1 and "false" is actually 0. Sometimes this is true, but not
always — sometimes it's false. "GET OUTTA HERE" yeah okay. :)

### 6. Sync says "error" but no details?

The sync error appears briefly in a red bar at the top of the inbox screen.
Common causes:

- **"Decryption failed"** — wrong token. See step 4.
- **Network timeout** — the daemon is unreachable. See step 3.
- **"Not configured"** — the mailbox setup isn't complete. Go to Settings and
  verify host, port, and token are filled in.

### 7. Contacts file is empty?

The contacts file syncs from the home server. If it's empty:

- Make sure the home server's contacts file has entries.
- Wait for a sync cycle (tap the refresh button).
- Check that the daemon is running the latest code (the contacts-in-sync-
  response feature requires the updated rmail.lua. Which update? I dunno,
  probably the most recent one.)

### 8. Messages aren't sending?

- Check that the recipient is in your contacts file with the correct IP, port,
  and token.
- Check that the recipient's daemon is running and reachable (see step 3, but
  for their IP/port).
- Check that port forwarding is set up on the recipient's router.
- Look at the daemon logs on your home server for errors:
  ```sh
  journalctl -u rmail -f                  # systemd
  tail -f /var/log/rmail/current          # runit
  tail -f /var/log/rmail.log              # OpenRC
  ```

### 9. Detect port doesn't find anything?

The port scanner only works when your phone is on the **same WiFi network** as
the home server. It probes the local network directly, avoiding router issues.

If it still doesn't find anything:
- Double-check that the daemon is running (step 1).
- Make sure the token you entered matches exactly (step 4).
- Try entering the port manually — you can find it in the config file on the
  home computer.
