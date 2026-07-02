# QA Tester Guide

Welcome.  This guide walks you through testing rmail — an encrypted,
file-based messaging system — one task at a time.  You don't need to
know the codebase, and you don't need to have used rmail before.
You'll set up the program once, then work through a series of
**walkthroughs**: each walkthrough is a short user journey ("try
sending a message", "try replying", "try sending an attachment") with
step-by-step instructions, plus a list of things to *watch for* while
you're doing it.

Your job is: follow the steps, see what happens, and record whether
each observation matched what was expected.

---

## Who this guide is for

Someone comfortable at a Linux command line.  Specifically, you
should be able to:

- open a terminal and run commands
- edit a text file with your editor of choice (nano, vim, VS Code,
  whatever)
- read a small amount of log output and tell whether a line is
  present or absent
- install system packages through your distro's package manager
  (apt, dnf, pacman, nix — whichever your machine uses)

You do **not** need to read any source code, write code, or know any
programming language.

---

## What you'll be doing

For each walkthrough:

1. **Read the "What this checks" paragraph.** It tells you, in plain
   English, what rmail should do in the scenario you're about to
   test.
2. **Do the "Setup" steps** if any are listed (most walkthroughs
   piggyback on the one-time setup below and have none).
3. **Work through the tests in order.**  Each test has:
   - **What to do** — numbered steps, just follow them.
   - **What you should see** — a list of things that should happen
     as a result.  Each bullet you confirm becomes a tick in the
     results table.
   - A **results table** with one row per observation: Pass / Fail /
     Blocked / N/A, plus a notes field for anything weird you saw.
4. **Report anything unexpected** using the template at the bottom
   of this guide.  Even if "it worked", if something felt surprising
   or slow or confusing, that's worth writing down.

Take your time.  If a step is ambiguous, mark the whole test
**Blocked** with a note explaining which step tripped you up — that
feedback is itself useful.

---

## Prerequisites

You're already looking at this file, so you have the **rmail
repository**.  Good.

Beyond that, you'll need:

1. **A Linux box** (VM, desktop, laptop — any of them).  Tested on
   Arch, NixOS, and Void Linux.  Other distros *probably* work —
   if you run into something weird on a distro we haven't tested,
   that's itself worth reporting.
2. **A C compiler** and **`make`** — almost certainly already on
   your system.  Try `cc --version` and `make --version`; if both
   print a version, you're set.  If not, install whichever
   "build tools" package your distro ships (e.g. `base-devel` on
   Arch).
3. **`wget` or `curl`** — the installer uses whichever is present
   to fetch dependencies it can't find.  Again, almost certainly
   already installed.

Everything else rmail needs — Lua, OpenSSL, luasocket, dkjson,
zip/unzip, UPnP and NAT-PMP tools — is built automatically by the
installer you're about to run.  You should not need to install any
additional packages.

### Disk space

- **During install**: up to ~300 MB temporarily (build intermediates).
- **After install**: ~70 MB total.
  - `deps/` ~28 MB (compiled Lua + OpenSSL)
  - `libs/` ~13 MB (built Lua modules)
  - `.git/` ~13 MB (repository history)
  - Source + docs + issues ~5 MB
  - A test mailbox with no real mail: a few hundred KB.

### Time

About 30–45 minutes for the first-time setup (most of that is
waiting for the C builds), then ~15-30 min per walkthrough.

---

## One-time setup

You're going to create **two mailboxes on this single machine** so
you can send messages from one to the other and watch what happens
on each side.  Call them `alice` and `bob`.  This is a test setup
— don't use a real mailbox you care about.

### Step 1 — install rmail (interactive) for alice

From inside the rmail repo directory, run:

```sh
./scripts/install.sh
```

This is the **interactive** mode.  The installer asks you three
questions up front, then builds dependencies.  Answer the questions
like this:

- **Mail directory**: `~/rmail-test/alice`
- **Your own name**: `alice`
- **TCP port**: `54321`

Then it'll ask a series of yes/no questions about whether to
compile each dependency, whether to set up a system service, etc.
For this test setup, **say "no" when asked about "setup
service"** — you want to run both daemons by hand so you can
watch them.  For the other compile questions, the default is fine:
just hit Enter.

First-time install takes a few minutes on most machines.

**You should see**, near the end:

- a green `created config` line
- a line like `your rmail port: 54321`
- a line like `mailbox: /home/<you>/rmail-test/alice`

If the installer errors out with "no C compiler found" or similar,
install the missing dependency and re-run.  Re-runs are safe —
every phase checks what's already built and skips it.

### Step 2 — install rmail (scripted) for bob

Run the installer a second time for bob.  This time use the
scripted, non-interactive form — it's faster, and it shows you
how you might script an install later:

```sh
./scripts/install.sh --silent --yes \
    --mail-dir=$HOME/rmail-test/bob \
    --name=bob \
    --port=54322 \
    --no-setup-service
```

The dependencies were already built in step 1, so this run is much
faster — it just writes a second config file and creates bob's
mailbox directory.

After both runs:

- `~/rmail-test/alice/` and `~/rmail-test/bob/` both exist.
- Each has subdirectories `inbox/`, `outbox/`, `attachments/`, and
  `.state/`, plus a file called `contacts` and a file called
  `config`.
- `.state/` is a *hidden* directory (leading dot).  If you run
  `ls ~/rmail-test/alice/` it won't show up.  Use `ls -a
  ~/rmail-test/alice/` to see it.

### Step 3 — make alice and bob contacts of each other

Each mailbox has a `contacts` file that lists the people it can
talk to.  You need to add one contact line to each.

Open `~/rmail-test/alice/contacts` in your editor and **append** these
lines to the bottom:

```
bob.ip    = "127.0.0.1"
bob.port  = 54322
bob.token = "shared-secret-for-alice-and-bob"
```

Open `~/rmail-test/bob/contacts` in your editor and append:

```
alice.ip    = "127.0.0.1"
alice.port  = 54321
alice.token = "shared-secret-for-alice-and-bob"
```

The **token must be exactly the same string** in both files — it's
the shared password that lets alice and bob decrypt each other's
messages.  (In real use, two people would agree on a secret token
out of band — by voice, in person, whatever.  For testing, you pick
any string and use it on both sides.)

### Step 4 — start both daemons

You'll want two terminal windows side by side.  In **terminal 1**:

```sh
./run-rmail.sh $HOME/rmail-test/alice
```

In **terminal 2**:

```sh
./run-rmail.sh $HOME/rmail-test/bob
```

Each terminal now shows alice's or bob's daemon output.  Leave them
running for the duration of testing.

**You should see**, in each terminal:

- a line like `listening on port 54321` (or 54322)
- a line like `outbox inotify watcher active`
- no red / error lines

If one of the terminals errors out about "address already in use",
another program is using that port — either stop that program, or
edit the config file (`~/rmail-test/alice/config` or bob's) to use
a different port, and update the corresponding contacts entry on
the other side.

### Step 5 — confirm: the daemons can reach each other

Each daemon's terminal should have logged `listening on port 54321`
(alice) and `listening on port 54322` (bob) during Step 4 — so the
simplest confirmation is: **both terminals showed that line and
neither reported an error.**

If you want a belt-and-braces network probe, here are three options,
pick whichever you have without installing anything:

```sh
# Option A: bash's built-in /dev/tcp (almost all bash installs have it)
(</dev/tcp/127.0.0.1/54321) && echo "alice reachable"
(</dev/tcp/127.0.0.1/54322) && echo "bob reachable"
```

```sh
# Option B: curl (almost always installed)
curl --silent --head --max-time 2 127.0.0.1:54321; echo "exit=$?"
curl --silent --head --max-time 2 127.0.0.1:54322; echo "exit=$?"
# exit=52 ("empty reply from server") is OK — the daemon refuses
# to speak plain HTTP, but it accepted the TCP connection.
# exit=7 ("couldn't connect") means the port isn't listening.
```

```sh
# Option C: if nc is already installed, one line covers both
nc -zv 127.0.0.1 54321 && nc -zv 127.0.0.1 54322
```

If none of those work, skip the probe — the daemon terminals' own
log lines from Step 4 are already confirmation.

You're now ready to walk through the tests.

---

## Glossary

Plain-English one-liners for terms you'll see throughout this guide.

- **Daemon** — the long-running rmail program that handles sending
  and receiving.  There's one daemon per mailbox.
- **Mailbox** — a directory on disk (e.g., `~/rmail-test/alice/`)
  that contains everything for one rmail identity: inbox, outbox,
  contacts, etc.
- **Inbox** — the subdirectory where received messages land as files.
- **Outbox** — the subdirectory where you drop files you want to
  send.  The daemon watches this directory and sends anything new.
- **Contact** — an entry in the `contacts` file; the info rmail
  needs to send mail to someone (their address, port, and a
  shared secret).
- **Token** — a shared secret between two rmail users.  Acts as
  the encryption key for messages between them.  Two users must
  have *the same* token in both of their contacts files to talk.
- **Sync** — one round of the daemon checking for mail to send and
  receive.  Happens automatically on a timer (every 10-30 s by
  default) and also immediately when you save a file in the outbox.
- **Hook** — a shell script the daemon runs when something happens
  (a message arrives, a message is sent, etc.).  Default hooks do
  nothing; the user can customise them.
- **Consent form** — when someone sends you an attachment, rmail
  first sends you a small file asking you to accept or deny the
  download.  You edit that file (or use a helper) to respond.
- **Port forwarding** — configuring your home router to let inbound
  rmail traffic reach your computer.  Needed for cross-internet use,
  not for same-box testing.

---

## How to report results

Each test below ends with a results table that looks like:

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Sender's terminal logs "sent X to bob" | ☐ | ☐ | ☐ | ☐ | |
| 2 | Recipient's inbox gains a new file | ☐ | ☐ | ☐ | ☐ | |

Fill it in as you go.  **Notes** is for anything weird — slower
than you expected, a message you didn't understand, a side-effect
you noticed.

At the end of your session, use the **Reporting template** at the
bottom of this guide to hand results back to the dev team.

---

## Walkthrough 1 — Send your first message

### What this checks

The most basic rmail operation: drop a file in the outbox, watch it
arrive in the other mailbox's inbox.  This exercises the daemon
startup, the outbox file-watcher, the network send, the receive
handler, and the filename-conflict rules all at once — if any of
those are broken, this walkthrough fails loudly.

### Setup for this walkthrough

None beyond the one-time setup above.  Both daemon terminals should
still be running.

### Test 1.1 — Send "hello" from alice to bob

**What to do:**

1. In your normal shell (not a daemon terminal), create a message
   file in alice's outbox:

   ```sh
   cat > ~/rmail-test/alice/outbox/hello <<'EOF'
   to: bob

   Hello, bob.  This is a test message.
   EOF
   ```

2. **Watch alice's daemon terminal** (the one running on port
   54321).  Within about 5-10 seconds, you should see log lines
   mentioning the file `hello` being sent.

3. **Watch bob's daemon terminal** (port 54322).  You should see
   log lines about receiving the message.

4. **Check bob's inbox**:

   ```sh
   ls ~/rmail-test/bob/inbox/
   cat ~/rmail-test/bob/inbox/hello
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Within ~10 s, alice's terminal logs something like `sent hello to bob` | ☐ | ☐ | ☐ | ☐ | |
| 2 | Within ~10 s, bob's terminal logs something like `received hello from alice` | ☐ | ☐ | ☐ | ☐ | |
| 3 | `ls ~/rmail-test/bob/inbox/` shows a file named `hello` | ☐ | ☐ | ☐ | ☐ | |
| 4 | The body of that file is exactly `Hello, bob.  This is a test message.` (the `to:` line is **not** included — it's a header, not part of the message) | ☐ | ☐ | ☐ | ☐ | |
| 5 | Alice's outbox still contains `hello` (sent files are not auto-deleted) | ☐ | ☐ | ☐ | ☐ | |
| 6 | No red or error lines appear in either daemon terminal during this test | ☐ | ☐ | ☐ | ☐ | |

### Test 1.2 — Spaces in the filename get converted to dashes

**What to do:**

1. Create another outbox file, this time with a space in the
   filename:

   ```sh
   cat > "$HOME/rmail-test/alice/outbox/hello world" <<'EOF'
   to: bob

   Second test: filename has a space.
   EOF
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | The filename `hello world` on alice's side is converted to `hello-world` (with dash) when bob receives it.  Check with `ls ~/rmail-test/bob/inbox/`. | ☐ | ☐ | ☐ | ☐ | |
| 2 | The body is `Second test: filename has a space.` | ☐ | ☐ | ☐ | ☐ | |
| 3 | No errors in either daemon terminal | ☐ | ☐ | ☐ | ☐ | |

### Covers checkboxes in q-a-tests.md

Walkthrough 1 contributes evidence for these ledger items (the dev
team will tick these based on your results):

- §3 "Outbox file watching" — the "saving a file triggers sync"
  bullet
- §1 "Daemon startup" — the startup and `outbox inotify watcher
  active` bullets

(Duplicate-filename-prevention testing lives in a later walkthrough
because it needs a more careful setup than Walkthrough 1 covers.)

---

## Walkthrough 2 — Respond, edit, and delete

### What this checks

Once messages can flow in one direction, the next question is
whether you can respond to them, edit a message you already sent
(and have the edit propagate), and clean up.  A delete on the
receiving side should tell the sender to stop retrying.

Note: rmail's daemon doesn't have any concept of "reply" as a
special kind of message — a reply is just another outgoing message.
The Android client has a "Reply" button that builds a new message
with `Re:` in the subject and the quoted original body, but when
you're testing the daemon directly (as you are here) you just write
the response file yourself.

### Setup for this walkthrough

You need a message from bob in alice's inbox.  If you don't already
have one, send one now:

```sh
cat > ~/rmail-test/bob/outbox/question <<'EOF'
to: alice

What's for dinner?
EOF
```

Wait ~10 s and confirm alice has it:

```sh
cat ~/rmail-test/alice/inbox/question
```

### Test 2.1 — Alice sends a response to bob

**What to do:**

1. Create a response in alice's outbox.  This test uses a multi-
   line body with a quote marker (`>`) to make sure those survive
   the round trip unchanged:

   ```sh
   cat > ~/rmail-test/alice/outbox/answer <<'EOF'
   to: bob

   Pasta.

   > you asked:
   > What's for dinner?
   EOF
   ```

2. Wait 10 s.  Check bob's inbox.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Bob's inbox has a file `answer` | ☐ | ☐ | ☐ | ☐ | |
| 2 | The body contains `Pasta.` as the first line | ☐ | ☐ | ☐ | ☐ | |
| 3 | The two `>`-prefixed lines survive unchanged | ☐ | ☐ | ☐ | ☐ | |
| 4 | No errors in either daemon terminal | ☐ | ☐ | ☐ | ☐ | |

### Test 2.2 — Alice edits her outbox copy, bob sees the edit

**What to do:**

1. Alice notices a typo in the message she just sent.  Open her
   outbox copy in any text editor and change `Pasta.` to `Pasta!`:

   ```sh
   # replace with your editor of choice — nano, vim, etc.
   nano ~/rmail-test/alice/outbox/answer
   ```

2. Save.  Wait ~30 s.

3. Re-read bob's inbox copy:

   ```sh
   cat ~/rmail-test/bob/inbox/answer
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's terminal logs something about re-sending / updating `answer` | ☐ | ☐ | ☐ | ☐ | |
| 2 | Bob's terminal logs something about receiving the update | ☐ | ☐ | ☐ | ☐ | |
| 3 | `cat ~/rmail-test/bob/inbox/answer` shows `Pasta!` (with the exclamation mark) on the first body line | ☐ | ☐ | ☐ | ☐ | |
| 4 | Bob's inbox still contains exactly one `answer` file (not two) | ☐ | ☐ | ☐ | ☐ | |

### Test 2.3 — Bob deletes the message; deletion propagates both ways

**What to do:**

1. From bob's side, delete the message you just received:

   ```sh
   rm ~/rmail-test/bob/inbox/answer
   ```

2. Watch both terminals.  The expectation is: bob's daemon notices
   the deletion, tells alice's daemon, and alice's daemon removes
   bob's `to:` line from her outbox copy.  Since bob was the only
   recipient, alice's outbox file has nothing left to send and gets
   cleaned up automatically.

3. Wait 30 s (roughly one retry window).

4. Check both mailboxes:

   ```sh
   ls ~/rmail-test/alice/outbox/
   ls ~/rmail-test/bob/inbox/
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's terminal logs something about bob deleting `answer` | ☐ | ☐ | ☐ | ☐ | |
| 2 | Alice's outbox **no longer contains** `answer` — with the only recipient removed, the file has no remaining work and is cleaned up | ☐ | ☐ | ☐ | ☐ | |
| 3 | Bob's inbox is empty (or at least, no `answer` file) | ☐ | ☐ | ☐ | ☐ | |
| 4 | After the 30 s retry window, no repeated "retry" / "send" log line about `answer` appears in either terminal | ☐ | ☐ | ☐ | ☐ | |

### Test 2.4 — After the delete, alice can send again cleanly

**What to do:**

1. Send a new message with the same filename:

   ```sh
   cat > ~/rmail-test/alice/outbox/answer <<'EOF'
   to: bob

   Second answer.
   EOF
   ```

2. Wait 10 s.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Bob's inbox gains a new `answer` file with body `Second answer.` | ☐ | ☐ | ☐ | ☐ | |
| 2 | No warning or error about a lingering state entry from the previous `answer` | ☐ | ☐ | ☐ | ☐ | |

### Test 2.5 — Alice deletes her outbox copy (sender-side delete)

**What to do:**

1. Delete alice's outbox copy:

   ```sh
   rm ~/rmail-test/alice/outbox/answer
   ```

2. Wait 30 s.

3. Check bob's inbox.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's terminal logs something about notifying bob of the deletion | ☐ | ☐ | ☐ | ☐ | |
| 2 | Bob's inbox no longer contains `answer` — the sender-side delete propagated | ☐ | ☐ | ☐ | ☐ | |
| 3 | Bob's terminal logs receipt of the deletion notification | ☐ | ☐ | ☐ | ☐ | |

### Covers checkboxes in q-a-tests.md

- §3 "Living messages — edits propagate (#306)" — bullets 1, 2, 3
- §3 "Delete/edit race conditions (#323)" — bullets 3, 4, 5

---

## Walkthrough 3 — Multiple recipients in one message

### What this checks

A single outbox file can list several recipients; each gets a copy.
Removing a recipient (editing out a `to:` line) should delete that
one person's copy without affecting the others.  Needs a third
mailbox to observe.

### Setup for this walkthrough

Spin up **carol** as a third mailbox on the same machine.  Same
pattern as alice and bob, different port:

```sh
./scripts/install.sh --silent --yes \
    --mail-dir=$HOME/rmail-test/carol \
    --name=carol \
    --port=54323 \
    --no-setup-service
```

Append to `~/rmail-test/alice/contacts`:

```
carol.ip    = "127.0.0.1"
carol.port  = 54323
carol.token = "shared-secret-for-alice-and-carol"
```

Append to `~/rmail-test/carol/contacts`:

```
alice.ip    = "127.0.0.1"
alice.port  = 54321
alice.token = "shared-secret-for-alice-and-carol"
```

In a **third** terminal, start carol's daemon:

```sh
./run-rmail.sh $HOME/rmail-test/carol
```

You now have three daemons running in three terminals.  Keep carol
running — she'll be useful for later walkthroughs too.

### Test 3.1 — Send one message to two recipients

**What to do:**

1. Create an outbox file with two `to:` lines:

   ```sh
   cat > ~/rmail-test/alice/outbox/team-update <<'EOF'
   to: bob
   to: carol

   Meeting at 3pm.
   EOF
   ```

2. Wait 10 s.  Check both recipients' inboxes:

   ```sh
   cat ~/rmail-test/bob/inbox/team-update
   cat ~/rmail-test/carol/inbox/team-update
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Bob's inbox contains `team-update` with body `Meeting at 3pm.` | ☐ | ☐ | ☐ | ☐ | |
| 2 | Carol's inbox contains `team-update` with the same body | ☐ | ☐ | ☐ | ☐ | |
| 3 | Alice's terminal logs one send to bob and one send to carol | ☐ | ☐ | ☐ | ☐ | |
| 4 | Alice's outbox file still has both `to:` lines intact | ☐ | ☐ | ☐ | ☐ | |

### Test 3.2 — Remove one recipient mid-conversation

**What to do:**

1. Edit alice's outbox file to remove the `to: carol` line.  The
   file should end up looking like:

   ```
   to: bob

   Meeting at 3pm.
   ```

2. Save.  Wait 30 s.

3. Check both recipients' inboxes.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's terminal logs something about notifying carol the message was removed | ☐ | ☐ | ☐ | ☐ | |
| 2 | Carol's inbox **no longer contains** `team-update` | ☐ | ☐ | ☐ | ☐ | |
| 3 | Bob's inbox **still contains** `team-update` (unchanged) | ☐ | ☐ | ☐ | ☐ | |
| 4 | Alice's outbox file still exists with only the `to: bob` line | ☐ | ☐ | ☐ | ☐ | |

### Test 3.3 — Receiver-side delete only affects that receiver

**What to do:**

1. Re-add carol as a recipient (put the `to: carol` line back in
   alice's outbox file and save).  Wait 10 s and confirm both
   bob and carol have `team-update` again.

2. Now have carol delete her copy:

   ```sh
   rm ~/rmail-test/carol/inbox/team-update
   ```

3. Wait 30 s.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's terminal logs carol's deletion | ☐ | ☐ | ☐ | ☐ | |
| 2 | Alice's outbox file now has only `to: bob` (carol's line removed automatically) | ☐ | ☐ | ☐ | ☐ | |
| 3 | Bob's inbox is unaffected | ☐ | ☐ | ☐ | ☐ | |

### Covers checkboxes in q-a-tests.md

- §3 "Outbox file watching" — third bullet (drain works)
- §3 "Living messages — edits propagate (#306)" — recipient-removal bullet
- §3 "Delete/edit race conditions (#323)" — receiver-delete bullets

---

## Walkthrough 4 — Duplicate filenames don't clobber each other

### What this checks

When the same filename shows up in a receiver's inbox a second time
(for example, alice sends `greeting`, then later sends another
`greeting` with different content), the daemon should **not**
overwrite the first.  Instead it appends a short disambiguation
suffix like `-<short-id>` to the second one.

### Setup for this walkthrough

Make sure walkthrough 2 and 3 are done (or at least that bob's and
alice's inboxes are clean — delete any leftover `answer`,
`team-update`, etc., so the walkthrough starts from a clean slate).

```sh
rm -f ~/rmail-test/alice/outbox/*
rm -f ~/rmail-test/bob/inbox/*
```

Wait ~30 s after these deletes so the daemons settle.

### Test 4.1 — Same sender, same subject twice → second gets a suffix

**What to do:**

1. Send the first `greeting`:

   ```sh
   cat > ~/rmail-test/alice/outbox/greeting <<'EOF'
   to: bob

   First one.
   EOF
   ```

2. Wait 10 s.  Confirm bob has `greeting` with body `First one.`

3. Delete alice's outbox copy so the next send is treated as a
   fresh message, not as an edit of the first:

   ```sh
   rm ~/rmail-test/alice/outbox/greeting
   ```

4. Wait 10 s.  Confirm alice's terminal logs the delete propagation
   and bob's `greeting` is gone.

5. Create a NEW outbox file, same filename, different body:

   ```sh
   cat > ~/rmail-test/alice/outbox/greeting <<'EOF'
   to: bob

   Second one.
   EOF
   ```

   Wait — but we just deleted the first and bob's inbox is also
   empty now.  For the duplicate-suffix test we need bob's inbox
   to still have the first `greeting` when the second arrives.
   So instead:

6. *Start over.*  Re-send the first `greeting`:

   ```sh
   cat > ~/rmail-test/alice/outbox/greeting <<'EOF'
   to: bob

   First one.
   EOF
   ```
   Wait 10 s.  Bob has `greeting`.

7. Move alice's outbox file **aside** (not delete — that would
   propagate), and then write a fresh file with the same name:

   ```sh
   mv ~/rmail-test/alice/outbox/greeting /tmp/greeting-stash
   # wait ~5 s for alice to notice the move (she'll treat it as a delete,
   # which tells bob to delete his copy)
   sleep 15
   # at this point bob's inbox/greeting is gone too.  now write a new one:
   cat > ~/rmail-test/alice/outbox/greeting <<'EOF'
   to: bob

   Second one.
   EOF
   ```

**What you should see:**

Because `mv` triggers the delete-propagation, the "duplicate
filename on bob's side" scenario is **hard to reproduce with just
alice and bob**.  The clean way to test the suffix behavior needs
either:
- two different senders (alice and carol) sending to bob with the
  same subject, OR
- a race where bob's inbox/greeting is still there when alice's
  second `greeting` arrives (requires precise timing).

**Mark the whole of Test 4.1 Blocked** and record that observation.
That's useful feedback for the dev team — it tells us this test
needs a more careful design, possibly with carol as the second
sender.

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Test 4.1 is blocked by the bidirectional-delete behavior; reframe needed | ☐ | ☐ | ☐ | ☐ | |

### Test 4.2 — Two different senders, same subject → second gets a `-from-<sender>` suffix

**What to do:**

1. Alice sends `greeting` to bob:

   ```sh
   cat > ~/rmail-test/alice/outbox/greeting <<'EOF'
   to: bob

   Hi from alice.
   EOF
   ```
   Wait 10 s.

2. Confirm bob has `greeting` with body `Hi from alice.`

3. Carol sends her own `greeting` to bob.  (For this, bob needs to
   be a contact of carol's.  If you didn't set that up in
   walkthrough 3, do it now: append to `~/rmail-test/carol/contacts`:
   ```
   bob.ip    = "127.0.0.1"
   bob.port  = 54322
   bob.token = "shared-secret-for-bob-and-carol"
   ```
   And append the matching line to `~/rmail-test/bob/contacts`.)

   Then:

   ```sh
   cat > ~/rmail-test/carol/outbox/greeting <<'EOF'
   to: bob

   Hi from carol.
   EOF
   ```
   Wait 10 s.

4. Check bob's inbox.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Bob's inbox has **two** files: `greeting` and `greeting-from-carol` (or similar disambiguation suffix) | ☐ | ☐ | ☐ | ☐ | |
| 2 | `greeting` contains `Hi from alice.` | ☐ | ☐ | ☐ | ☐ | |
| 3 | `greeting-from-carol` (or whatever the suffixed name is) contains `Hi from carol.` | ☐ | ☐ | ☐ | ☐ | |
| 4 | No errors in any daemon terminal | ☐ | ☐ | ☐ | ☐ | |

### Covers checkboxes in q-a-tests.md

- §3 "Duplicate filename prevention (#315)" — different-senders bullet

---

## Walkthrough 5 — Attachments: the happy path

### What this checks

Attachments flow in three stages:

1. Sender adds an `attach:` line to an outbox file.
2. Receiver's daemon sees the attachment request and writes a
   **consent form** — a small file in the inbox asking the user
   whether to download this attachment.
3. User says yes (writes `accept` in the consent file).  The daemon
   then downloads the attachment in chunks and saves it to the
   receiver's `attachments/` directory.

This walkthrough exercises all three stages with a small file.

### Setup for this walkthrough

Create a small test file for alice to attach:

```sh
mkdir -p ~/rmail-test/attachments-source
echo "hello world" > ~/rmail-test/attachments-source/greeting.txt
```

### Test 5.1 — Send a tiny attachment end to end

**What to do:**

1. Send an outbox message with an attach line:

   ```sh
   cat > ~/rmail-test/alice/outbox/package <<EOF
   to: bob
   attach: $HOME/rmail-test/attachments-source/greeting.txt

   Here's a file.
   EOF
   ```

2. Wait 10-15 s.  Check bob's inbox:

   ```sh
   ls ~/rmail-test/bob/inbox/
   ```

   You should see a file named something like
   `consent-<something>` — that's the consent form.  Also a file
   named `package` with the body.

3. Open the consent file in your editor:

   ```sh
   cat ~/rmail-test/bob/inbox/consent-*
   ```

   You'll see two lines, one saying `accept` and one saying
   `deny`.  To accept the transfer, edit the file so only
   `accept` remains (delete the `deny` line):

   ```sh
   # replace the consent file's content with just "accept"
   for f in ~/rmail-test/bob/inbox/consent-*; do
       echo "accept" > "$f"
   done
   ```

4. Wait 15-30 s for the chunk transfer to complete.

5. Check bob's attachments directory:

   ```sh
   ls ~/rmail-test/bob/attachments/
   cat ~/rmail-test/bob/attachments/greeting.txt
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Bob's inbox initially contains both `package` (the message) and a `consent-…` file (the consent form) | ☐ | ☐ | ☐ | ☐ | |
| 2 | The consent form starts with both `accept` and `deny` lines | ☐ | ☐ | ☐ | ☐ | |
| 3 | After editing to `accept`, the daemon logs chunk-transfer progress | ☐ | ☐ | ☐ | ☐ | |
| 4 | After completion, the consent file is gone from bob's inbox | ☐ | ☐ | ☐ | ☐ | |
| 5 | `~/rmail-test/bob/attachments/greeting.txt` exists and contains `hello world` | ☐ | ☐ | ☐ | ☐ | |
| 6 | The `attach:` line is removed from alice's outbox `package` file (the daemon rewrites it after a successful transfer) | ☐ | ☐ | ☐ | ☐ | |
| 7 | No errors in either daemon terminal | ☐ | ☐ | ☐ | ☐ | |

### Test 5.2 — Deny a consent form

**What to do:**

1. Alice sends a second attachment:

   ```sh
   cat > ~/rmail-test/alice/outbox/package2 <<EOF
   to: bob
   attach: $HOME/rmail-test/attachments-source/greeting.txt

   Here's another file.
   EOF
   ```

2. Wait for the consent form to appear in bob's inbox, then edit
   it to `deny` (delete the `accept` line):

   ```sh
   for f in ~/rmail-test/bob/inbox/consent-*; do
       echo "deny" > "$f"
   done
   ```

3. Wait 15 s.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | The consent file disappears from bob's inbox after the deny propagates | ☐ | ☐ | ☐ | ☐ | |
| 2 | No new file appears in `~/rmail-test/bob/attachments/` for this transfer | ☐ | ☐ | ☐ | ☐ | |
| 3 | Alice's outbox `package2` file gets its `attach:` line removed (the transfer is over, even though it ended in a deny) | ☐ | ☐ | ☐ | ☐ | |
| 4 | No error loop in either terminal | ☐ | ☐ | ☐ | ☐ | |

### Covers checkboxes in q-a-tests.md

- §2 "raccept / rdeny helpers (#332)" — the consent-file behaviour
  bullets (manually exercised here; walkthrough 8 uses the helper
  scripts)
- §4 "Chunk handling (#202)"
- §5 "Oversized transfer rejection (#327)" — not the oversized
  bullet specifically, but the general chunk pipeline

---

## Walkthrough 6 — Attachments: edge cases

### What this checks

Three scenarios that break naive implementations:

- The sender references an attachment file that **doesn't exist**.
- The attach path contains a **glob wildcard** (`*`, `?`, `[…]`)
  that expands to multiple files.
- The message body itself is **larger than 128 KB**, which the
  daemon auto-converts into an attachment.

### Setup for this walkthrough

Make sure the attachments-source directory from walkthrough 5
exists.  Add a couple of extra files for the glob test:

```sh
echo "apple"  > ~/rmail-test/attachments-source/fruit-a.txt
echo "banana" > ~/rmail-test/attachments-source/fruit-b.txt
echo "cherry" > ~/rmail-test/attachments-source/fruit-c.txt
```

### Test 6.1 — Attach a file that doesn't exist

**What to do:**

1. Send a message with a bogus attach path:

   ```sh
   cat > ~/rmail-test/alice/outbox/broken <<EOF
   to: bob
   attach: $HOME/rmail-test/attachments-source/does-not-exist.txt

   Here's a file that doesn't exist.
   EOF
   ```

2. Wait 30 s.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's terminal logs a clear "file not found" / "missing attachment" style message naming the bad path | ☐ | ☐ | ☐ | ☐ | |
| 2 | Alice's outbox `broken` file gains a `// MISSING ATTACHMENT:` comment line under the bad `attach:` line (see issue #363) | ☐ | ☐ | ☐ | ☐ | |
| 3 | The message body still arrives at bob (bob's inbox has `broken` with body `Here's a file that doesn't exist.`) | ☐ | ☐ | ☐ | ☐ | |
| 4 | The daemon does **not** retry the missing attach every 30 s in a loop — the warning appears once (or a small number of times) then stops | ☐ | ☐ | ☐ | ☐ | |

**Note for tester**: if you see the daemon retrying the missing
attach endlessly, that's the bug described in issue #363 part (b)
— mark it Fail and report, but keep going.

### Test 6.2 — Glob expansion (`*.txt`)

**What to do:**

1. Send a message with a glob in the attach line:

   ```sh
   cat > ~/rmail-test/alice/outbox/fruit-basket <<EOF
   to: bob
   attach: $HOME/rmail-test/attachments-source/fruit-*.txt

   Three fruits, one message.
   EOF
   ```

2. Wait 10 s.

3. Check alice's outbox file after the daemon processes it:

   ```sh
   cat ~/rmail-test/alice/outbox/fruit-basket
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's outbox file has been rewritten: the single `attach: .../fruit-*.txt` line is replaced by **three separate `attach:`** lines, one per matched file (sorted) | ☐ | ☐ | ☐ | ☐ | |
| 2 | Alice's terminal logs one "attach expanded" line showing the three matches | ☐ | ☐ | ☐ | ☐ | |
| 3 | Bob's inbox gets three consent forms (one per file) | ☐ | ☐ | ☐ | ☐ | |
| 4 | Accept all three (edit each consent file to `accept`); after completion, bob has all three files in `~/rmail-test/bob/attachments/` | ☐ | ☐ | ☐ | ☐ | |

### Test 6.3 — Glob that matches zero files

**What to do:**

1. Send a message with a glob that won't match anything:

   ```sh
   cat > ~/rmail-test/alice/outbox/no-match <<EOF
   to: bob
   attach: $HOME/rmail-test/attachments-source/nonexistent-*.xyz

   Glob with zero matches.
   EOF
   ```

2. Wait 30 s.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's terminal logs a single "attach: no files match …" warning | ☐ | ☐ | ☐ | ☐ | |
| 2 | The warning does NOT repeat on every subsequent sync cycle | ☐ | ☐ | ☐ | ☐ | |
| 3 | Alice's outbox file is **unchanged** — the glob line is left in place | ☐ | ☐ | ☐ | ☐ | |
| 4 | Bob still receives the message body | ☐ | ☐ | ☐ | ☐ | |

### Test 6.4 — Oversized body becomes an attachment automatically

**What to do:**

1. Generate a body larger than 128 KB:

   ```sh
   head -c 200000 /dev/urandom | base64 > ~/rmail-test/big-body-src.txt
   ```

2. Send it as the message body:

   ```sh
   {
     echo "to: bob"
     echo
     cat ~/rmail-test/big-body-src.txt
   } > ~/rmail-test/alice/outbox/big
   ```

3. Wait 15 s.  Bob should get a consent form for the auto-body.
   Accept it:

   ```sh
   for f in ~/rmail-test/bob/inbox/consent-*; do
       echo "accept" > "$f"
   done
   ```

4. Wait 30 s for the chunk transfer.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | Alice's terminal logs something about "oversized body" / "converting to attachment" / similar | ☐ | ☐ | ☐ | ☐ | |
| 2 | Bob's inbox gets a consent form (even though there's no `attach:` line — the body itself was converted) | ☐ | ☐ | ☐ | ☐ | |
| 3 | Bob's initial inbox/`big` file contains a stub message naming the attachment (something like `delivered as attachment big`) | ☐ | ☐ | ☐ | ☐ | |
| 4 | After accepting, `~/rmail-test/bob/attachments/big` exists and its contents match the base64 blob | ☐ | ☐ | ☐ | ☐ | |
| 5 | No errors | ☐ | ☐ | ☐ | ☐ | |

### Covers checkboxes in q-a-tests.md

- §4 "attach: paths (#101)"
- §4 "attach: glob expansion (#362)" — all the glob bullets
- §5 "Auto-body: oversized message bodies (#349)"
- §5 "list_files skips directories (#356)" — partial (the attach
  pipeline testing exercises the file-vs-dir discrimination)
- Issue #363 parts (b) and (c) — missing-file detection, quoted-
  path parsing

---

## Walkthrough 7 — Hooks fire when expected

### What this checks

rmail runs user-customisable shell scripts (*hooks*) at specific
points: when a message arrives, when one is sent, when one is
deleted, etc.  The default hooks do nothing.  This walkthrough
replaces a couple of them with one-liners that write to a log
file, then exercises those events.

### Setup for this walkthrough

Hooks live in `scripts/hooks/` in the rmail repo.  The config
points at them by absolute path.  Check alice's config:

```sh
grep 'on_receive' ~/.config/rmail/config-home-*-rmail-test-alice
```

You should see lines pointing at `.../scripts/hooks/on_receive.sh`
and `.../scripts/hooks/on_receive_raw.sh`.

**Important**: these hooks are **shared across all mailboxes** on
this machine because they live in the repo, not per-mailbox.  If
you edit one, it fires for alice AND bob AND carol.  For this
walkthrough that's fine — we're just logging events.

### Test 7.1 — on_receive fires on a delivered message

**What to do:**

1. Edit `scripts/hooks/on_receive.sh` in the rmail repo.  Replace
   its contents with:

   ```sh
   #!/bin/sh
   echo "on_receive fired: sender=$1 subject=$2 file=$3" >> /tmp/rmail-hook-test.log
   exit 0
   ```

2. Make sure it's executable: `chmod +x scripts/hooks/on_receive.sh`.

3. Clear the log: `rm -f /tmp/rmail-hook-test.log`.

4. Send a message from alice to bob:

   ```sh
   cat > ~/rmail-test/alice/outbox/hook-test <<'EOF'
   to: bob

   Hook test body.
   EOF
   ```

5. Wait 15 s.

6. Check the log:

   ```sh
   cat /tmp/rmail-hook-test.log
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | `/tmp/rmail-hook-test.log` exists and contains one line with `on_receive fired: …` | ☐ | ☐ | ☐ | ☐ | |
| 2 | The line includes `sender=alice subject=hook-test` and a path to bob's inbox file | ☐ | ☐ | ☐ | ☐ | |
| 3 | No errors in any daemon terminal | ☐ | ☐ | ☐ | ☐ | |

### Test 7.2 — on_send fires on outgoing message

**What to do:**

1. Similarly, edit `scripts/hooks/on_send.sh` to append to the log:

   ```sh
   #!/bin/sh
   echo "on_send fired: me=$1 to=$2 body=$3" >> /tmp/rmail-hook-test.log
   # on_send is expected to optionally transform the body; print $3 unchanged
   echo "$3"
   ```

2. `chmod +x scripts/hooks/on_send.sh`.

3. Send another message:

   ```sh
   cat > ~/rmail-test/alice/outbox/hook-test-2 <<'EOF'
   to: bob

   Second hook test.
   EOF
   ```

4. Wait 15 s.  Check the log.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | The log gains an `on_send fired: me=alice to=bob …` line | ☐ | ☐ | ☐ | ☐ | |
| 2 | Bob receives `hook-test-2` with the original body `Second hook test.` (the hook's echo `$3` preserved it) | ☐ | ☐ | ☐ | ☐ | |

### Test 7.3 — Disable a hook

**What to do:**

1. Open alice's config file and set `on_receive` to an empty
   string:

   ```
   on_receive = ""
   ```

   (Leave the other hook lines alone.)

2. Clear the log: `rm /tmp/rmail-hook-test.log`.

3. Send another message.  Wait 15 s.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | `/tmp/rmail-hook-test.log` exists and contains an `on_send fired` line (since on_send is still active) | ☐ | ☐ | ☐ | ☐ | |
| 2 | The log does **not** contain an `on_receive fired` line | ☐ | ☐ | ☐ | ☐ | |

### Cleanup

Restore the default hook scripts before moving on (otherwise they
keep firing during later walkthroughs):

```sh
cd <the rmail repo>
git checkout scripts/hooks/on_receive.sh scripts/hooks/on_send.sh
```

And put back the `on_receive` line in alice's config.

### Covers checkboxes in q-a-tests.md

- §2 "Hook config format (#325)" — all four bullets
- §3 "On_update hook (#306)" — partial (no update flow here; see
  walkthrough 2 for that)

---

## Walkthrough 8 — Helper scripts

### What this checks

`helpers/` contains small shell scripts users and hooks can call:

- `rto.sh <file> <recipient>...` — add `to:` lines to a message.
- `rattach.sh <file> <path>...` — add `attach:` lines.
- `raccept.sh <consent-file>` / `rdeny.sh <consent-file>` — respond
  to a consent form without opening it in an editor.
- `rfield.sh <contacts-file> <name> <field>` — read a named field
  from a contacts file.

### Setup for this walkthrough

The helpers live in `helpers/` in the repo.  Make sure they're
executable: `chmod +x helpers/*.sh`.

### Test 8.1 — rto adds recipients

**What to do:**

1. Create an empty outbox file (not in alice's real outbox — use
   a scratch location):

   ```sh
   : > /tmp/draft
   ```

2. Add two recipients with rto:

   ```sh
   helpers/rto.sh /tmp/draft alice
   helpers/rto.sh /tmp/draft bob carol
   cat /tmp/draft
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | `/tmp/draft` now contains three `to:` lines, in order: `to: alice`, `to: bob`, `to: carol` | ☐ | ☐ | ☐ | ☐ | |
| 2 | No extra lines / blank headers | ☐ | ☐ | ☐ | ☐ | |

### Test 8.2 — rattach adds attachments after the to: block

**What to do:**

1. Use the `/tmp/draft` from test 8.1.  Add a body line manually:

   ```sh
   printf '\nmessage body here\n' >> /tmp/draft
   ```

2. Run rattach to add an attach line:

   ```sh
   helpers/rattach.sh /tmp/draft /tmp/some-file.txt
   cat /tmp/draft
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | `/tmp/draft` has the three `to:` lines, then `attach: /tmp/some-file.txt`, then a blank line, then `message body here` | ☐ | ☐ | ☐ | ☐ | |
| 2 | The attach line appears **between** the `to:` block and the body — not prepended to the whole file, not appended past the body | ☐ | ☐ | ☐ | ☐ | |

### Test 8.3 — raccept / rdeny

**What to do:**

1. Send an attachment from alice to bob (see walkthrough 5).  Wait
   until the consent form appears in bob's inbox.

2. Accept it via the helper:

   ```sh
   helpers/raccept.sh ~/rmail-test/bob/inbox/consent-*
   ```

3. Wait 15 s.  Check that the transfer completed.

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | After running `raccept.sh`, the consent file contains only `accept` (no `deny` line) | ☐ | ☐ | ☐ | ☐ | |
| 2 | The daemon picks it up and completes the transfer | ☐ | ☐ | ☐ | ☐ | |
| 3 | Test the denial path similarly: send a second attachment, run `helpers/rdeny.sh <consent-file>`, verify the file ends up with only `deny` and the transfer does not complete | ☐ | ☐ | ☐ | ☐ | |

### Test 8.4 — rfield reads contact fields

**What to do:**

1. Read a field from alice's contacts file:

   ```sh
   helpers/rfield.sh ~/rmail-test/alice/contacts bob port
   # should print: 54322
   helpers/rfield.sh ~/rmail-test/alice/contacts bob token
   # should print the shared secret string (no quotes)
   helpers/rfield.sh ~/rmail-test/alice/contacts bob nonexistent
   # should print nothing and exit non-zero
   echo "exit: $?"
   ```

**What you should see:**

| # | Observation | Pass | Fail | Blocked | N/A | Notes |
|---|---|---|---|---|---|---|
| 1 | `port` → prints `54322` | ☐ | ☐ | ☐ | ☐ | |
| 2 | `token` → prints the shared-secret value, unquoted | ☐ | ☐ | ☐ | ☐ | |
| 3 | `nonexistent` → prints nothing, exits non-zero | ☐ | ☐ | ☐ | ☐ | |

### Covers checkboxes in q-a-tests.md

- §2 "Helper scripts (#326)" — both bullets
- §2 "rto / rattach helpers (#330, #331)" — all four bullets
- §2 "raccept / rdeny helpers (#332)" — all three bullets
- Issue #364 — rfield takes contacts file as first arg

---

## Walkthroughs to be added

The following walkthroughs are planned but not yet written.  If you
finish 1-8 and have time, flag that you're ready for these.  Some
require extra setup (a phone, a flash drive, a second machine) that
will be called out in the walkthrough text.

- **Walkthrough 9 — Multi-IP contacts (#347).**  Testing the
  "contact has several possible IPs, daemon tries each and promotes
  the winner" feature.  Single-box, no extra hardware.
- **Walkthrough 10 — Android companion app.**  Needs an Android
  phone on the same network.  Tests the pairing flow, sync, compose
  on phone, attachment handling on phone.
- **Walkthrough 11 — Portable USB mailbox drive (#339, #361).**
  Needs a USB flash drive.  Tests the generator scripts and the
  plug-and-run mailbox.
- **Walkthrough 12 — Cross-network / public-IP tests.**  Requires
  two boxes on two different networks with router port forwarding.
  The dev team usually does this one themselves; flag it if you
  have access to a second machine and want to try.

---

## Reporting template

For anything that didn't pass (or didn't make sense), all we need is:

- **Which step**: e.g. `Walkthrough 2, Test 2.3, observation 3`.
- **What you were trying to do** — one sentence.
- **What actually happened** — one to three sentences.  If a
  command printed an error, copy-paste the error.

Example:

```
Walkthrough 2, Test 2.3, observation 3
Trying: delete bob's inbox/answer and confirm alice stops retrying.
What happened: alice's terminal kept printing
  "retry answer -> bob (attempt 4)" once a minute for 10 minutes.
  Never stopped.
```

Paste these notes into whatever channel the dev team gave you.

---

## Next walkthroughs

Additional walkthroughs covering attachments, Android app, multi-IP
contacts, hooks, and the portable mailbox drive will be added in
subsequent drafts of this guide.  If you finish walkthroughs 1 and
2 and have time, flag that you're ready for more.
