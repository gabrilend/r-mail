# Helper Scripts

The `helpers/` directory contains scripts meant to be called from hooks or
the command line. They handle common tasks so you don't have to reimplement
them yourself.

See the [scripting tutorial](scripting-tutorial.md) for how hooks work and
how to write your own.

---

## rto.sh — add recipients to an outbox file

Inserts one or more `to:` lines into an outbox message. New lines are placed
after the existing header block (all contiguous `to:` and `attach:` lines at
the top), so attachment targeting is preserved.

```
helpers/rto.sh <file> <recipient> [<recipient> ...]
```

**Examples:**

```sh
# Start a new message to alice and bob
helpers/rto.sh ~/mail/outbox/hello alice bob
```

```sh
# Add a recipient to an existing message — carol won't receive
# attachments that were listed above her
helpers/rto.sh ~/mail/outbox/hello carol
```

If the file doesn't exist yet, it's created. If it has no headers (body
only), the `to:` lines are prepended.

---

## rattach.sh — add attachments to an outbox file

Inserts one or more `attach:` lines into an outbox message. Same insertion
rule as `rto.sh`: lines go after the existing header block, so attachments
apply to every `to:` recipient above them.

```
helpers/rattach.sh <file> <path> [<path> ...]
```

**Example:**

```sh
helpers/rattach.sh ~/mail/outbox/hello ~/photos/pic.jpg ~/docs/notes.txt
```

**Combining with rto.sh:** because `rto` and `rattach` are separate scripts,
you control exactly which recipients get which attachments by interleaving
calls:

```sh
# alice and bob get pic.jpg; carol does not
helpers/rto.sh ~/mail/outbox/hello alice bob
helpers/rattach.sh ~/mail/outbox/hello ~/photos/pic.jpg
helpers/rto.sh ~/mail/outbox/hello carol
```

---

## raccept.sh — accept a package request

When a contact wants to send you an attachment, a consent file appears in
your inbox (e.g. `photo-consent-to-download-form`). This script accepts the
request by removing the `deny` line, leaving only `accept` for the daemon to
pick up on the next sync cycle.

```
helpers/raccept.sh <consent-file>
```

**Example:**

```sh
helpers/raccept.sh ~/mail/inbox/photo-consent-to-download-form
```

---

## rdeny.sh — deny a package request

The opposite of `raccept.sh`: removes the `accept` line, leaving only `deny`.

```
helpers/rdeny.sh <consent-file>
```

**Automating consent in hooks:** wire `raccept` and `rdeny` into an
`on_receive` hook to auto-accept from trusted contacts:

```sh
#!/bin/sh
# on_receive hook: auto-accept from alice, deny from gary
sender="$1"
file="$2"

case "$file" in
    *-consent-to-download-form)
        case "$sender" in
            alice) helpers/raccept.sh "$file" ;;
            gary)  helpers/rdeny.sh "$file" ;;
        esac
        ;;
esac
```

---

## rfield.sh — read a contact field

Reads an arbitrary field from the contacts file by name. Located in
`scripts/` (not `helpers/`) but used the same way.

```
scripts/rfield.sh <name> <field>
```

**Examples:**

```sh
scripts/rfield.sh alice phone     # → 555-1234
scripts/rfield.sh alice notify    # → email@example.com
```

Contacts can store any fields you like alongside the required `ip`, `port`,
and `token`:

```
alice.ip    = 203.0.113.1
alice.port  = 8025
alice.token = "shared-secret"
alice.phone = "555-1234"
alice.notify = "email@example.com"
```

Exits 0 and prints the value if the field exists, or exits 1 silently if it
doesn't — so wrapping it in an `if` or checking for empty output handles
missing fields cleanly.

---

## checksum.sh — SHA-256 hash of a file

```
helpers/checksum.sh /path/to/file
```

Prints the hex digest. Thin wrapper around `sha256sum`.

---

## filename.sh — extract filename from a path

```
helpers/filename.sh /home/ritz/mail/inbox/hello-world
# → hello-world
```

Strips the directory, returning only the final path component.
