# rmail Scripting Tutorial

Hooks let you run a script in response to message events. Configure them in
`~/.config/rmail/config`:

```
on_receive_raw = /path/to/script.sh
on_receive     = /path/to/script.sh
on_package     = /path/to/script.sh
on_send        = /path/to/script.sh
on_delete      = /path/to/script.sh
```

---

## Hook interface

Each hook is a path to an executable. rmail calls it with shell arguments.
For `on_receive_raw` and `on_send`, stdout is read back and replaces the
message body. For all others, stdout is ignored.

| Hook            | `$1`       | `$2`       | `$3`                  | stdout        |
|-----------------|------------|------------|-----------------------|---------------|
| `on_receive_raw`| sender     | subject    | message body          | replaces body |
| `on_receive`    | sender     | subject    | path to inbox file    | ignored       |
| `on_send`       | recipient  | subject    | message body          | replaces body |
| `on_delete`     | other party| —          | —                     | ignored       |
| `on_package`    | sender     | filename   | path to saved file    | ignored       |

**on_receive_raw** fires before the message is written to disk. Whatever your
script prints to stdout becomes the body that gets saved. If your script prints
nothing (or exits non-zero), the original body is kept. This hook is synchronous
— rmail waits for it before writing. Use it for filtering, transformation, or
security analysis on data that hasn't touched the filesystem yet.

**on_receive** fires after the message is written. The file is already on disk
at `$3`. This hook runs in the background: rmail appends `&` to the command,
which tells the shell to fork a child process and continue immediately without
waiting for it to finish. The hook runs concurrently with rmail. Its stdout
is not captured. Use it for notifications, backups, or logging — anything where
you don't need to block delivery and can't transform the message anyway.

**on_send** fires once per recipient before the message is sent to that person.
Each call is independent — `$3` is the body as it will be sent to `$1`, and
stdout replaces it for that recipient only. rmail calls the hook separately
for each recipient with fresh arguments, so each transformation is isolated.
Also synchronous.

**on_delete** fires when a message is deleted from either inbox or outbox. `$1`
is the name of the other party — the sender for inbox deletions, the recipient
for outbox deletions.

**on_package** fires after a received attachment is fully assembled and saved.
`$1` is the sender's name, `$2` is the filename (useful for filetype detection),
`$3` is the full path to the saved file. Runs in the background.

---

## Bash examples

### Wrap incoming messages to 80 columns

Uses `on_receive_raw` — transforms the body before it hits disk.

```sh
#!/bin/sh
# ~/.config/rmail/hooks/wrap.sh
from="$1"
subject="$2"
body="$3"

printf '%s' "$body" | fold -s -w 80
```

```
on_receive_raw = ~/.config/rmail/hooks/wrap.sh
```

`fold -s` breaks on word boundaries. The wrapped text goes to stdout, which
rmail saves as the message body. `$from` and `$subject` are available if you
want to apply per-sender or per-subject rules.

### Tally deleted messages per contact

Uses `on_delete`.

```sh
#!/bin/sh
# ~/.config/rmail/hooks/tally.sh
contact="$1"
tally_file="${HOME}/mail/.tally"

# one pipe character per deletion: "alice: ||||"
if grep -q "^${contact}:" "$tally_file" 2>/dev/null; then
    sed -i "s/^${contact}: /&|/" "$tally_file"
else
    printf '%s: |\n' "$contact" >> "$tally_file"
fi
```

```
on_delete = ~/.config/rmail/hooks/tally.sh
```

Result in `~/mail/.tally`:
```
alice: ||||
bob: ||
```

### Desktop notification on new message

Uses `on_receive` — fires after the message is saved.

```sh
#!/bin/sh
# ~/.config/rmail/hooks/notify.sh
from="$1"
subject="$2"
# $3 is the inbox file path, not needed here

notify-send "rmail" "New message from ${from}: ${subject}"
```

```
on_receive = ~/.config/rmail/hooks/notify.sh
```

### Prepend a disclaimer for a specific recipient

Uses `on_send` to add a footer only when sending to a particular person.

```sh
#!/bin/sh
# ~/.config/rmail/hooks/disclaimer.sh
recipient="$1"
subject="$2"
body="$3"

if [ "$recipient" = "legal-team" ]; then
    printf '%s\n\n---\nThis message may be monitored.' "$body"
else
    printf '%s' "$body"
fi
```

```
on_send = ~/.config/rmail/hooks/disclaimer.sh
```

If the script prints nothing for a given recipient, the body is sent unchanged.

### Read arbitrary contact fields

If you store extra data in the contacts file (like `alice.phone = "555-1234"`),
you can read it inside a hook using grep. This works in any hook — here shown
in `on_send` to look up the recipient:

```sh
#!/bin/sh
recipient="$1"
subject="$2"
body="$3"
contacts="${HOME}/mail/contacts"

phone=$(grep "^${recipient}\.phone" "$contacts" | sed 's/.*= *//' | tr -d '"')

# do something with $phone, e.g. log it or include in body
printf '%s\n\ncc: %s' "$body" "$phone"
```

---

## Lua examples

Any executable works as a hook — not just shell scripts. For Lua:

```lua
#!/usr/bin/env lua
-- ~/.config/rmail/hooks/wrap.lua
-- Wrap incoming message body to 80 columns.

local from    = arg[1]   -- sender name
local subject = arg[2]   -- message subject
local body    = arg[3]   -- message body text

local function wrap(text, width)
    local result = {}
    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        while #line > width do
            local cut = line:sub(1, width):match("^(.*%s)") or line:sub(1, width)
            result[#result + 1] = cut:match("^(.-)%s*$")
            line = line:sub(#cut + 1):match("^%s*(.-)$") or ""
        end
        result[#result + 1] = line
    end
    return table.concat(result, "\n")
end

io.write(wrap(body, 80))
```

```
on_receive_raw = /home/you/.config/rmail/hooks/wrap.lua
```

**Receiving data:** arguments map to `arg[1]`, `arg[2]`, `arg[3]` exactly as
shown in the interface table above. For hooks where `$3` is a file path
(`on_receive`), read the file with `io.open(arg[3], "r")`.

**Returning data:** write to stdout with `io.write()`. Prefer `io.write()` over
`print()` for body-replacement hooks — `print()` appends a newline that will
appear at the end of the saved message.

### Lua example: log received messages to a file

Uses `on_receive` — fires after the message lands on disk.

```lua
#!/usr/bin/env lua
local from    = arg[1]
local subject = arg[2]
local path    = arg[3]   -- path to saved inbox file

local log = io.open(os.getenv("HOME") .. "/mail/.log", "a")
if log then
    log:write(os.date("%Y-%m-%d %H:%M") .. "  from=" .. from ..
              "  subject=" .. subject .. "  file=" .. path .. "\n")
    log:close()
end
```

```
on_receive = /home/you/.config/rmail/hooks/log.lua
```

---

## C examples

Compile a C program and point the config at the binary.

```c
/* wrap.c — compile with: cc -O2 -o wrap wrap.c */
#include <stdio.h>
#include <string.h>

#define WIDTH 80

void wrap_line(const char *line, int width) {
    int len = strlen(line);
    int start = 0;
    while (len - start > width) {
        int cut = start + width;
        while (cut > start && line[cut] != ' ') cut--;
        if (cut == start) cut = start + width;
        fwrite(line + start, 1, cut - start, stdout);
        putchar('\n');
        start = cut;
        while (line[start] == ' ') start++;
    }
    puts(line + start);
}

int main(int argc, char *argv[]) {
    if (argc < 4) return 1;

    /* argv[1] = sender, argv[2] = subject, argv[3] = body */
    const char *body = argv[3];
    char line[4096];
    int i = 0, j = 0;

    while (body[i]) {
        if (body[i] == '\n' || j == (int)sizeof(line) - 1) {
            line[j] = '\0';
            wrap_line(line, WIDTH);
            j = 0;
        } else {
            line[j++] = body[i];
        }
        i++;
    }
    if (j > 0) {
        line[j] = '\0';
        wrap_line(line, WIDTH);
    }
    return 0;
}
```

```
on_receive_raw = /home/you/.config/rmail/hooks/wrap
```

**Receiving data:** `argv[1]`, `argv[2]`, `argv[3]` correspond to the positions
in the interface table. rmail shell-quotes all arguments, so each arrives as a
single string even if it contains spaces, newlines, or quotes.

For `on_receive` and `on_package` where `$3` (or `$1` for `on_package`) is a
file path, open it with `fopen(argv[3], "r")`.

**Returning data:** write to `stdout`. Return 0 for success. Non-zero exit
causes rmail to log a warning and keep the original body unchanged.

---

## Tips

- Hook scripts must be **executable** (`chmod +x`). Lua and C scripts need this
  too even though they're not shell scripts — the OS needs permission to execute
  them.
- For `on_receive_raw` and `on_send`, printing nothing or exiting non-zero
  preserves the original body. Your script does not need to handle every case —
  just print nothing to pass the message through unchanged.
- `on_receive_raw` and `on_send` are synchronous — rmail waits for them. Keep
  them fast. `on_receive` and `on_package` run in the background so they can
  take as long as they need.
- Message bodies are capped at 128 KB. Larger content must be sent as an
  attachment. This keeps `$3` in `on_receive_raw` and `on_send` a manageable
  size that won't hit OS argument length limits.
- Arbitrary contact fields (`ip`, `port`, `token`, plus anything you add) are
  stored in `~/mail/contacts` but not passed to hooks automatically. Read them
  with `scripts/rfield.sh` or directly with grep, as shown in the examples above.

---

## Reading contact data in hooks

Contacts can store arbitrary fields alongside the required `ip`, `port`, and `token`:

```
alice.ip    = 203.0.113.1
alice.port  = 8025
alice.token = "shared-secret"
alice.phone = "555-1234"
alice.notify = "email@example.com"
```

The `scripts/rfield.sh` utility reads these fields by name:

```sh
rfield alice phone     # → 555-1234
rfield alice notify    # → email@example.com
```

This is useful in hooks. For example, an `on_receive` hook that sends an SMS notification:

```sh
#!/bin/sh
# on_receive hook: send SMS when a message arrives
sender="$1"
subject="$2"

phone=$(rfield "$sender" phone 2>/dev/null)
if [ -n "$phone" ]; then
    # replace this with your SMS provider's CLI
    sms-send "$phone" "New message from $sender: $subject"
fi
```

Configure it in `~/.config/rmail/config`:

```
on_receive = /path/to/notify-sms.sh
```

rfield exits 0 and prints the value if the field exists, or exits 1 silently if it doesn't — so wrapping it in an `if` or checking for empty output handles missing fields cleanly.
