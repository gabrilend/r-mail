# rmail Scripting Tutorial

Hooks let you run a script in response to message events. Configure them in
`~/.config/rmail/config`:

```
on_receive_raw = /path/to/script.sh
on_receive     = /path/to/script.sh
on_package     = /path/to/script.sh
on_send        = /path/to/script.sh
on_delete      = /path/to/script.sh
on_update      = /path/to/script.sh
```

## Table of contents

- [Hook interface](#hook-interface)
- [Examples](#examples) — ordered from simplest to most involved
  - [Desktop notification on new message](#desktop-notification-on-new-message)
  - [Wrap incoming messages to 80 columns](#wrap-incoming-messages-to-80-columns)
  - [Prepend a disclaimer for a specific recipient](#prepend-a-disclaimer-for-a-specific-recipient)
  - [Read contact fields in a hook](#read-contact-fields-in-a-hook)
- [Using other languages](#using-other-languages)
  - [Lua](#lua)
  - [C](#c)
- [Tips](#tips)

---

## Hook interface

Each hook is a path to an executable. rmail calls it with shell arguments.
For `on_receive_raw`, `on_send`, and `on_update`, stdout is read back and
replaces the message body. For all others, stdout is ignored.

| Hook            | `$1`       | `$2`       | `$3`                  | stdout        |
|-----------------|------------|------------|-----------------------|---------------|
| `on_receive_raw`| sender     | subject    | message body          | replaces body |
| `on_receive`    | sender     | subject    | path to inbox file    | ignored       |
| `on_send`       | recipient  | subject    | message body          | replaces body |
| `on_delete`     | other party| —          | —                     | ignored       |
| `on_update`     | sender     | inbox path | new message body      | replaces body |
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
Also synchronous. Printing nothing passes the body through unchanged.

**on_delete** fires when a message is deleted from either inbox or outbox. `$1`
is the name of the other party — the sender for inbox deletions, the recipient
for outbox deletions.

**on_update** fires when a living message is updated — that is, when the sender
edits an outbox file and the new body arrives at your end. `$2` is the path to
the existing inbox file (still holding the old content), `$3` is the new body.
Whatever your script prints to stdout becomes the body that gets saved, just
like `on_receive_raw`. Synchronous. If no `on_update` hook is configured, the
update is applied directly. Use it for diff logging or edit rejection (print
the old body to reject an update).

**on_package** fires after a received attachment is fully assembled and saved.
`$1` is the sender's name, `$2` is the filename (useful for filetype detection),
`$3` is the full path to the saved file. Runs in the background.

---

## Examples

Examples below use shell scripts for simplicity. Any executable works as a
hook — see [Using other languages](#using-other-languages) for Lua and C.

### Desktop notification on new message

Uses `on_receive` — fires after the message is saved. About as simple as a
hook gets: one `notify-send` call.

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

### Read contact fields in a hook

Use `helpers/rfield.sh` to read arbitrary contact fields — see the
[helper scripts](helper-scripts.md#rfieldsh--read-a-contact-field) reference.
Here's a quick example in `on_send`:

```sh
#!/bin/sh
recipient="$1"
subject="$2"
body="$3"

phone=$(helpers/rfield.sh "$recipient" phone 2>/dev/null)
if [ -n "$phone" ]; then
    printf '%s\n\ncc: %s' "$body" "$phone"
else
    printf '%s' "$body"
fi
```

Contact fields are arbitrary — store `phone`, `notify`, `nickname`, whatever
you need alongside the required `ip`/`port`/`token`, and hooks can read them.

---

## Using other languages

Any executable works as a hook. rmail doesn't care what language it's in —
just that `chmod +x` succeeds and the file has a valid shebang. Below are
the same kinds of examples in Lua and C.

### Lua

Point the shebang at rmail's bundled Lua interpreter — it's guaranteed to
match the version rmail itself uses, and it's available on any machine
where rmail is installed:

```lua
#!/home/you/programs/email/deps/lua/bin/lua
```

If your install doesn't bundle Lua (the install script only compiles one when
no system Lua is detected), use `#!/usr/bin/env lua` instead; any Lua 5.1+
or LuaJIT works.

**Receiving data:** arguments map to `arg[1]`, `arg[2]`, `arg[3]` exactly as
shown in the [interface table](#hook-interface). For hooks where `$3` is a
file path (`on_receive`), read the file with `io.open(arg[3], "r")`.

**Returning data:** write to stdout with `io.write()`. Prefer `io.write()`
over `print()` for body-replacement hooks — `print()` appends a newline that
will appear at the end of the saved message.

#### Log received messages to a file

```lua
#!/home/you/programs/email/deps/lua/bin/lua
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

#### Wrap incoming messages to 80 columns (Lua version)

```lua
#!/home/you/programs/email/deps/lua/bin/lua
local from    = arg[1]
local subject = arg[2]
local body    = arg[3]

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

### C

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

- Hook scripts must be **executable** (`chmod +x`).
- For compiled languages, point the config at the **binary**, not the source.
  For C:
  ```sh
  cc -O2 -o ~/.config/rmail/hooks/wrap ~/.config/rmail/hooks/wrap.c
  ```
  Then in config: `on_receive_raw = ~/.config/rmail/hooks/wrap`. Recompile
  after editing the source.
- Message bodies are capped at 128 KB. Larger content must be sent as an
  attachment — this keeps `$3` in `on_receive_raw` and `on_send` a manageable
  size that won't hit OS argument length limits.
- The `helpers/` directory handles common tasks you'd otherwise reimplement
  in every hook: adding recipients, inserting attachments, accepting/denying
  package requests, reading contact fields. Most hook scripts end up calling
  one or two of them — see the [helper scripts](helper-scripts.md) reference
  for what's available.
