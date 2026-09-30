# #403 — The JSON library's choice of decoder is made silently, and its LPeg switch is broken for new LPeg

## Status

Done — filed and completed 2026-09-29.  Found while working on the sister
project rao-chat, which bundles the same JSON library file.  Numbered in
phase 4 because phase 3 is full (see `phase-4-progress.md`); it belongs
with the daemon's start-up and dependencies when #402 re-sorts the phases.

## Current Behavior

rmail reads and writes all of its state (`.state/*.json`) and every
message on the wire as JSON, through the bundled library `libs/dkjson.lua`
(David Kolf's dkjson, version 2.5 by its own header — older than the 2.8
that `scripts/install.sh` downloads on a fresh install).

dkjson has two decoders inside it:

- a **plain Lua decoder**, which walks the text one character at a time;
- an **LPeg decoder**, built on LPeg, a C library that matches text with
  compiled grammars.  It is faster on large texts.

Which one runs is decided once, when the file is loaded, by a "switch to
LPeg" step at the bottom of the file.

**Now:**

- The switch accepts both shapes of LPeg: an old one whose `version` is a
  function (still checked against the buggy 0.11 and refused if so) and a
  new one whose `version` is a string.  Two small changes in
  `libs/dkjson.lua`, each marked with a dated "rmail change" comment.
- When the switch does not happen, dkjson keeps the reason in a field on
  the module (the reason LPeg is unused) instead of throwing it away.
- The daemon's start-up block, right after "mail dir", logs one line
  saying which decoder it is on — one of:
  - `json decoder: LPeg (LPeg 1.1.0)`
  - `json decoder: plain Lua (LPeg is not installed for Lua 5.4)`
  - `warning: json decoder: plain Lua, although LPeg is installed: <reason>`
- `scripts/test-json-decoders.sh` runs every Lua interpreter on the
  machine through both decoders on state-file-shaped texts (and, given a
  mailbox path, on that mailbox's real `.state/*.json`), and fails if LPeg
  is loadable but unused.

On the owner's desktop the mailboxes run on Lua 5.4, which has no LPeg,
so they log `json decoder: plain Lua (LPeg is not installed for Lua 5.4)`.
Under LuaJIT and Lua 5.1, which have LPeg 1.1.0, dkjson now switches to
LPeg (shown by the test) — but the daemon itself cannot start under either
on this machine today, for reasons unrelated to JSON: the bundled
luasocket in `libs/socket/` is built against Lua 5.4 ("undefined symbol:
lua_newuserdatauv" under LuaJIT), and Lua 5.1 cannot parse the `goto`
statements in `rmail.lua`.  So the LPeg branch of the start-up line is
proven by the test, not by a live daemon.

### Before this issue (the problem it solved)

The last lines of dkjson called the switch inside a protected call and
threw the result away.  The switch began by checking for LPeg 0.11 by
calling LPeg's `version` as a function.  LPeg 1.0 and later expose
`version` as a plain string (`"LPeg 1.1.0"` on this machine), so the check
itself raised "attempt to call field 'version' (a string value)", the
protected call swallowed it, and dkjson fell back to the plain decoder on
every machine with a modern LPeg, without a word.

Evidence, 2026-09-29, on the owner's desktop:

    luajit -e 'print(require("lpeg").version)'
      -> LPeg 1.1.0
    luajit, with rmail's libs/ on the path, calling the switch directly:
      -> false  libs/dkjson.lua:603: attempt to call field 'version' (a string value)

Which Lua actually runs rmail here, and whether it can see LPeg at all:

| interpreter | how it is reached | LPeg on its path | decoder before this issue |
|---|---|---|---|
| `/usr/bin/lua5.4` | the two running mailbox services (`ps`) | no — LPeg is only installed for Lua 5.1 / LuaJIT | plain, because LPeg is absent |
| `deps/lua/bin/lua` (5.4.7) | `run-rmail.sh`, first choice | no | plain, because LPeg is absent |
| `luajit`, `lua5.1` | `run-rmail.sh` fallbacks | yes, 1.1.0 | plain, **because of the broken check** |

So the running mailboxes were on the plain decoder for a legitimate
reason, but nobody could tell that from the outside; and under LuaJIT
the fallback would have happened for a wrong reason, silently.  The new
test, run against the old dkjson, fails on exactly this ("LPeg 1.1.0 is
present but unused").

LPeg is not an rmail dependency: it is absent from the dependency table
in `rmail.lua`, `scripts/install.sh` describes dkjson as "pure-Lua" and
never installs LPeg, and the README and QA guide never mention it.

## Intended Behavior

1. **The switch works with every LPeg.**  An old LPeg (where `version` is a
   function) is still checked for the 0.11 bug; a new one (where `version`
   is a string) is accepted.  Under LuaJIT on this machine dkjson runs on
   the LPeg decoder.
2. **The choice is never silent.**  When the switch does not happen, dkjson
   keeps the reason instead of discarding it.  At start-up the daemon logs
   exactly one line saying which decoder it is on:
   - `json decoder: LPeg (LPeg 1.1.0)`
   - `json decoder: plain Lua (LPeg is not installed for this Lua)`
   - `warning: json decoder: plain Lua, although LPeg is installed — <reason>`
     when LPeg loaded but dkjson refused or failed to use it.  This last
     case is the kind of fallback that hid this bug, so it is worded as a
     warning, not as information.
3. **A missing LPeg is a stated choice, not an error.**  Decision
   (2026-09-29), and why:
   - LPeg is not a dependency of rmail, and nothing in its install path
     puts it there.  The mailbox services on this machine run on a Lua
     that has no LPeg.  Making LPeg's absence an error would stop every
     existing mailbox from starting, for a speed-up.
   - The two decoders produce the same tables for the same text; that is
     now checked by a test (below) rather than assumed.  Being on the plain
     decoder changes speed, not meaning.
   - What the owner's "errors over fallbacks" rule is really aimed at is
     the fallback that happens for a wrong reason and hides it.  That case
     — LPeg present but not used — is logged as a warning at every start,
     and the test below fails outright when LPeg is present for an
     interpreter but dkjson does not switch to it.  So the silent-wrong
     case is an error at test time and a loud warning at run time.
   - The daemon does not refuse to start on that warning: refusing would
     turn a broken speed-up into a mail outage, while the result of every
     decode is the same.
4. **A test proves both decoders agree** on the shapes rmail really keeps
   in `.state/` (inbox records, outbox records with recipients, pending
   consents, empty objects and empty arrays, uploads, addresses), and that
   the switch takes LPeg whenever it is present.

## Suggested Implementation Steps

1. `libs/dkjson.lua` (third-party; keep the change small and marked with a
   dated comment saying what changed and why):
   - in the switch, read `version`, call it only when it is a function, and
     compare the result against the 0.11 bug as before;
   - at the bottom, keep the protected call's error message in a new field
     on the module (the reason LPeg is not in use) instead of dropping it.
2. `rmail.lua`, in the start-up block (`init_runtime`), beside "rmail
   starting" and "mail dir": work out which of the three cases above holds
   — LPeg in use; LPeg loaded (it is in Lua's table of loaded modules) but
   refused, with the kept reason; or LPeg not loaded — and log it once.
   The small function that words the sentence lives inside the start-up
   block, not at the top of the file: `rmail.lua`'s top level already
   holds Lua's maximum of 200 local names, and the first attempt, which
   added two there, stopped the whole file compiling ("too many local
   variables").  Any future top-level addition has the same limit to
   respect.
3. `scripts/test-json-decoders.sh`: for every Lua interpreter on the
   machine (the bundled `deps/lua/bin/lua`, `lua5.4`, `lua5.3`, `lua5.1`,
   `luajit`, `lua`), load dkjson twice — once with LPeg hidden, once as it
   loads normally — decode a fixed set of state-file texts through both,
   and compare the results field by field, including which empty tables
   are objects and which are arrays.  Also: fail if LPeg is loadable for
   that interpreter but dkjson did not switch to it; and check the 0.11
   refusal still happens with a stand-in LPeg whose `version` is a
   function returning "0.11", and that a stand-in returning "0.12" is
   accepted.  Optionally decode every `.state/*.json` of a real mailbox
   passed on the command line, through both decoders.
4. Start a mailbox and read the new log line.

## Tests

- `scripts/test-json-decoders.sh [checkout] [mailbox]` — 2026-09-29: all
  six interpreters on the owner's desktop passed (bundled 5.4.7, 5.4.6,
  5.3, 5.2 with LPeg rows skipped; LuaJIT and 5.1 with every row run),
  including the real `.state/*.json` of `/home/ritz/mail`.  Run against
  the dkjson from before this issue, the same checker fails three rows
  (reason not kept; LPeg present but unused; 0.11 refusal unexplained).
- Every other `scripts/test-*.sh` still passes.  `test-log-location.sh`
  starts real daemons; their output shows the new line
  `json decoder: plain Lua (LPeg is not installed for Lua 5.4)`.

## Related

- #402 — the phase re-sort; this issue moves with the daemon's start-up
  and dependencies.
- rao-chat bundles the same dkjson file and has the same bug; that is
  where it was noticed.  It is not changed by this issue.
- The thin clients (`clients/`) download their own copy of dkjson at
  install time; those copies are 2.8 by default and are not changed here.
- Not addressed here, noticed while testing: `run-rmail.sh` offers
  `luajit` and `lua5.1` as fallback interpreters, but on this machine
  rmail cannot start under either (bundled luasocket is built for Lua 5.4;
  Lua 5.1 has no `goto`).  Belongs with the interpreter-choice work in
  #383 / #402 if it matters.
