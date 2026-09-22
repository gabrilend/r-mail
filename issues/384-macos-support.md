# #384 — Running rmail on macOS

## Summary

macOS is a Unix and most of rmail would work there unchanged, because
most of rmail is Lua.  Three things stand between it and running: one
Linux-only kernel interface, a different binary format, and a different
way of starting services.

None of them is hard.  One of them needs a Mac.

## Why this is not simply "it's Unix"

**The outbox watcher is Linux-only.**  `rmail_inotify.c` is 114 lines
wrapping `inotify`, which is a Linux kernel interface and does not
exist on macOS.  The daemon uses it to notice a file appearing in the
outbox and sync immediately rather than at the next timer.

macOS has `kqueue` with `EVFILT_VNODE`, which does the same job with a
different shape: you register interest in a file descriptor and read
events off a queue.  It is a rewrite of one small file, not a redesign.
The daemon already tolerates the watcher being absent — it falls back
to its timer — so a first pass can ship without it and still work,
just less promptly.

**Binaries are Mach-O, not ELF.**  Everything compiled — the
interpreter, luasocket, mime, and the two rmail libraries — is a
different object format, and loadable modules are `.dylib` rather than
`.so`, which Lua's module search path has to be told about.

Building Mach-O binaries from Linux needs Apple's SDK, whose licence
restricts using it off Apple hardware.  **So this needs a Mac to build
on.**  That is the real gate, and it is a hardware and licensing
question rather than a programming one.

**Services are launchd.**  The installer generates units for five init
systems; macOS would be a sixth, a `launchd` property list under
`~/Library/LaunchAgents`.  It is the most mechanical part of the job.

## What would not need touching

The daemon.  `rmail.lua` is the program, it is Lua, and nothing in it
is Linux-specific beyond reaching for the watcher.  Mail, contacts,
config, hooks and sync state are text files. The protocol is TCP.  A
macOS rmail would talk to a Linux rmail without either knowing.

## What the watcher port turned out to need

Less than expected, and the reason is worth writing down.

inotify tells you *which* file in a watched directory changed.  kqueue
tells you only that the directory changed.  That looked like the hard
part of this issue and is not part of it at all: the daemon calls
`read()` purely to drain the queue and then sets a boolean meaning "go
look at the outbox".  It never touches the event's name, mask or watch
descriptor.  The coarser answer is the whole of what anyone wanted.

The one thing kqueue needs that inotify does not is that a watched path
stays open — inotify takes a path and returns a small integer, kqueue
needs a live file descriptor for the life of the watch.  So `add_watch`
opens the path and hands the descriptor back as the watch descriptor,
and `close` releases them.

## Suggested implementation steps

Ordered so that each one is useful on its own.

1. **Confirm the daemon runs on macOS at all**, with the libraries
   built by hand on a Mac.  This is the experiment that tells you
   whether the rest is worth doing, and it needs nothing designed
   first.

2. **Teach the module search to accept `.dylib`.**  Lua's `package.cpath`
   is set in one place in the daemon.

3. ~~**Write the kqueue watcher.**~~  **Written — `rmail_kqueue.c`.**
   Same four functions and same constant names as the inotify module,
   so the daemon cannot tell which it has.  See the verification
   section below for exactly how far it has been checked, which is
   further than "not at all" and well short of "works".

4. **Teach the installer to detect macOS** and build the right things:
   Mach-O output, `.dylib` suffix, Homebrew or system OpenSSL, and the
   kqueue watcher in place of the inotify one.

5. **Add a launchd branch** to service generation.

6. **Decide about drives.**  A drive built on a Mac would run on Macs;
   a drive built on Linux would not.  This is the same shape as #383's
   per-processor problem, one level up — per operating system as well
   as per processor — and the layout there should be able to hold it.

## How far the untested code has actually been checked

It has never run on a Mac and cannot be, here.  But "never compiled" is
a weak thing to ship, and typos are most of the risk in code nobody can
execute, so it was taken as far as a Linux machine allows:

- **Syntax-checked** against a hand-written stand-in for BSD's
  `<sys/event.h>` — the `kevent` struct, `EV_SET`, the `NOTE_*` flags,
  and the two function signatures.  Clean under `-Wall -Wextra`.
- **Built and loaded**, linked against fake `kqueue` and `kevent`
  implementations, and driven from Lua: the module exports the right
  four functions, exports all five constant names, returns a watch
  descriptor, returns one event table on a read with something queued,
  and returns `nil` on a read with nothing queued.  That last one
  matters more than it looks — the daemon's select loop depends on it.
- **Platform dispatch tested three ways** on Linux: with inotify
  present it picks inotify; with inotify removed and kqueue present it
  picks kqueue and says so; with neither it stops and prints what it
  tried.

**What remains unverified is everything the kernel does**: whether
`EVFILT_VNODE` with those flags actually fires on a file appearing in a
directory, whether `O_EVTONLY` behaves as intended on a removable
volume, and whether the kqueue descriptor is selectable the way the
main loop assumes.  Those need a Mac and about twenty minutes.

The file says all of this at the top, in the project owner's own words,
so whoever finds it knows what they are holding.

## Open questions

- Is there a Mac to build and test on?  Step 1 cannot start without
  one, and steps 3 through 5 cannot be verified without one.  Nothing
  here is blocked on design.
- Apple Silicon and Intel Macs are different processors, so macOS
  support is two builds, not one.  That interacts with #383.
- Does the attachment pipeline shell out to anything Linux-flavoured?
  It uses `zip` and `unzip`, which macOS has, but this has not been
  checked properly.

## Related

- #383 — several processors on one drive.  Same problem shape: a
  compiled artefact only runs where it was built for, and the drive
  layout has to hold more than one of them.
- #382 — settled that rmail targets operating systems with sockets, a
  filesystem, and processes.  macOS qualifies; a bare-metal board does
  not.

## Status

Open.  No steps started.  Step 1 is the whole question and needs
hardware rather than a decision.
