# In-app script editor for Android (low priority)

## Overview

Users manage **phone-side** hook scripts from inside the rmail app.
These scripts run on the phone and react only to rmail events that
happen on the phone — incoming message delivered to the phone's inbox,
message sent from the phone's outbox, phone-side update, and so on.

## Architectural principle: phone and desktop hooks are separate

This is explicit and non-negotiable:

- **Desktop daemon** hooks live on the desktop filesystem and run
  against messages passing through the desktop.
- **Phone (thin client)** hooks live on the phone and run against
  messages passing through the phone.
- The two sets are **not shared** and **not synced**. A script written
  on the phone does not end up on the desktop, and vice versa.

The reason is practical: cross-device script sync would require pushing
files into the desktop filesystem from the phone, with all the trust,
conflict, and format questions that implies. We don't have a plan for
that, and we don't need one if each side owns its own hook surface.

This separation also sidesteps #308 (synced phone config) for the
hook-binding use case: the phone owns its own bindings.

## New hook category: sync-process hooks

Once phone and desktop hooks are separate, there's an open slot for
hooks that fire during the **sync between desktop and thin client** —
at the boundary, rather than on either side. Examples of where that
could be useful:

- Strip or rewrite fields on messages crossing the boundary.
- Log/audit what leaves the desktop for the phone (and vice versa).
- Defer or drop messages that shouldn't round-trip.

Scope for this issue: acknowledge the category exists. Designing the
sync-process hook set is a separate piece of work.

## Script execution environment — open questions

Before designing the UI we need answers:

- **Language.** Lua (to match the daemon) is the obvious candidate, but
  Android doesn't ship a Lua interpreter. What does?
- **Interpreter.** Can we embed a Lua interpreter inside the Android
  app (e.g. LuaJ, LuaJava, a native build)? What size/permission cost?
- **Bridge.** Can a Lua script call into Kotlin to do things the user
  actually cares about — read the inbox file, send an rmail message,
  talk to the Android side of another app via content providers /
  intents?
- **Capability ceiling.** Given whatever the answers above are, can a
  user write scripts that do *meaningful* things (not just log), or is
  the environment so sandboxed that the feature doesn't pay for itself?

This is the main reason the issue is low priority: without a
satisfying answer here, the UI work is premature.

## Design (contingent on the execution-environment questions)

### Script storage

Each script is a plain text file stored on the phone. Phone-only —
never synced to the desktop.

### Editor

A plain text editor for the script body. No FSM canvas, no block
programming — those may come later but are out of scope here.

The editor is not how a script gets wired up to a hook. To **use** a
script, the user goes to the hook-config screen and picks a script
from a list.

### Hook configuration

For each phone-side hook (`on_receive`, `on_send`, `on_update`, …), the
user has two ways to supply a script:

1. **Pick from the list** of phone-side scripts already written.
2. **Import from a text file** on the phone. The import dialog opens
   to the rmail inbox by default, so a script received as an rmail
   message is immediately visible and importable.

(The earlier draft included a third option — "type a path to a script
on the desktop daemon" — removed under the phone/desktop separation
principle above.)

### Screen navigation — open design question

Two new screens are implied but their entry points are undefined:

- Where does the user reach the **script editor** from? Which screen,
  which button?
- Where does the user reach the **hook-config screen** from? Which
  screen, which button?

Both answers should be recorded here before any UI work starts.

## Inter-device use

Scripts can send rmail messages to trigger actions on other devices.
"Just write an rmail message" remains the universal interface for
cross-device automation — and under the separation principle, it is
the *only* way phone-side logic influences the desktop.

## Dependencies

- Daemon hook system must be stable first.
- No longer depends on #308 (synced phone config). Hook bindings live
  only on the phone.

## Status

Design phase. **Low priority** — the cross-device utility is marginal,
and the execution-environment questions are a hard prerequisite.
