# rmail monitor program

## Vision

A system-level program that manages rmail instances on a machine. Think of
it as the "mailboxes" view from the Android app, but for the computer — a
platform that other things can interface with.

## Core features

### Instance detection
- Detects all running rmail instances on the system
- Shows version number, mailbox path, port, status
- Instances can opt out of detection via a config flag

### Version tracking and transition
- Caches the last known version number per instance
- When a new version is detected (higher than cached), runs a transition
  script that walks through the changes made between versions
- The transition script follows the development story one change at a time
  (from LLM transcripts), showing what was built, why, and how
- This serves as both a changelog and a "how this program was built" story
  — a selling point for someone evaluating rmail

### Platform / API design
The monitor should be designed as a platform — something other tools can
talk to. Not a rigid controller, but a capable actor with clear abilities.

Design philosophy (per the user): less "movement_controller" or
"kinematic_rigidbody" and more "seventeen.footmen" or "dave the barbarian" —
"what can I do? I can swing a sword, and I am tough as I am hard. Let me
'at em."

In other words: the API should describe what the monitor CAN DO, not what
it IS. It's an agent with capabilities, not a data model with methods.

Capabilities might include:
- "I can list all rmail instances on this machine"
- "I can tell you the version and status of each one"
- "I can show you the story of how this version was built"
- "I can restart an instance"
- "I can run a script against an instance's hooks"
- "I can relay a message between instances"

This should integrate with rmail's scripting system (hooks) as a first-class
interface — the monitor is another hook consumer/producer.

### UI
- List of instances (similar to Android mailbox list)
- Select an instance to see details and configure
- Version history browser with the development narrative
- Could be TUI (terminal), or serve a local web UI, or both

## Implementation thoughts
- Detect instances: scan for running processes with `rmail.lua` in the
  command line, or scan `~/.config/rmail/config-*` files
- Version: rmail needs a `--version` flag or a version constant in the source
- Transition scripts: stored per-version in a `transitions/` directory,
  each one describing what changed and running any necessary migrations
- The monitor could be a separate Lua script or a shell script that wraps
  rmail functionality

## Status

Design phase. This is a larger project that builds on the stable rmail base.

## Witness material

The user described the design philosophy during a late-night session on
2026-03-28. The analogy to "dave the barbarian" — a simple, capable agent
that describes itself by what it can do rather than what it is — captures
the intended API design direction. The development story (LLM transcripts
walking through each change) is both a technical changelog and a marketing
tool: "look how this was built, step by step, by a human and an AI
collaborating."
