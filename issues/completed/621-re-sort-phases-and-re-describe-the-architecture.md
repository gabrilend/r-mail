# #621 — Re-sort the issues into nine phases and re-describe the whole architecture as blueprints

## Status

Completed 2026-10-04 — planned 2026-09-23 and deferred by the
owner until before release ("let's write the blueprints and renumbering
into an issue file and come back to it later"); taken up on 2026-10-04:
"can we work on this?"  Numbered 402 at first, only because phase 3 was full; this
issue is itself renumbered by the work it describes (to 621).

**Decided 2026-10-04** (the open questions below, answered):

1. The nine themes, as proposed — "Use these nine".
2. Foundations first across phases too: "you know how to number phases".
   So a phase stands on the ones before it.  One consequence: the door the
   home daemon opens for the owner's own devices (the phone API) sits in
   phase 7, before the desktop thin client that uses it, and the Android
   client (phase 8) stands on it.
3. The Android blueprints are written in this pass, by the same session
   as the rest.

**Done so far (2026-10-04):**

- 17 blueprints written for what was built without an issue
  (`issues/completed/new-*.md`, numbered by the mapping); a planned
  eighteenth, on attachment pieces, was dropped because #302 already
  describes them.
- The 30 open issues missing the three required sections restructured
  without losing their text (built ones state what exists in a new
  Current Behavior; design sections renamed); `validate-issues` reports
  no findings.
- `scripts/renumber-issues.lua` and its test `scripts/test-renumber-issues.sh`.
- The mapping, `notes/phase-renumbering-2026-10.map`.
- `scripts/generate-phase-progress.lua`, which writes each phase's
  progress file from the issue files.

- The renumbering, run 2026-10-04 with the mapping: 147 issues moved,
  195 files rewritten (code comments, documents, tests, the Android
  source, other issues); the lines it left for a person to check were
  all history or numbers that are not issues (HTTP 403, line numbers).
- One progress file per phase, generated; the four old hand-written ones
  kept as `notes/progress-before-the-re-sort.md`.
- `docs/table-of-contents.md`: every document and the nine phases.
- A demo per phase (`issues/completed/demos/phase-N-demo.sh`) and
  `run-demo.sh` at the root, which asks for a phase.

- Every demo run end to end, and the whole test suite on the renumbered
  tree: everything passes except `scripts/test-lan-discovery-names.sh`,
  which failed the same way before any of this (noted in phase 4's
  progress file).  One test's window was widened: the busy answer of #120
  makes a sender that calls while it is being dialed retry on its next
  timer, up to a minute later.

Completed 2026-10-04.

## Current Behavior

**Phases.**  Issues are numbered `{phase}{id}`, and a phase is meant to
group related functionality, foundations first (the owner's rules: "The
phases should correspond to sections of the software, clusters of
functionality and major methodologies").  In practice:

| phase | issues | what it holds |
|---|---|---|
| 1 | 7, all done | the early same-network groundwork |
| 2 | 6, all done | shared devices, early reliability fixes |
| 3 | 100 (every number 300–399), about half done | everything since, whatever it is about |
| 4 | 402 and 401 | overflow: decoy traffic (renumbered from a duplicate 314) and this issue |

Current counts: `/home/ritz/programming/ai-stuff/scripts/progress-dashboard.lua /mnt/mtwo/programs/r-mail -m`.

Phase 3 mixes the daemon's core, the outbox format, attachments,
addresses, installation, helper scripts and the whole Android client.
Within it, numbers follow the order issues were filed, not what builds on
what.  The numbering tool's way of continuing past 399 (`3100`) reads back
as phase 31, so there is no clean room left in phase 3.

**Undescribed functionality.**  A large share of the project was built on
the owner's laptop, whose instructions deliberately do not ask for issue
files.  Owner: "sometimes it does, but they're usually bad because it
doesn't know how".  So much of what the daemon and the phone do exists in
code and commits with no blueprint.  36 or so older issue files also lack
the three required sections (`validate-issues` lists them).

**References.**  Issue numbers are cited all over: `#115` in `rmail.lua`
comments, in docs, in other issues, in the Android client's Kotlin, in
test scripts, in `q-a-tests.md`; file names like
`115-per-contact-sync-timers` in a few places.

## Intended Behavior

Before release:

1. **Every piece of functionality has a blueprint issue**, written so the
   project could be rebuilt from `issues/completed/` alone.  Each has the
   three required sections, names the real functions, files and tests, and
   keeps the decisions and the reasons for them.  Existing issues are
   rewritten in place where they cover the ground; new ones are written for
   what was built without one (the laptop work).
2. **Issues sit in up to nine phases by theme**, foundations first.  Within
   a phase, the issues others build on get the lower numbers, and the last
   is often a capstone.  Proposed themes (2026-09-23, not yet confirmed):

   | phase | theme | examples by today's numbers |
   |---|---|---|
   | 1 | The daemon's core: main loop, sync cycle, encryption, sending | 104, 105, 106, 204, 324, 377, 387, 396, 397 |
   | 2 | Messages as files: outbox format, edits, deletes, dates | 101, 306, 310, 323, 349, 362, 363, 368, 374, 399 |
   | 3 | Attachments and consent | 327, 328, 346, 372, 391 |
   | 4 | Addresses and networking: discovery, IP changes, NAT, IPv6 | 102, 203, 300, 302–304, 311, 312, 347, 353, 354, 365, 379, 388, 389, 393 |
   | 5 | Contacts, identity and privacy of state | 338, 348, 394, 395, 398 |
   | 6 | Installation, services and portable drives | 333–345, 350, 351, 381–385, 339, 361, 376 |
   | 7 | Helper scripts and desktop tools | 326, 330–332, 364, 301, 329, 380, 200, 352 |
   | 8 | The Android client | 305, 307–309, 313–322, 357–360, 369, 373, 375, 378, 386, 392 |
   | 9 | Privacy against people watching the network; new transports | 366, 367, 401, 370, 390 |

3. **Every reference follows its issue.**  After the renumbering, no
   comment, doc, test, issue or Android source cites an old number or an
   old file name.  Owner: "We can renumber issue files as we please, so
   long as we update any references to them in docs and comments and
   whatnot."  Transcripts are not rewritten: they are the record of what
   was said at the time.
4. **Each phase has a progress file and a demo**, per the owner's rules,
   and the table of contents names every phase.

## Suggested Implementation Steps

1. **Confirm the themes** with the owner (open question 1), and settle what
   belongs where for issues that straddle two themes.
2. **Inventory what exists**, from the code rather than the issue tree:
   walk `rmail.lua`, the helper scripts, `scripts/install.sh` and the
   Android client, and list every capability.  Mark each as described by an
   issue (which) or undescribed.  The commit history and
   `llm-transcripts/` hold the story of the laptop work.
3. **Write the missing blueprints and rewrite the thin ones**, one phase at
   a time, foundations first.  A blueprint states the built system, not a
   work log.  The 36 files the validator flags are part of this.
4. **Build a renumbering tool** (per the owner's rule to build the tool that
   makes the thing, not the thing by hand), e.g.
   `scripts/renumber-issues.lua`:
   - input: a mapping file, one line per issue, old number → new number;
     the owner reviews it before anything moves;
   - it refuses a mapping with a duplicate target, a missing issue, or a
     number already taken outside the mapping;
   - it moves each file (`issues/` and `issues/completed/`), then rewrites
     references across the repository: `#NNN` in any text file, `NNN-slug`
     file names, and "issue NNN" wording; it skips `llm-transcripts/` and
     `.git/`;
   - it swaps in two steps (old → a placeholder that cannot occur in text →
     new), so an old number that is also another issue's new number cannot
     be rewritten twice;
   - it reports every file it changed and every line that mentions a
     three-digit number it chose not to touch, for a human to check;
   - it has its own test on a scratch copy.
5. **Run it**, review the report, run every `scripts/test-*.sh`, then commit
   the renames and the rewritten references together so git records the
   moves.
6. **Progress files and demos**: one `issues/phase-N-progress.md` per phase
   (naming the dashboard command rather than copying counts), phase demos
   under `issues/completed/demos/`, the table of contents updated.  Retire
   the overflow note in `phase-4-progress.md`.

## Open Questions

All three answered 2026-10-04 (see Status):

1. **Are the nine themes right?**  Yes, as proposed.
2. **Does "foundations first" apply across phases too?**  Yes — left to
   this session's judgment ("you know how to number phases").
3. **The Android client's own history.**  Phase 8's blueprints are written
   in this pass.

## Related

- #121 (a sync in planned passes) — will change phase 1's core a great
  deal; its blueprint is best written after it is built.
- `issues/phase-3-progress.md`, `issues/phase-4-progress.md` — replaced by
  per-phase files once this is done.

## Origin

2026-09-23.  The decoy-traffic issue could not be renumbered into phase 3
(every number taken), which led to looking at the phases as a whole.
Owner: "I'm amazed we used 100 issue names in one phase. What do the other
phases look like? Can we re-sort the phase numbers? There should be up to
9. ... I think this project also implemented a majority of it's
functionality on my laptop, and I don't have the same claude.md file there
(on purpose) so my laptop doesn't create issue files. ... So there's lots
of undescribed functionality. Before we release, we're gonna go back
through and re-describe the entire architecture, blue-print style, as it
should be. But that's for later."
