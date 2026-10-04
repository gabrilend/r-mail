# Conversation Summary: 44efc473-3b08-4771-8b15-67e610ded2ae

Generated on: 2026-10-04 15:28:48
Models: claude-opus-5-5

## Contents

1. 2026-10-04 13:47, after Request 2 - I'm answering your four questions from
   the last round: the discovery test fails because this machine's firewall
   drops the packets, and six built issues are now completed and committed.
   Next, I need your answers to my seven open questions, starting with whether
   to split the half-built address-announcement issue.
2. 2026-10-04 14:06, after Request 3 - We're making it easy to restart every
   mailbox after an update. That script is built and tested but not committed.
   Next: tell me what the update script should be, and whether to delete the
   network discovery feature.

--------------------------------------------------------------------------------

### User Request 1

<pasted_content id="c98d">
● All four bug fixes, the attachment work and the phase re-sort are done and
committed, and every test passes except one network-discovery test that was
already failing before today.

  The bugs and the attachment work

  - Edits that never arrived. Each recipient now keeps a fingerprint of the
    version it last took. An edit stays owed to anyone who doesn't have it yet,
    and is retried each time their
    timer comes round. Before, an edit made while a contact was offline, or not yet due, was lost for good.
  - The plain "are you there?" answer now says only that something is listening.
    It no longer gives out the mailbox's name.
  - Saving contacts from the phone changes only the contacts that changed. Your
    comments, blank lines and order stay. If the merged file wouldn't read back
    as exactly what the phone
    sent, nothing is written.
  - Attachments now work as you decided:
    - Each recipient's answer is remembered per file, so a refusal is final, and someone reached late still gets the file.
    - Everyone gets the same copy, packed when the file was first offered and kept on disk until all have answered.
    - Removing an attach: line withdraws the file. Putting it back after a sync offers it again, and a changed path counts as a new file.
    - Cancelling one attachment no longer counts as deleting the whole message.
    - Pieces of an arriving file now wait on disk inside the mailbox, so a transfer survives a reboot.

  Each fix has a test that fails on the old code.

  Two more problems turned up along the way:

  - A crash when a contact announced its address. If the contact was known only
    by its key, the daemon saved the address and then crashed. Some of the older
    two-mailbox tests had been
    passing only because of this crash.
  - Two daemons locking each other up. With the crash gone, two daemons that
    each had mail for the other stalled each other every few seconds,
    indefinitely. This is a real-world
    problem, not just a test one. Now, when a daemon is sending and the contact it's dialing calls in, it answers "busy" at once and both retry shortly. Anyone else who calls is
    served as soon as the sync ends. This is part of the open blocking-sync issue, not all of it.

  The re-sort

  - Your answers are recorded: the nine themes as proposed, foundations first,
    and the Android blueprints written now.
  - 17 new issue files describe things that were built without one, including
    much of the laptop work.
  - The 30 open issues that lacked the three required sections were reorganised
    without losing any text. The issue checker now finds nothing to report.
  - All 147 issues were renumbered by a tool, and every mention of them in code
    comments, the guides, the tests and the phone app's source was rewritten.
    Transcripts were left as they
    were said. The old-to-new number map is in notes/ and can be run backwards.
  - Each phase now has a progress file generated from its issues. The old
    hand-written progress files are kept in notes/.
  - A table of contents in docs/ lists every document and the nine phases.
  - ./run-demo.sh runs a measured demo of any phase. Phase 9's demo shows that a
    sealed message's length is visible to anyone watching the network: it's the
    message length plus about
    270 bytes.

  Questions for you

  1. Older daemons and the "busy" answer. An older daemon that gets "busy" would
     read it as a refusal, and could drop an attachment offer. Your two running
     mailboxes use a different
     copy of rmail (/home/ritz/programs/r-mail). Should I worry about mixed versions, or will you update both together?
  2. The failing network-discovery test. It fails the same way on the code from
     before today, maybe because of how this machine handles the local network.
     Do you want me to
     investigate it?
  3. Seven issues that are built but still marked open: per-contact timers, the
     24–48-hourly address re-check, the phone's step-by-step sync record,
     phase 1 of the address
     announcements, the reversed hashing of names in saved state, and the two drive generators. Their files now say they're built and waiting on your check. Should I move them to
     completed?
  4. One known gap left open: the multiple-addresses issue still lists one
     unbuilt part. Damaged contact lines left by an old version (table: 0x…)
     aren't cleaned up when the file is
     read. Do you want that done now?

✻ Cogitated for 3h 0m 55s · done 12:00 PM

※ recap: The audit's bugs are fixed, the attachment rules work as you decided,
and the issues are re-sorted into nine phases with blueprints and demos;
everything is committed. Next,
  I need your answers to my four questions, starting with whether older daemons
  will meet the new "busy" answer. (disable recaps in /config)

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯  1. Older daemons and the "busy" answer. An older daemon that gets "busy"
would read it as a refusal, and could drop an attachment offer. Your two running
mailboxes use a
  different copy of rmail (/home/ritz/programs/r-mail). Should I worry about
  mixed versions, or will you update
       both together?

  huh? Isn't that this copy?

    2. The failing network-discovery test. It fails the same way on the code from before today, maybe because of how this machine handles the local network. Do you want me to
  investigate it?

  yes please investigate. Could it be because other versions of rmail aren't
  updated on my other computers?

    3. Seven issues that are built but still marked open: per-contact timers, the 24–48-hourly address re-check, the phone's step-by-step sync record, phase 1 of the address
  announcements, the reversed hashing of names in saved state, and the two drive
  generators. Their files now say
       they're built and waiting on your check. Should I move them to completed?

  yeah if they're built then they're complete. We can re-open them if needed.

    4. One known gap left open: the multiple-addresses issue still lists one unbuilt part. Damaged contact lines left by an old version (table: 0x…) aren't cleaned up when the file
  is read. Do you want that done now?

  oh, um... no, there's no more table: 0x... contacts left. I removed them all.
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
</pasted_content id="c98d">

--------------------------------------------------------------------------------

### Assistant Response 1

> Short answer to your first question: yes, it is this copy.
> `/home/ritz/programs` is a link to `/mnt/mtwo/programs`, so I was wrong there.
> Now I'm looking at the failing discovery test.

> Both test mailboxes send their "are you here?" packets, but neither one logs
> receiving the other's. Now I'm checking whether the packets reach the
> machine's network at all.

> I found a likely cause in the code. I'm running one experiment to confirm it
> before I tell you.

> Alpha's first round is done and it has stopped reading the network. Now I'll
> put a note in alpha's outbox. That makes it run another round, which reads the
> discovery socket.

> The probe couldn't find rmail's network library. I'm pointing it to the right
> library folder and running it again.

> The listener joined the group on the wired network card, as it should. The
> packet goes out but doesn't come back. Next I'll look at the firewall and the
> kernel's packet filtering.

> There's an iptables service running, and I need root to list its live rules.
> Its saved rules file is usually readable, so I'll check that instead.

I found the cause: this machine's firewall. I'll write it up once the seven
issues are moved, since you said yes to that. Loading the issue workflow first.

--------------------------------------------------------------------------------

### User Request 2

Base directory for this skill: /home/ritz/.claude/skills/issue-lifecycle

# Issue lifecycle

The owner's CLAUDE.md is the authority on what issue files are for and what
they must contain; where it and this skill ever disagree, CLAUDE.md wins. This
skill adds the mechanics CLAUDE.md leaves open: which tools answer which
question, in what order, and what to do when a tool says no.

All tools live in one place and are called by absolute path:

| Tool | Answers |
|---|---|
| `/home/ritz/programming/ai-stuff/scripts/validate-issues <project>` | is the issue tree consistent; next free number per phase |
| `validate-issues <project> --next <phase>` | the number to give a new issue |
| `validate-issues <project> --file <issue>` | is this one issue well-formed and are its links matched |
| `/home/ritz/programming/ai-stuff/scripts/progress-dashboard.lua <project> -m` | done/open counts per phase (for progress files and demos) |
| `/home/ritz/programming/ai-stuff/scripts/commit-own-changes <repo> -F -` | commits exactly the lines this session wrote, plus the changed transcripts of the commit's projects (any conversation's), and runs the repository's commit hooks, without touching the shared staging area |
| `/home/ritz/programming/ai-stuff/scripts/stage-own-changes <repo>` | previews what that commit would take; writes nothing |
| `/home/ritz/programming/ai-stuff/scripts/claim-own-change <file>` | records lines this session changed by a route the edit ledger cannot see (see Committing) |
| `/home/ritz/programming/ai-stuff/scripts/adopt-left-behind-changes <repo> -- <path>...` | takes ownership, line by line, of uncommitted work a finished session left, leaving lines any other session still holds (see Committing) |

Each tool has a `.info.md` beside it; read that rather than the source.

## Before writing a new issue

1. **Search first, including `issues/completed/`.** Grep the issue tree for
   the feature's nouns, not just the likely title. A completed issue about the
   same machinery is reopened and extended rather than duplicated: history is
   more useful stacked vertically in one file than spread across several.
2. **Pick the phase by what the work builds on**, not by when it is being
   done. Lower numbers are foundations; later issues depend on earlier ones.
3. **Take the number from the tool:** `validate-issues <project> --next
   <phase>`.
   It reads the project's own naming shape (522, 1001, 9-007, A04) and never
   reuses a number that a completed file already holds.
4. **Write the blueprint** with the three sections CLAUDE.md requires, plus
   link fields in the shape the project already uses (look at a neighbour).
   Name related functions, structures and files instead of pasting code.
5. **Check it:** `validate-issues <project> --file <new-issue>`, and fix what it
   reports on the new file. If the new issue blocks or is blocked by others,
   add the matching line to the other side too.

## While working

- Keep **Current Behavior** true. It is the only section that changes while
  an issue is in progress; rewrite it in place rather than appending a log.
- A question that surfaces is written into the issue (an "Open questions"
  section) and then asked. An issue with an unanswered question is in
  progress, not done.
- Anything discovered that changes another issue's assumptions is written into
  that issue now, not at completion.

## Splitting into sub-issues

Split when an issue holds work streams that could be built, tested or reviewed
separately, or when it cannot be finished in one sitting. Do not split an issue
that is already one mechanism. When splitting, produce and then write out:

1. **A table** — `| ID | Name | Dependencies | Description |`, where ID is the
   parent number plus a lower-case letter (103a, 103b), Name is dash-separated
   lower-case words, Dependencies is "None" or sibling IDs.
2. **The rationale** — the distinct work streams, why one issue cannot hold
   them, what splitting buys.
3. **The execution order** — a small dependency graph, e.g.
   `103a (foundation) → 103b (needs 103a) → 103c (parallel with 103b)`.

Each row becomes a file `{parent}{letter}-{name}.md` with the three sections.
The parent keeps its blueprint and gains a short list of its sub-issues; the
analysis itself is not appended to the parent (that would be worklog, not
blueprint). Run `validate-issues` afterwards: it reports orphaned sub-issues
and one-sided links.

## Completing an issue

An issue is complete only when nothing in it is deferred and no open question
is unanswered. Then, in this order:

1. **Run the project's tests.** A fixed bug gets a test that would have caught
   it.
2. **Rewrite the issue as the blueprint of what was built**: Current Behavior
   states the built system; steps name the real functions and files; decisions
   not taken are stated with their reason. Poetry the owner wrote during the
   work goes into the issue verbatim.
3. **Move it** into `issues/completed/` (`git mv`, so the history follows).
4. **Update `issues/phase-<N>-progress.md`** for that phase. Take counts from
   `progress-dashboard.lua <project> -m`, or better, name the command instead
   of copying numbers that will go stale.
5. **Update related issues** whose Current Behavior or assumptions changed.
6. **Run `validate-issues <project>`** and fix new findings that the change
   caused. Findings older than the change are reported to the owner, not
   silently fixed in passing.
7. **Commit** as below.

## Committing

The rule (CLAUDE.md): a commit carries exactly the lines this session wrote —
never another session's work, even if it sits in the same file — and every
changed transcript of the commit's projects rides along — the session's own
project folder and the projects of the files it commits — this
conversation's and any other's left behind (a session that committed, talked
on and quit), so each project's story in git stays whole.

Commit small and often: each piece as soon as it is done and checked, not a
pile at the end.

1. Optionally preview: `stage-own-changes <repo>` lists what would be taken
   and what left out, and writes nothing.
2. Commit: `commit-own-changes <repo> -F -` with the message on standard
   input. It builds the commit on a private staging list from this session's
   own lines (the edit ledger the edit hook keeps) plus those transcripts, and
   never touches the shared staging area, so nothing another
   session has staged can ride along. Plain `git commit` is refused by the
   commit gate.
3. Message style: say what the software now does, in plain English and by
   mechanism or analogy; mention any extra changes and why. No function names.

**When it stops or leaves something out.**

- **A tangled ("mixed") block** means another session changed lines right
  next to or on top of yours. Nothing is committed. Tell the owner which file
  and line; decide together what that region should say. `--leave-mixed`
  commits your other blocks meanwhile.
- **Lines that are yours but were written by a route the ledger could not see**
  (a script you ran, a generator, `sed`, a rename): record them with
  `claim-own-change <file>` and say so in the commit message.
- **Nothing to commit, but the work is there**: an earlier session wrote it
  and ended, or the machine rebooted and emptied the ledgers. Look first with
  `adopt-left-behind-changes <repo> --dry-run -- <path>...`, then adopt and
  commit one batch at a time with `commit-own-changes <repo> -F - --
  <path>...`. Lines reported as **held** belong to another session. Take them
  (`--from <session>`) only if that session has finished, and ask the owner
  if unsure. Say in the commit message that the work was adopted and from
  whom. This is the route for a left-behind backlog, not the token.
- **A warning about the shared staging area** means someone had staged that
  file by hand in a way that overlaps your commit; their entry was left alone.
  Tell the owner.

The one-time permission tokens (`/tmp/claude-allow-*`) belong to the person.
Never create one; if a gate names a token, relay the gate's message and let
the owner decide.

## Open questions

- Phase ≥ 10 in compact names depends on the project's issue-number width;
  `validate-issues` decides it from evidence (progress files, `phase-N-demo`
  names). A project with none of those gets a warning. Should the house rule
  fix one width (two digits, as in the 522 example) for every new project?


ARGUMENTS: complete seven built-but-open issues: per-contact timers,
24–48-hourly address re-check, phone step-by-step sync record, phase 1 of
address announcements, reversed hashing of names in saved state, two drive
generators

--------------------------------------------------------------------------------

### Assistant Response 2

> Now I'll edit the six issues' opening paragraphs.

> Now the two drive issues:

> The six are edited. Before moving them, I'm checking whether anything links to
> their current paths.

> All six are moved. Next I'll regenerate the progress files and run the issue
> checker.

> The progress files changed because my generator run rewrote them, so I'm
> recording them as this session's work.

> The preview takes the six moves, five progress files and the transcript, and
> nothing else. Committing.

*[commit] f615f844c in r-mail - Six built issues closed: contact timers, address re-check, phone sync record, state names, both drive makers*

> The commit went through. The warnings come from my own moves: moving a file
> with git also records the move in git's shared staging area. I'm checking that
> what's left there matches the commit.

> The files on disk match the commit. Git's staging area still held the unedited
> copies my moves put there, so I'm resetting those five entries to match the
> commit.

The discovery test failure comes from this machine's firewall, not from your
other computers. I also moved six of the seven issues to completed and committed
them. The seventh is only half built, so I left it open; there's a question
about it below.

## 1. Which copy the mailboxes run

You're right, and I was wrong. `/home/ritz/programs` is a link to
`/mnt/mtwo/programs`, so your two mailboxes run the same `rmail.lua` I've been
editing.

One catch remains: both daemons started at 6:40 this morning, before today's
fixes were committed at 10:38. A running program keeps the version it loaded at
startup, so they are still running the old code. They pick up the fixes,
including the "busy" answer, when you restart them (`kuvalu-mail` and
`kuvalu-notes` in your service list). There's no mixed-version problem beyond
that.

## 2. The failing network-discovery test

**Cause: the firewall written on October 3.** That's why it also failed on
yesterday's code.

- The test starts two throwaway mailboxes on this computer, on ports 59391 and
  59392. They find each other by sending a packet to a multicast group, an
  address that any program on the network can sign up to listen on.
- The firewall rules at `/etc/iptables/iptables.rules` drop all incoming traffic
  except a short list. UDP is allowed only on 8025 and 8026, your two real
  mailboxes.
- When this computer hears its own multicast packet, the kernel treats it as
  arriving on the wired network card, not as internal traffic. The firewall
  checks it like any outside packet and drops it, because 59392 isn't on the
  list.

To confirm this, I ran a small probe outside rmail that listens on the same
group:

| Packet sent to | Arrived? | Why |
|---|---|---|
| the multicast group | no | comes back in through the wired card, so the firewall drops it |
| this machine's own network address (192.168.1.100) | yes | the kernel routes it internally, and internal traffic is always allowed |
| 127.0.0.1 | yes | same reason |

Your other computers aren't involved. The packets are encrypted with a token
only the two test mailboxes share, and nothing from outside reached the test.

Your real mailboxes are not affected by this, because they use 8025 and 8026,
which the firewall allows. But I found two real problems while looking:

- **Your running mailboxes never joined the group.** Both logs say "failed to
  join multicast group" at 6:40:23, probably because the network wasn't up yet
  at boot. rmail tries once and never again, so neither mailbox can hear
  discovery packets until it is restarted.
- **Discovery packets are only read when a sync round starts.** The main loop
  sleeps until a connection comes in, a file changes, or a contact's timer comes
  due. The discovery socket isn't on that list. So a neighbour's "are you here?"
  sits unread until the next round, which can be 6½ minutes or more once a
  contact has backed off. The old fixed sync interval hid this; the per-contact
  timers exposed it. I confirmed it by putting a file in a test outbox, which
  forced a round: that round found the socket empty, because the firewall had
  already dropped the packet.

I haven't changed any code for these. Questions 5–7 below ask what you want
done.

## 3. The seven issues

Six moved to completed and committed, with the phase progress files regenerated.
The issue checker reports nothing. The six are:

- per-contact timers
- the 24–48 hour address re-check
- the phone's step-by-step sync record
- the reversed hashing of names in saved state
- the portable mailbox drive generator
- the installer drive generator

Each file says it was closed on your word and can be re-opened. The two drive
issues also note that no drive made by them has been tried on a second machine
yet.

**Not moved: the address announcements.** Its first half is built. The second
half, keeping owed announcements as files in the mailbox instead of one hidden
list, was never started. My earlier wording "phase 1 of the address
announcements" made it sound finished.

## 4. Damaged contact lines

Understood, nothing to clean up.

## Open questions

1. **The address-announcement issue:** should I split the unbuilt second half
   into its own issue so the built half can be completed? Or keep it as one open
   issue?
2. **The multiple-addresses issue:** you've removed all the damaged contact
   lines, so should I remove that unbuilt part from the issue? If it was the
   last thing open, the issue could then be completed. I haven't checked yet
   whether anything else in it is unbuilt.
3. **Restart the two daemons?** That loads today's fixes and retries joining the
   multicast group. Do you want to do it, or should I?
4. **The test itself:** do you want to change the firewall, which needs root?
   The alternative is to make the test detect a firewall block and say so
   instead of reporting a plain failure. Or both?
5. **Retrying the group join:** should rmail keep trying to join the multicast
   group after a failure at boot, instead of trying once?
6. **Reading discovery packets right away:** should the discovery socket be
   added to the list of things that wake the main loop, so a neighbour gets an
   answer within a second instead of at the next round?
7. **Skipping its own address:** each mailbox also sends its discovery packet
   directly to every address on the local network except its own. Two mailboxes
   on the same computer therefore depend on multicast alone. Should a mailbox
   also try its own address? The catch is that it would then hear its own
   packet, and a mailbox that shares a token with a contact would read its own
   packet as that contact's.

--------------------------------------------------------------------------------

### User Request 3

> One catch remains: both daemons started at 6:40 this morning, before today's
> fixes were committed at 10:38. A running program keeps the version it loaded
> at startup, so they are still running the old code. They pick up the fixes,
> including the "busy" answer, when you restart them
> (kuvalu-mail and kuvalu-notes in your service list). There's no mixed-version
> problem beyond that.

can we build a script that restarts-all-mailboxes and has a list at the top of
the script (or taken as arguments) of all the service names it should restart?
Then it runs the appropriate service restarting commands. It's important that
it's a variable at the top of the script (can we gitignore specific lines? No,
probably not... Hmmm...) so that users can restart their own list of mailboxes
if they do an update. And we should include calling that script into the
"update" script. Also, maybe we should do like we do with the documentation, and
have a script template with an empty list, and if you run it without a list of
entries it says "type the name of each mailbox, and push enter after each name.
When you're done, provide a blank name, or push enter twice, double-click
style." and then it populates the instantiated script file, which was created
from the template during the installation phase, if it didn't already exist.
This script should go in the program directory, not in the mailboxes. And I
guess we can have the template have each type of service to restart, but we'd
only need to put one of them into the built script.

  - The test starts two throwaway mailboxes on this computer, on ports 59391
    and 59392. They find each other by sending a packet to a multicast group,
    an address that any program on the network can sign up to listen on.

I don't think we should allow multicast groups, because they break the security
model. If multiple people can listen on a network, then a compromised system
could listen to that multicast address without "claiming" the port number with
the OS, who then receives it from the router and only the router. The router has
to send one port to exactly one address, always.

> 2. The multiple-addresses issue: you've removed all the damaged contact lines,
> so should I remove that unbuilt part from the issue? If it was the last thing
> open, the issue could then be completed. I haven't checked yet whether
> anything else in it is unbuilt.

sure.

> 6. Reading discovery packets right away: should the discovery socket be added
> to the list of things that wake the main loop, so a neighbour gets an answer
> within a second instead of at the next round?

what are discovery packets? Why do we need them?

--------------------------------------------------------------------------------

### Assistant Response 3

> Your answer is all the multiple-addresses issue needed. I'm recording that the
> cleanup was decided against, and why, and then completing it.

*[commit] 396eab2c0 in r-mail - Multiple addresses per contact: complete, with the load-time cleanup decided against*

> The multiple-addresses issue is done. Next is the restart script. I'm reading
> how the installer sets up services and where the update script is.

> I haven't found an update script yet. The only match so far is a mailbox hook
> called `on_update`, so I'm checking what that is.

> Two existing issues might overlap: one about mailboxes being self-contained
> installations, and one about service names. Reading both.

> I have the design. Before writing the issue I'm checking which phase covers
> installing.

> Now writing the issue for the restart script:

> The issue is written and passes the checker. Now the template. It holds all
> four restart methods, one folded block each, and the builder keeps only one.

> Now the installer step and the ignore line:

> All 17 cases pass on the first run. Before trusting that, I'll look at the
> actual output: the script built for this machine, and what the prompt looks
> like on screen.

> The built script has only the runit block, git ignores it, and its list is
> empty. Your service guide should mention the script, so I'm finding the right
> spot in it.

> The guide is updated. Now the issue's current-behavior section: everything is
> built except the update-script step, which is waiting on your answer.

> The restart script is done for now. I'm reading the existing issue about
> dropping network auto-detection, since it may already plan to remove
> discovery.

> That issue already plans to remove discovery completely. I'm reading the rest
> of it for anything still undecided.

> Issue #418 already plans to delete all of it. Your objection to multicast is a
> new reason, so I'm adding it there along with what today's investigation
> found.

I built the restart script and tested it, but haven't committed it yet. Its
issue is still open because rmail has no update script to call it from.
Discovery packets are a workaround the project already plans to remove, for
reasons that include your multicast objection.

## The restart-all-mailboxes script

- **Template:** `scripts/.templates/restart-mailboxes.sh` is tracked by git. It
  has the list at the top, and one folded block for each service manager: runit,
  systemd, OpenRC and NixOS.
- **Builder:** `scripts/make-restart-script.sh <manager>` builds
  `restart-mailboxes.sh` in the program folder from the template. It keeps only
  that manager's block and fills in the folder path. If a built copy already
  exists it is left alone, so your list survives re-installs. `--force` rebuilds
  it and empties the list.
- **Git:** it can't ignore single lines, only whole files, so your guess was
  right. The built script is in `.gitignore` and the template is tracked, the
  same way the docs work.
- **Installer:** builds the script once it knows the service manager, if no copy
  exists yet.
- **Running it:**
  - With no arguments it restarts everyone in the list.
  - `./restart-mailboxes.sh kuvalu-notes` restarts only that one, once, and
    leaves the list alone.
  - With an empty list it asks: "Type the service name of each mailbox, pressing
    enter after each one. When you're done, give a blank name (press enter
    twice)." It then saves the names into its own list line.
- **Checks:** every name is checked before anything restarts, so a typo can't
  leave half the mailboxes on the new code. Three seconds after restarting, it
  asks whether each service is running again, and fails if any isn't.
- **Root:** runit, OpenRC, NixOS and systemd system services are restarted
  through `sudo`. systemd user services don't need it.
- **Tests:** `scripts/test-restart-mailboxes.sh` runs 17 cases against stand-in
  service commands that only record what they're asked to do. All pass.
- The service guide has a new section describing it.

This machine's copy is built (runit, empty list) but I haven't run it, because
it needs your sudo password. To restart your two mailboxes onto today's code,
run it once from a terminal and type `kuvalu-mail`, `kuvalu-notes`, then a blank
line.

## What discovery packets are

Both your mailboxes sit behind one home router, so the outside world sees them
at one public address, 97.120.253.166. A contact entry usually holds that public
address. When a mailbox connects to its own public address from inside the
house, the packet goes out to the router and has to be turned around and sent
back in. Many routers won't do that turnaround. The test log shows it: "timeout
connecting to 97.120.253.166:59392" after 8 seconds.

Discovery was the workaround. A mailbox that notices a contact shares its own
public address sends an encrypted "are you here? I'm at 192.168.1.100, port N".
It sends that to a multicast group and also to every address from .1 to .254 on
the local network. Whichever mailbox's shared password opens the packet records
the sender's local address, answers "here, I'm at 192.168.x.x", and connections
from then on use the local address.

**We no longer need them.** Since the address-announcement work, a contact can
carry a local-address line, written by hand or announced automatically to a
contact on the same local network. An open issue already plans to delete
discovery completely: the multicast, the scan of all 254 addresses, and the
network socket they use. I added your objection to that issue, along with
today's findings:

- the mailboxes fail to join the group at boot and never retry;
- discovery packets are only read at the start of a sync round;
- the firewall drops the machine's own multicast packet when it comes back in.

**One correction on the security point.** Multicast set to stay on the local
network never leaves your house, and routers don't pass it in from the internet.
Your port forward still sends 8025 to exactly one machine. What it breaks is the
inside of the house: any device on your network can join the group and hear the
packets. The 254-address scan is just as bad, since it hands the same packet to
every device. The packets are encrypted, but their arrival still tells any
listener that an rmail mailbox is at 192.168.1.100, on which port, and how often
it syncs. Deleting discovery removes both.

## Also done

The multiple-addresses issue is complete and committed. The cleanup of damaged
contact lines is recorded as decided against, with your reason.

## Questions

1. **Delete discovery now?** That removes the multicast, the 254-address scan,
   the network socket they use, and the failing test. It also converts any
   old-style `lan_ip` contact lines into the newer local-address lines.
2. **What is "the update script"?** None exists. Options, most likely first:
   - (a) a new `update.sh` in the program folder that pulls the new code,
     rebuilds the libraries if their sources changed, then runs
     `restart-mailboxes.sh`;
   - (b) the installer runs the restart at its end, since re-running it is the
     closest thing to an update today;
   - (c) updating stays `git pull`, plus a printed reminder to restart.

   The restart-script issue stays open until this is answered, which is why it
   isn't committed.
3. **Should the installer add the service it just created to the restart list?**
   Right now the list starts empty and the first run asks, as you described.
   Adding it automatically would mean the list is never empty on a machine where
   you installed through the installer.

--------------------------------------------------------------------------------

### User Request 4

> - Template: scripts/.templates/restart-mailboxes.sh is tracked by git. It has
> the list at the top, and one folded block for each service manager: runit,
> systemd, OpenRC and NixOS.

do we put the service files in there too? Also, do we update the documentation
depending on what OS the user is running, in the same way that we're handling
the restart-mailboxes.sh script?

> 1. Delete discovery now? That removes the multicast, the 254-address scan, the
> network socket they use, and the failing test. It also converts any old-style
> lan_ip contact lines into the newer local-address lines.

great

>   2. What is "the update script"? None exists. Options, most likely first:
>      - (b) the installer runs the restart at its end, since re-running it is the closest thing to an update today;
>
> 3. Should the installer add the service it just created to the restart list?
> Right now the list starts empty and the first run asks, as you described.
> Adding it automatically would mean the list is never empty on a machine where
> you installed through the installer.

yep

--------------------------------------------------------------------------------

### Assistant Response 4

> I'll start with the installer changes (restart at the end, add the new service
> to the list), then delete discovery. First, how the installer asks yes/no
> questions:

> The script side is done. Now the installer: it remembers whether this run set
> up a service, adds that service to the list, and offers a restart at the very
> end.

> Now the restart at the end of the installer:

> The installer side is done. I'll add test cases for `--add` and `--check`,
> then run the tests and a syntax check of the installer.

> All 21 cases pass. Next I'm confirming the installer accepts the new
> `--restart-mailboxes` flag.

> It does. This machine's copy was built from the older template, so I'm
> rebuilding it. Then I'm adding your two mailboxes, as the installer would have
> done if it had set them up.

> Both are listed and both are installed runit services. I'm correcting one
> outdated line in the builder's message and updating the guide.

> Now I'm rewriting the issue to match what was built, with your answers
> recorded, so it can be completed.

> The preview would also take my note on the discovery issue, which belongs to
> the next piece of work. I'll leave that file out by naming the restart files
> explicitly.

*[commit] 9008f64a1 in r-mail - One script restarts every mailbox after an update, with its list kept per machine*

> The restart work is committed. Now deleting discovery. I'm finding every part
> of the daemon, the tests, the docs and the phone app that touches it.

> The discovery code runs from line 7509 to line 7637. I'm cutting it and
> leaving a short note saying where it went and why.

> The block is gone. Now the leftover pieces elsewhere that called into it.
> First, the packet encryption helpers, which only discovery used:

> Now the five remaining spots: the polling step, the runtime table, opening the
> network socket, the boot-time broadcast, and the per-round reset.

> The timed re-check now depends on whether the boot-time lookups worked. Next
> the boot-time lookups themselves need to report that:

> The public-address check already reports a failed lookup the same way. The
> timed re-check should also count a failed local-address lookup as "try again
> in an hour":

> Both Lua versions parse it. Now I'm checking for stray references, and for
> comments that still describe discovery as existing.

> Before the tidying passes, I'm adding a small conversion step: any old
> `name.lan_ip = X` line becomes a `local-ip` line, or is dropped if that
> contact already has the same address.

> All nine pass. A test is only worth something if it fails on the old code, so
> I'll run it against the last committed version, unpacked into a scratch
> folder.

> The full run is going in the background. While it runs, I'm finding every
> document that still describes discovery.

> Most matches are history: completed issues and notes. The ones that describe
> the program as it is now are the README, the QA checklist, the phase 4 demo,
> and three open issues. I'm reading those.

> Now updating each of them: the README first.

> Next, the three completed issues that built discovery each get a note at the
> top saying it has since been removed, so anyone rebuilding the project from
> its issues knows what happened.

> The local-address lookup belongs to the address re-check issue, so I'm adding
> a follow-up there describing the corrected behavior.

> Now I'm updating the discovery issue itself: what's removed, and what's left
> waiting on your answer.

> The full test run is about a quarter done, with five passes so far. I'll wait
> for it to finish.

> One failure so far: `test-busy-while-sending`, the test for this morning's fix
> where two mailboxes calling each other at once answer "busy". Reading its log:

> The daemon dialed alice, the stand-in recipient, at 14:39:53, and the
> connection was refused: nothing was listening on alice's port yet. I'm reading
> when the test starts alice.

> The stand-in recipient couldn't start: port 59506 was already taken. Finding
> what holds it:

> The zip test fails because rmail's copy of your shared zip library no longer
> matches the original in `my-libs`. Checking when each was last changed:

> I'm recording the two files changed by commands the edit ledger can't see (the
> cut from the daemon, and the note added to the address re-check issue), so a
> later commit includes them.

Discovery is gone from the daemon and every test passes, but I haven't committed
it. Your rule is to commit once an issue is finished, and the discovery issue
still has an open question (number 2 below). The restart-script work is
committed.

## Discovery: deleted

- The multicast group, the scan of all 254 local addresses, the replies, and the
  daemon's UDP socket are gone. The daemon now listens only on TCP, and its
  startup line says "(TCP+IPv6)".
- Old `name.lan_ip` lines in a contacts file are rewritten as `name.local-ip`
  lines at startup, and each rewrite is logged.
- `scripts/test-lan-discovery-names.sh` is deleted. The README, the QA
  checklist, the phase 4 demo and the three completed discovery issues now say
  discovery was removed and why.
- The firewall rule you added on October 3 that allows UDP on 8025 and 8026
  isn't needed any more. It's root's to remove.

**A bug turned up that the deletion would have exposed.** Both your mailboxes
had recorded their own home-network address as **127.0.0.1**, which is loopback,
not the home network.

- **Cause:** at boot the network isn't up, so the routing table can't say which
  address the machine sends from. The daemon then fell back to a guess that
  searched the interface list badly and returned 127.0.0.1 on every machine.
- **Effect:** your two mailboxes weren't trying each other's `local-ip`
  addresses, because a mailbox only does that when both addresses look like the
  same home network. An older step had been quietly swapping in the right
  address anyway, which hid the problem.
- **Fixed:**
  - no answer from the routing table now means "unknown", never a guess;
  - a recorded loopback value is replaced without sending you a false "your
    address changed" notice;
  - a lookup that fails at boot is retried in an hour instead of 24–48 hours.

`scripts/test-home-address.sh` covers this. Against yesterday's code 8 of its 9
checks fail; against today's all 9 pass. The one case it can't check is the
routing table having no answer at all, because simulating that needs root.

**Full test run:** 24 of 26 tests passed.

- The "busy" test failed once because some short-lived connection briefly held
  its port. It passed when I ran it again alone.
- The zip library test fails because this morning's renumbering tool rewrote two
  issue-number comments inside rmail's copy of your shared zip library. The
  original in `my-libs` still has the old numbers. Today's change didn't cause
  it.

Your running mailboxes still have the old code. Once this is committed,
`./restart-mailboxes.sh` (it asks for your sudo password) loads it. It already
lists `kuvalu-mail` and `kuvalu-notes`; I added them myself.

## Your two questions

**Are the service files in the templates folder?** No. The installer writes each
one from text kept inside `install.sh`, one block per service manager, filling
in paths as it goes. Moving them into `scripts/.templates/` would make them
files you can read and edit directly, built the same way as the restart script.

**Are the docs tailored to the user's service manager?** No. Building the docs
only swaps in three paths (where the program is, where the mailbox is, and where
Lua is), so `service.md` shows all four managers to everyone. Keeping only this
machine's section the same way is possible. The downside is that someone helping
a friend on a different system would only see their own system's section in the
built docs, though the templates would still have all four.

## Questions

1. **Templates:** do you want the service files moved into templates, the
   service guide trimmed to this machine's service manager, both, or neither?
2. **The rest of the discovery issue:** none of it broadcasts, so it doesn't
   break your one-address rule.
   - The address-swap step and the quieter step that learns a local address from
     a contact's incoming connection. The learning step is the only thing that
     can find a same-house contact with no `local-ip` line on either side, but
     it forgets on restart. With the 127.0.0.1 bug fixed, `local-ip` lines work
     without the swap.
   - A "where am I in your contacts?" request that nothing calls, its config
     setting, and an unused function in the phone app.
   - A "local address" field in the answer the phone gets when it asks the
     daemon for its address.

   Delete these as well, or keep them?
3. **Commit now?** Should I commit the discovery deletion and the address fix
   now, or wait until question 2 is settled and the issue is finished?
4. **The zip library:** may I update the two comments in `my-libs/zip` to the
   new issue numbers (#309 and #311a) so the copies match again? That's a
   different project, so I didn't touch it.

--------------------------------------------------------------------------------

### User Request 5

> 1. Templates: do you want the service files moved into templates, the service
> guide trimmed to this machine's service manager, both, or neither?

yes please

> 2. The rest of the discovery issue: none of it broadcasts, so it doesn't break
> your one-address rule.

great, let's delete these for now since we don't need them.

> 3. Commit now? Should I commit the discovery deletion and the address fix now,
> or wait until question 2 is settled and the issue is finished?

we can commit when you get to a breaking point. A time to stop because we've
concluded and finished up some tasks. Not if they're still in-progress, but
*completed*.

> 4. The zip library: may I update the two comments in my-libs/zip to the new
> issue numbers (#309 and #311a) so the copies match again? That's a different
> project, so I didn't touch it.

sure?

--------------------------------------------------------------------------------

### Assistant Response 5

> I'll finish the discovery issue first and commit it, then do the templates,
> then the zip comments. First, every remaining piece of the discovery issue in
> the daemon:

> I'll delete the learning step now. Before deleting the "where am I in your
> contacts?" request, I'm checking that nothing in the phone app actually calls
> it, since its comment claims phones use it.

> Only defined, never called. Removing it from the daemon:

> Removing it from the README and the protocol guide:

> Now the address swap. It runs in four places; removing each:

> With the swap gone, nothing calls the hostname-lookup helper any more; it only
> existed to feed the swap. Checking it and its small cache:

> Now checking the comment that mentioned the cache, and that the daemon still
> parses:

> The daemon side of the remaining pieces is gone and parses. I'm now pointing
> the docs and issues away from the deleted test.

> A message got through using the `local-ip` line alone, with no discovery and
> no swap. I'm adding this test to the phase 4 demo, then rewriting the
> discovery issue as a finished blueprint.

> There are three changed lines, not two: the writer has one as well. Checking
> the rest of the zip folder for other old rmail issue numbers:

> The renumbering map confirms the old #405 is now #309 and the old #404a is now
> #311a. Five places in all: the reader (2), the writer (1), and the two
> description files beside them.

> The zip test passes. Previewing a commit in the `ai-stuff` repository limited
> to the four zip files:

> It takes exactly the five edited lines and nothing else. Committing:

*[commit] 48d4f0b2a in ai-stuff - Zip library: rmail's issue numbers brought up to date after its renumbering*

> The zip fix is committed. Now the full rmail test run, in the background,
> before committing the discovery work:

> While the tests run, I'm reading the service guide's layout to plan the
> templates work.

> I'm checking whether an existing issue covers this before writing a new one.
> The completed "documents built from templates at install time" issue is the
> obvious candidate:

> Now the implementation steps for the extension, at the end of the issue:

> I'm moving this detection into its own small script, so the installer and the
> docs builder can't disagree about which service manager the machine runs.

> It says runit, which is right. Replacing the installer's inline detection with
> a call to it, and adding the template-filling function:

> Now each of the six inline blocks becomes a single call. Re-reading that part
> of the installer:

> 112 lines removed, exactly the six blocks, and it parses. Putting it in place:

> The six calls sit exactly where the blocks were, with the existing `chmod` and
> messages kept. Now the service guide: fold markers round each manager's
> section.

> Now the docs builder: after filling in the paths, it keeps only the section
> for this machine's service manager and drops the markers. When no manager is
> found it keeps every section and says so.

> The docs builder borrows the installer's function and calls `info`, so I'm
> checking that both scripts define it, then giving `generate-docs.sh` the
> detected manager:

> One problem: the function looks for templates inside the program folder, so
> the sample program folder must be the real checkout. I'm switching both
> renders to that path:

> Every case passes. One untidy line: the first lift complained that the scratch
> file didn't exist yet. Creating the file first fixes that:

> Clean now. Next a real run of `generate-docs.sh` for this machine, to check
> the standalone script works end to end:

> This machine's guide now shows only the runit section, plus the sections every
> reader needs. Checking on the full test run:

> The run is on its first test, which is a slow one. While it runs I'm writing
> up the reopened templates issue as finished:

> The issue is written up. Waiting for the full test run before committing
> anything:

> `test-edit-delivery` failed this time; it passed in the previous run, and the
> daemon has changed since. Reading why:

> It passes alone. Waiting for the rest of the full run:

> The preview takes exactly this session's work, split cleanly between the two
> issues. Committing the discovery removal first, naming only its files:

*[commit] 128d467e3 in r-mail - Mailboxes no longer look for each other on the home network; a contact's local address is written down instead*

> Committed. Now the templates work:

*[commit] 72badcb15 in r-mail - Service files come from templates, and the service guide shows only this machine's service manager*

> Both are committed. Checking the working tree for stale staged copies left by
> the moves:

All four things you approved are done and committed, the working tree is clean,
and every test passes. I kept one item you said to delete, because the phone
uses it.

## Discovery and the rest of its issue

Deleted:

- the multicast and the 254-address scan;
- the step that swapped in a contact's local address;
- the step that learned local addresses from incoming connections;
- the "where am I in your contacts?" request, its setting, and the phone's
  function for it;
- a small hostname cache that only the swap used.

Old `lan_ip` contact lines are rewritten as `local-ip` lines when a mailbox
starts.

**Kept, against what you approved:** the local-address field in the answer your
phone gets from its home computer. I described it to you as unused, but the
phone app stores that address and tries it first when picking where to connect.
Deleting it would have taken that away. If you still want it gone, it's a few
lines.

**The 127.0.0.1 fix is in this commit.** Your mailboxes had recorded their own
home address as loopback, and the swap step was hiding the mistake. A new test,
`test-local-ip-delivery.sh`, checks that two mailboxes in one house now deliver
to each other using only their `local-ip` lines.

I removed an unused function from the phone app's code but didn't rebuild the
app. Nothing called that function, so the change is safe.

## Service files and the service guide

- The six service files the installer writes are now template files in
  `scripts/.templates/services/`. Filled with the same values, all six are byte
  for byte identical to what the installer wrote before. I checked this with
  paths containing `&` and `|`, which are special characters for the
  substitution tool.
- The service guide built into `docs/` shows only your machine's service
  manager. Yours shows runit, plus the sections everyone needs. The templates in
  the repository still have all four.
- One small script now decides which service manager a machine runs, and both
  the installer and the docs builder use it.
- `test-service-templates.sh` checks all of this.

## Zip library

I updated the comments in `my-libs/zip` to the new issue numbers and committed
only those five lines in the `ai-stuff` repository. That repository has a lot of
other uncommitted work, which I left alone. rmail's zip test passes again.

## Tests

All 27 tests pass. Two failed during the full runs and passed when run alone:
the "busy" test and the edit-delivery test. Both times, a test mailbox couldn't
take its port because something else held it for a moment. Every test port is in
the 59000s, inside the range Linux uses for its own outgoing connections
(32768–60999), so this will keep happening now and then. Moving the test ports
below 32768 would fix it.

## For you to do

- **Restart the mailboxes:** run `./restart-mailboxes.sh`. Both mailboxes are on
  its list, and it will ask for your sudo password. Until then they keep running
  this morning's code, still with discovery and still holding 127.0.0.1 as their
  home address.
- **Firewall:** the UDP rule for ports 8025 and 8026 isn't needed any more. It's
  root's to remove.

## Questions

1. **Test ports:** move every test port below 32768 so these random failures
   stop?
2. **The phone's local-address field:** keep it, or remove it too?
3. **Guide examples:** the examples in the service guide are written by hand,
   and they've already drifted from the real service files. The systemd examples
   are missing the log lines the installer writes. Should the guide include the
   actual templates instead, filled with example values, so they can't drift?

--------------------------------------------------------------------------------

### User Request 6

Hi where are we at with issue file 714?

> - Firewall: the UDP rule for ports 8025 and 8026 isn't needed any more. It's
> root's to remove.

tell me the command to do so?

[ritz@kuvalu r-mail]$ mv ./restart-mailboxes.sh ./scripts
[ritz@kuvalu r-mail]$ cd scripts


<pasted_content id="c98d">
$ ./restart-mailboxes.sh

rmail: restarting mailboxes (runit)

Password:
  ok   restarted kuvalu-mail
  ok   restarted kuvalu-notes

  ok   kuvalu-mail is running
  ok   kuvalu-notes is running

  every mailbox restarted
</pasted_content id="c98d">


>   2. The phone's local-address field: keep it, or remove it too?

what's the argument for removing it? My understanding is that we first assume
the user is at home when they're using their phone, so we try the local address
first, then if they aren't, they try the public IP. Is that right?

> 3. Guide examples: the examples in the service guide are written by hand, and
> they've already drifted from the real service files. The systemd examples are
> missing the log lines the
>      installer writes. Should the guide include the actual templates instead, filled with example values, so they can't drift?

Yeah probably

--------------------------------------------------------------------------------

### Assistant Response 6

> I'll answer your questions first, then build the guide examples from the
> templates. Starting with issue 714, and with what this machine's firewall
> files hold for UDP:

> I'm reopening the docs-templates issue for this; it already lists this as its
> "possible next step":

> The tool has a bug: the way it splits and rejoins lines would drop the file's
> final newline, so it would report a change on every run. Fixing that:

> Now rewriting the service guide: the introduction explains the example values,
> and each hand-written example becomes a marked spot the tool fills.

> Now running the tool: first in checking mode, which should report all six
> empty examples as out of date, then for real.

> The runit example now reads exactly as the installer writes it. Next, the docs
> builder drops the example markers as well as the manager markers:

> The marker check I just wrote is wrong: it pipes the output of a silent `grep
> -q` into another grep, so it can never fail. Fixing it:

> On this machine the built guide shows its real paths, and the runit example is
> exactly what the installer writes. Completing the issue: updating its current
> behavior, then moving it to completed.

*[commit] 6bcb94729 in r-mail - The service guide's examples are now the installer's own templates, so they cannot drift*

Everything is committed except your moved restart script. Issue 714 hasn't been
started.

## Issue 714: publish a message as a web page

Nothing is built yet. The design is written and nearly complete:

- You write `to: url` in an outbox message instead of a contact's name.
- rmail adds a `URL:` line to the file, with an address made of dictionary
  words.
- Anyone who has that address can open the message in a browser, with images
  shown inline and other files offered as downloads.
- It's served over plain HTTP on its own port, with no JavaScript. Light and
  dark themes come from the reader's browser settings.

Three questions in it are still open. They need your answers before building
starts:

1. **The word list for the addresses:** ship a ready-made list with rmail, or
   build one at install time from the machine's dictionary
   (`/usr/share/dict/words`)?
2. **Is publishing part of sending?** Does it pass through the same send steps
   as a normal message, or is it entirely separate, triggered only by `to: url`?
3. **Private files below `to: url`:** an `attach:` line applies to every `to:`
   line above it in the message. So `to: url` publishes every file listed after
   it, including one meant only for a contact further down. Should rmail guard
   against that, or is it up to whoever writes the message?

## Firewall commands

The UDP rule is in both firewall files, IPv4 and IPv6. These remove it from the
running firewall and from the saved files that load at boot, and fix the two
comments that say "tcp+udp":

```sh
sudo iptables -D INPUT -p udp -m multiport --dports 8025,8026 -j ACCEPT
sudo ip6tables -D INPUT -p udp -m multiport --dports 8025,8026 -j ACCEPT
sudo sed -i '/-A INPUT -p udp -m multiport --dports 8025,8026 -j ACCEPT/d' /etc/iptables/iptables.rules /etc/iptables/ip6tables.rules
sudo sed -i 's/tcp+udp/tcp    /' /etc/iptables/iptables.rules
```

To check: `sudo iptables -S INPUT` should list 8025,8026 for TCP only. `grep -n
udp /etc/iptables/*.rules` should show only the DHCP lines and the
virtual-machine lines.

## The phone's local-address field

Your understanding is close, with one refinement: the phone doesn't assume it's
at home, it checks.

- **Local addresses first:** from the list typed into the phone's settings, plus
  the one the home computer reports. Each is tried only if the phone's own
  current address is on the same home network (same first three numbers, e.g.
  192.168.1.x). If so, it gets 1 second to answer.
- **Public addresses next:** 3 seconds each.
- **In a café:** the phone's address is something else, so it never knocks on
  192.168.1.100, which on that network would be a stranger's device.

**The case for removing it** is weak:

- It overlaps with the local-address list you can type into the phone's
  settings.
- The phone only learns it after it has already connected once, and forgets it
  when the app restarts.

**The case for keeping it:** without it, a phone that's never been told the home
address has to go out and back through the router while you're at home, and many
routers won't route traffic back in like that.

I'd keep it.

## Guide examples: done

Each example in the service guide is now written by a small tool,
`scripts/fill-guide-examples.lua`, from the same template the installer fills.
So the guide shows the exact file the installer writes. On this machine the
built guide shows your real paths. The templates test fails if a template
changes without the guide being refreshed. It's committed, and the tests pass.

## You moved `restart-mailboxes.sh` into `scripts/`

The restart worked. The mailbox logs now show TCP only, and the home address
recorded as 192.168.1.100. But the rest of the setup still expects the script in
the main folder:

- **Git:** the ignore rule only covers the main folder, so git now lists
  `scripts/restart-mailboxes.sh` as a new file. It could get committed, list and
  all.
- **The installer** looks for it in the main folder, finds nothing, and builds a
  fresh one there with an empty list. Then it offers to restart from that one.
- **Adding a name:** `--add` would fail. The script edits its own list at the
  path it was built for, which is still the main folder.

Should `scripts/` be its home? I'd recommend it. If yes, I'll move it there in
the builder, the installer, the ignore rule, the guide and the test, and keep
your current list.

--------------------------------------------------------------------------------

