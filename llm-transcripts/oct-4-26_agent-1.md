# Conversation Summary: 44efc473-3b08-4771-8b15-67e610ded2ae

Generated on: 2026-10-04 14:02:58
Models: claude-opus-5-5

## Contents

1. 2026-10-04 13:47, after Request 2 - I'm answering your four questions from
   the last round: the discovery test fails because this machine's firewall
   drops the packets, and six built issues are now completed and committed.
   Next, I need your answers to my seven open questions, starting with whether
   to split the half-built address-announcement issue.

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

