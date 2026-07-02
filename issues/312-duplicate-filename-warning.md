# Warn about duplicate filename conflicts

## Current behavior

If you send a message to a recipient who already has a file with the
same name in their inbox, the behavior is undefined — the message may
fail silently, overwrite, or cause confusion.

## Intended behavior

Handle filename collisions gracefully, either by:
- Warning the sender about the conflict, OR
- Resolving it silently on the recipient side

This is distinct from "living messages" (issue #306), which handle
intentional updates from the original sender. This issue is about
accidental name collisions.

## Unanswered questions

### Server-side warning vs client-side resolution

**Option A: Server tells sender about conflict**
- Sender gets feedback: "Message 'foo' not delivered to bar: filename exists"
- Problem: leaks information about recipient's inbox contents
- An attacker could probe for message names to learn what someone has received
- Could be "cute" — knowing what's in someone's inbox has social value
- But also creepy? "I see you already have a message called 'love-letter'..."

**Option B: Recipient resolves silently**
- Recipient's daemon auto-renames: `foo` → `foo-2` or `foo-from-alice`
- No information leaks back to sender
- Sender doesn't know their chosen filename wasn't used
- Simpler, more private, but less transparent

**Option C: Configurable per-recipient**
- Recipient sets preference: "warn senders" vs "auto-rename"
- Most flexible, most complex
- Default matters: which is the safe default?

### What counts as a collision?

- Same subject/filename only?
- Same subject AND same sender? (different senders could have same subject)
- What about case sensitivity? `Foo` vs `foo`?

### Living message interaction

- Living messages from the SAME sender should update, not collide
- But what if Alice sends "status" and Bob also sends "status"?
- Should living messages be sender-namespaced? `alice/status` vs `bob/status`?
- Or reject the second sender's "status" as a collision?

## Suggested implementation steps

(Depends on answers to above questions)

1. Decide on collision resolution strategy
2. If server-side warning:
   - Check inbox for existing filename on receive
   - If conflict AND not a living update from same sender:
     - Return error response with reason
     - Sender's daemon writes warning to sender's inbox
3. If client-side resolution:
   - On conflict, append sender name or incrementing number
   - Log the rename somewhere (inbox log file?)

## Edge cases

- Living messages should bypass this for same-sender updates
- Recipient deletes and re-receives: UUID tracking handles this
- Multiple recipients: each resolves independently
- What if auto-renamed file ALSO conflicts? Keep incrementing?

## Source

Mail: ~/mail/inbox/rmail-improvements-too — file processed and removed
