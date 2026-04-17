# In-app script editor for Android

## Overview

Users write hook scripts from inside the rmail app. Scripts react to rmail
events (on_receive, on_send, on_update, etc.) and can interface with other
apps on the phone.

The long-term vision: visual programming (FSM diagrams, Scratch-style blocks)
that makes automation accessible to non-programmers. But start with text.

## Why in-app editing?

Desktop editing (via synced phone config #308) is powerful but requires:
- Sitting at a computer
- Knowing the config format
- Thinking ahead about what you want

In-app editing enables:
- Quick tweaks while you're using the phone
- "I want this message to do X" → write script right there
- Experimentation without context-switching

Both are valuable. In-app for quick/casual, desktop for complex/bulk.

## Editor evolution

### Phase 1: Text editor
- Simple text input field
- Syntax highlighting (if easy)
- Save/test/run buttons
- Error display when script fails
- Good enough for power users, foundation for later phases

### Phase 2: Template library
- Pre-built scripts for common tasks
- "Notify urgently when [contact] messages"
- "Forward messages matching [pattern] to [contact]"
- "Log all received messages to [file]"
- User selects template, fills in blanks

### Phase 3: Block programming
- Scratch-style drag-and-drop blocks
- Visual representation of logic
- Blocks compile to script text (can view/edit raw)
- Lower barrier to entry

### Phase 4: FSM diagrams
- State machine visualization
- States = conditions (inbox empty, message received, etc.)
- Transitions = actions (send message, notify, etc.)
- Good for complex multi-step workflows
- "When I receive a message from X, wait 5 minutes, then forward to Y"

## Script capabilities

### Available hooks (events)
```
on_receive      - message arrived in inbox
on_send         - message sent from outbox
on_update       - living message updated
on_delete       - message deleted
on_sync_start   - sync cycle beginning
on_sync_complete- sync cycle finished
on_error        - something failed
```

### Available actions
```
notify(title, body)         - show notification
notify_urgent(title, body)  - high-priority notification
send_message(to, subject, body) - send rmail message
forward(message, to)        - forward received message
log(text)                   - append to log file
run_intent(intent)          - launch Android intent
read_content(uri)           - read from content provider
```

### Context variables
```
message.sender    - who sent it
message.subject   - filename/subject
message.body      - message content
message.timestamp - when received
device.battery    - current battery %
device.network    - wifi/cellular/none
device.location   - if permitted
```

## Script language

### Option A: Lua
- Matches desktop hooks
- Full programming language
- Need Lua interpreter on Android (LuaJ? native?)
- Familiar to existing rmail users

### Option B: Custom DSL
- Simpler, purpose-built
- Easier to parse/validate
- Compiles to actions
- Less flexible

### Option C: JSON/YAML rules
- Declarative, not imperative
- Easy to generate from visual editor
- Limited expressiveness
```yaml
when: on_receive
if: sender == "mom"
then: notify_urgent("Mom messaged!")
```

**Recommendation:** Start with Option C (declarative rules) because:
- Easy to generate from templates/blocks
- Easy to validate
- Can add Option A (Lua) later for power users

## Example scripts

### Urgent notification for specific contact
```yaml
name: "mom-urgent"
when: on_receive
if: sender == "mom"
then:
  - notify_urgent:
      title: "Mom"
      body: "${message.body}"
```

### Forward work emails to desktop
```yaml
name: "work-forward"
when: on_receive
if: sender contains "@work.com"
then:
  - forward:
      to: "desktop"
      note: "Forwarded from phone"
```

### Log all messages
```yaml
name: "message-log"
when: on_receive
then:
  - log: "${message.timestamp} | ${message.sender} | ${message.subject}"
```

### Cross-device automation
```yaml
name: "home-arrival"
when: on_sync_complete
if: device.network.ssid == "HomeWifi"
then:
  - send_message:
      to: "desktop"
      subject: "phone-arrived-home"
      body: "Trigger welcome script"
```
Desktop's on_receive hook sees "phone-arrived-home" and runs welcome script.

## UI design

### Script list screen
- List of all scripts (name, hook type, enabled/disabled)
- Toggle switch to enable/disable each
- Tap to edit, long-press for delete/duplicate
- FAB to create new script

### Script editor screen
- Name field
- Hook type dropdown (on_receive, on_send, etc.)
- Condition builder (visual) or text field
- Action list (add/remove/reorder)
- Test button (simulate with fake message)
- Save button

### Error handling
- If script fails, show error in-app
- Option to disable script that keeps failing
- Error log accessible from settings

## Inter-app communication

### Android intents
Scripts can launch other apps via intents:
```yaml
then:
  - run_intent:
      action: "android.intent.action.VIEW"
      data: "https://example.com"
```

### Content providers
Scripts can read data from other apps:
```yaml
# Read next calendar event
- read_content:
    uri: "content://com.android.calendar/events"
    query: "dtstart > now()"
    limit: 1
```

This is the bridge between rmail and the phone's ecosystem.

## Security considerations

### Script permissions
- Scripts run with app's permissions
- If app has calendar access, scripts can read calendar
- No additional permission prompts per-script
- User already trusts the app

### Malicious scripts via sync
- Desktop-edited scripts sync to phone and run
- If attacker compromises desktop, they can run code on phone
- Mitigation: trust model assumes user controls both
- Future: script signing, review before execution

### Resource limits
- Scripts should timeout (prevent infinite loops)
- Limit memory usage
- Limit number of actions per execution
- Rate-limit notifications

## Testing and debugging

### In-app test mode
- "Test" button simulates hook with fake data
- Shows what actions would execute
- Displays any errors

### Dry run
- Execute script but don't actually perform actions
- Log what would happen
- Useful for complex scripts

### Error log
- Persistent log of script errors
- Timestamp, script name, error message
- Accessible from settings

## Unanswered questions

### Script storage format
- YAML? JSON? Lua source?
- Must be human-editable (for desktop editing)
- Must be machine-parseable

### Script execution environment
- Kotlin/Android native interpreter?
- Embedded Lua (LuaJ)?
- Custom interpreter?

### Sync granularity
- Sync all scripts as blob (simple)
- Sync individual scripts (complex, enables collaboration)

### Version control
- Keep history of script changes?
- Undo/redo in editor?
- Desktop git integration?

## Implementation steps

1. Define script data model (YAML schema)
2. Implement script storage in phone config (#308)
3. Build basic text editor UI
4. Implement script parser/validator
5. Implement action executors (notify, send, etc.)
6. Hook scripts into rmail event system
7. Add test mode
8. Add template library
9. (Future) Block editor
10. (Future) FSM designer

## Dependencies

- Issue #308 (synced phone config) — scripts stored here
- Daemon hook system — phone hooks mirror daemon hooks

## Dependents

- Issue #310 (periodics) — periodics are a type of script

## Related concepts

From the original mail:
> "apps like your gallery or Facebook or games or calendar or whatever"

Scripts are the glue between rmail and the phone ecosystem. The phone
becomes programmable through rmail's event system.

> "user designed networking for AI generated apps"

The script system is infrastructure for personal automation. Each user's
scripts are unique — generated or written for their specific needs.

## Status

Design phase.

## Source

Mail: ~/mail/inbox/Android — file processed and removed
