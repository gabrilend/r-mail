# #325 — Clean up hook script configuration in config file

## Problem

The hook configuration in the config file is hard to follow — commented-out
examples, argument documentation mixed in, duplicate names.

## Desired changes

### Config file format
- Remove argument documentation from config (move to script files).
- Use empty string as default instead of commented-out lines:
  ```
  # runs when a message in the inbox or outbox is deleted.
  on_delete = ""
  ```

### Default hook scripts
- Ship default orchestrator scripts in a hooks directory, e.g.
  `scripts/hooks/on-delete.sh`.
- Config points to these by default:
  ```
  on_delete = "${RMAIL_DIR}/scripts/hooks/on-delete.sh"
  ```
- Each default script contains: argument table, link to scripting tutorial,
  hint that it's an orchestrator (call other scripts from here), hint that
  users can point to any script they want.
- Hint in each script: it's often easier to set up separate rmail mailboxes
  for separate purposes than to do complex control flow in a single hook.

### Variable expansion
- Need to resolve `${RMAIL_DIR}` in config values. Options:
  - Two-pass config parsing (gather directory first, then substitute)
  - Shell-style expansion at parse time
  - Relative paths from config file location

## Source

From `unsorted-issue-4`.
