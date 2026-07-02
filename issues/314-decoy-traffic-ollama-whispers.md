# Decoy traffic: ollama-generated whispers

## Overview

When sending a message, also send decoy messages to many different target ports.
A network observer wouldn't know which connection carries the real message —
they all look like plausible rmail traffic.

Use ollama to generate variations of the original message, creating "echoed
whispers" that radiate outward, often repeating. The real message hides among
the noise.

## Current behavior

rmail sends messages directly to recipients. A traffic analyst watching the
network can see exactly who you're communicating with based on connection
patterns.

## Intended behavior

Optional decoy mode: when enabled, each send triggers additional fake sends to
random ports/addresses. The decoys contain ollama-generated variations of the
message — similar enough to be plausible, different enough to not be identical.

An observer sees many outbound connections, can't distinguish real from decoy.

## Design

### Helper script: `helpers/whisper-decoys.sh`

Called by rmail's send logic when decoy mode is enabled.

Arguments:
- $1: original message body
- $2: number of decoys to generate
- $3: output directory (for generated decoy files)

The script:
1. Calls ollama with a prompt to generate variations
2. Writes each variation to a file in the output directory
3. rmail sends each decoy to a random port in a configured range

### Ollama prompt concept

```
You are creating decoy messages to hide real traffic. Given this message:

"{original_message}"

Generate a variation that:
- Has similar length and structure
- Changes specific details (names, times, places)
- Maintains the same tone and style
- Could plausibly be a real message

Output only the variation, no explanation.
```

### Decoy targets

Options for where to send decoys:
1. **Random ports on real hosts**: Send to contacts' IPs but wrong ports
2. **Random IPs in subnet**: Send to nearby IPs that probably don't exist
3. **Dedicated decoy receivers**: Friends run decoy listeners that accept and discard
4. **Loopback with delay**: Send to self with random timing, creates traffic pattern

### Timing

Decoys shouldn't all fire simultaneously — that's suspicious. Stagger them:
- Random delays between 0-N seconds
- Some decoys repeat (same message, different times)
- Real message sent at random position in the sequence

### Configuration

```lua
decoy_mode = {
    enabled = true,
    count = 5,           -- number of decoys per real send
    port_range = {9000, 9999},  -- random ports for decoys
    delay_max_ms = 5000, -- max delay between sends
    repeat_chance = 0.3, -- probability of repeating a decoy
    ollama_model = "llama3.2", -- model for variations
}
```

## Edge cases

- **Ollama not available**: Fall back to sending original message unmodified
  to decoy targets, or skip decoys entirely
- **Decoy connection fails**: Ignore silently (expected — random ports won't answer)
- **Performance**: Generating N variations takes time; consider caching or
  pre-generating a pool of variations
- **Recipient confusion**: Decoys shouldn't go to real rmail listeners (they'd
  appear as spam). Need to ensure decoy ports don't accidentally hit real daemons.

## Privacy model

This protects against:
- **Traffic analysis**: Observer can't tell which connection is real
- **Timing correlation**: Staggered sends obscure when the real send happened
- **Frequency analysis**: Decoys make communication patterns noisy

This does NOT protect against:
- **Content inspection**: If observer can decrypt, decoys are obviously fake
- **Endpoint compromise**: If recipient is compromised, decoys don't help
- **Long-term analysis**: Patterns may emerge over many observations

## Unanswered questions

### Decoy plausibility
- How good does ollama need to be for decoys to seem real?
- Should decoys have fake headers (to:, from:) that look valid?
- What if someone runs the decoys through an LLM detector?

### Resource usage
- Ollama inference takes time — acceptable latency for send?
- Pre-generate decoy pool at idle time?
- How many decoys is enough? Too few = easy to filter. Too many = slow.

### Coordination with recipients
- Should recipient know to expect decoys? (To not be alarmed by failed deliveries)
- Should there be a "decoy listener" mode that accepts and discards?

## Implementation steps

1. Create `helpers/whisper-decoys.sh` script
2. Add decoy_mode config section
3. Modify send logic to optionally call decoy generator
4. Implement staggered send timing
5. Add fallback for ollama unavailable
6. Test with tcpdump to verify traffic looks noisy
7. Document privacy model and limitations

## Related files

- rmail.lua (send logic)
- helpers/ directory (new script lives here)
- config (new decoy_mode section)

## Status

Design phase.
