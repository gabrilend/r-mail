# #501 — The contacts file: who the mailbox knows, and how to reach them

## Status

Completed — a blueprint written 2026-10-04 (#621) for what was built
before issue files described it.  The foundation of phase 5.

## Current Behavior

`contacts`, in the mailbox, is a text file the owner writes by hand (or
the phone saves, #504).  One fact per line, `name.field = value`;
`//` and `#` start comments; blank lines are kept; a value may be quoted.
A contact's name is letters, digits, `-` and `_`, and is only this
mailbox's word for them — they never see it (#503).

    // alice: home computer
    alice.ip    = "203.0.113.1"
    alice.port  = 51234
    alice.token = "a long shared secret"

    phone.token = "another secret"
    phone.own   = true

| field | type | meaning |
|---|---|---|
| `token` | string | the shared secret; its SHA-256 is the key (#105) |
| `ip` | string | the address tried first: IPv4, IPv6 or a hostname (#405, #406); pinned first, never reordered |
| `port` | number | their port |
| `ip[N]`, `port[N]` | string, number | more addresses, tried in order after `ip`; one that answers moves up (#408, #407); a missing `port[N]` is `port` |
| `local-ip`, `local-ip[N]` | string | private addresses, tried only from the same /24 (#409); a public address here is refused with a warning |
| `own` | `true` | the owner's own device: may use `/api/` (#709) and is sent the whole file, tokens included |
| `ipv6`, `lan_ip` | string | older forms, folded into the lists above |

A contact with only a `token` can talk to us but we cannot dial them;
their address arrives with their first announcement
(#402).

**Reading** builds, per contact, the ordered list of places to try —
`endpoints`, each an address, a port and where it came from — that every
sender uses.  A contacts file in the old JSON form is converted to this
form, once, on first read.

**Keeping it tidy.**  At start-up and whenever the file changes, each
contact's lines are gathered together at the place of its first line and
their `=` signs lined up; comments and blank lines between contacts stay
where they are.  The daemon writes only the lines it means to change
(`write_contact_fields`, address sets), so the owner's layout survives.

**The canonical form** — every contact sorted, every field sorted, one
line each, no comments — is what the phone holds and what its hash is
taken of.

## Intended Behavior

As above.

## Suggested Implementation Steps

1. `rmail.lua`: `load_contacts` (the JSON conversion) and
   `contactfile.parse` (the format, the folding, `endpoints`);
   `align_contacts`; `write_contact_fields`, `promote_contact_address`,
   `promote_contact_index`; `serialize_contacts_canonical`,
   `canonical_contacts_hash`.
2. `helpers/rfield.sh` reads one field from a shell (#702, #703).
3. Tests: `scripts/test-phone-contacts-save.sh`,
   `scripts/test-lan-address-learning.sh`.

## Related documents

- `README.md` (contacts), `docs/.templates/android-instructions.md`
- `#406`, `#405`, `#503`, `#408`, `#407`, `#409`, `#504`
