# #370 — Mesh network compatibility: thin shim via hooks

## Summary

rmail assumes IP routing: contacts are `ip`/`port` tuples, the wire
protocol is TCP-framed AES-GCM.  A contact unreachable over IP is
undeliverable today.  Mesh networking projects (Meshtastic, MeshCore,
Reticulum) solve a neighbouring problem — off-grid delivery over LoRa /
packet radio / ad-hoc WiFi / etc.

**Position:** we don't think mesh networks are the right answer to the
problems they're trying to solve.  But some of the people doing
interesting work in this space are mesh people, and we'd like rmail
to be reachable from their world without owning any of their stack.

**Plan:** ship a thin compatibility shim.  Make mesh integration
**possible, not easy** — zero mesh code inside the rmail daemon, zero
bundled dependencies, no opinion from rmail about *which* mesh.  A user
who wants it wires it up themselves through the existing hook-script
system (`scripts/hooks/`) and the `helpers/rfield.sh` contacts accessor.
We document the recipe; we don't ship the mesh.

## The mesh projects, briefly

- **Reticulum.**  Cryptographic networking stack that runs over LoRa,
  packet radio, serial, ad-hoc WiFi, *and encapsulated over IP*.  On top
  of it sits **LXMF**, a delay/disruption-tolerant message protocol
  with store-and-forward via propagation nodes.  Of the three, this is
  the only one whose abstractions actually match rmail's
  (cryptographic, file-at-rest, delay-tolerant).  `rncp` is the
  file-copy-over-Reticulum CLI that ships with the stack — that's the
  most likely integration touchpoint.
- **MeshCore.**  Modern LoRa mesh protocol.  Relevant here only as
  *one possible LoRa substrate Reticulum can ride over* — not a direct
  integration target.
- **Meshtastic.**  Excluded.  Flood routing, same bandwidth ceiling as
  MeshCore, nothing unique.

## Why "thin shim" and not "integration"

Two reasons.

**Ideological.**  We want the door open for people doing mesh work to
reach rmail users.  We don't want rmail to endorse, depend on, or
assume a mesh.  The integration should look like "here's how, if you
want."

**Technical.**  A real integration has three bad choices:
1. Reimplement enough of Reticulum in Lua to interop.  ~2000 LOC of
   crypto + wire protocol + LXMF, with bit-exact fidelity to an
   upstream we don't control.  Interop-fidelity risk alone kills it.
2. Bundle a Python `rnsd` sidecar with every rmail install.  Ships a
   Python runtime next to the Lua daemon and makes us responsible for
   Reticulum config we don't want to own.
3. Don't ship any mesh code.  Let the user run their own Reticulum
   tooling (MeshChat, Sideband, Nomad, plain `rnsd` + `rncp`), and give
   them a documented way to plug rmail into it.

Option 3 is what this issue proposes.

## The shim: what's already in place

rmail already ships the two pieces this needs:

- **`helpers/rfield.sh`.**  Reads an arbitrary user-defined field from
  a contacts file by name: `rfield contacts alice lxmf` returns
  `alice.lxmf`'s value.  Users can put *anything* in contacts; rmail
  ignores fields it doesn't know.  So `alice.lxmf = <destination_hash>`
  (or `alice.meshcore_id`, or `alice.whatever`) costs the daemon
  nothing.
- **`scripts/hooks/`.**  The hook-script system (see #306, #307, #325).
  User-editable shell scripts that fire at points in the message
  lifecycle: `on_send`, `on_package`, `on_receive`, etc.  Already the
  blessed extensibility mechanism.

Combined, a user who wants Reticulum delivery writes their own hook
script that:
1. Uses `rfield.sh` to look up `alice.lxmf` for the current recipient.
2. If set, hands the message body off to whatever local Reticulum
   tooling they run — `rncp` directly, a `curl` POST to a local
   MeshChat HTTP port, a tiny Python sidecar they wrote, whatever.
3. Returns.

rmail's daemon never learns what Reticulum is.

## What actually needs to change in the repo

1. **Document it.**  Add a "Mesh networks / alternate transports"
   section to `docs/.templates/scripting-tutorial.md` showing the
   pattern above with `rncp` as the worked example.  Half a page.
2. **Maybe ship an example hook** under something like
   `scripts/hooks/examples/on_send.reticulum-rncp.sh`.  Not installed
   by default — reference material users copy from.
3. **Reserve `lxmf` and `reticulum` as well-known optional contact
   field names** in the docs so different users' hook scripts don't
   collide on naming.

That's it.  No daemon code.  No Python.  No new dependencies.

## Open question: can a hook signal "delivered, skip IP"?

Current hooks transform the body or do side effects; they don't appear
to have a way to say *"I took care of delivery, don't also try IP."*
That gates whether the shim supports:

- **Mesh-as-fallback** (IP first, mesh if IP fails): needs a new hook
  point like `on_delivery_failure`, or the existing retry loop needs
  an opt-out signal.  Small daemon change.
- **Mesh-and-IP in parallel** (send both, let the receiver dedupe on
  file ID): works today with zero daemon change.  Wasteful but
  acceptable if files are idempotent.
- **Mesh-only for specific contacts**: needs the above opt-out signal.

Minimum-viable is the "and-IP in parallel" mode with zero daemon
change.  The more useful modes want a small hook-protocol extension,
which should be its own issue if/when someone actually wants to build
this.

## External references

- Reticulum stack: https://reticulum.network/
- Reticulum manual / "What is Reticulum": https://reticulum.network/manual/whatis.html
- LXMF protocol: `markqvist/LXMF` on GitHub
- `rncp` (ships with Reticulum): `rnp`/`rncp` in the `rns` pip package
- MeshChat (local HTTP API for LXMF): `liamcottle/reticulum-meshchat`
- MeshCore: https://github.com/meshcore-dev/MeshCore

## Source

Raised 2026-04-20.  Initial framing was "investigate integration";
through iteration the scope collapsed to "thin compatibility shim via
hooks, no daemon coupling."  Position articulated by user: *mesh
networks are the wrong solution to the problems they're trying to
solve, but the people doing interesting work there are worth being
reachable by.  Make it possible, not easy.*

## Status

Open, docs-only work pending.  No code change required for the
parallel-send mode.  If/when someone wants the fallback-only or
mesh-only modes, file a follow-up for the hook-protocol extension
(probably `on_delivery_failure` or an opt-out return code from
`on_send`).
