---
description: Pick the next actionable item from docs/ROADMAP.md and state it as a concrete, bounded task. Use at the start of a build cycle or when you need to know what to work on.
---

Read `docs/ROADMAP.md`, `docs/ARCHITECTURE.md` and `AGENTS.md`. Then choose the
single next item to work on.

Selection rules, in order:

1. **Respect `human-gate`.** If the highest-value remaining item is marked
   `human-gate: true`, do not start it. Post a question via ntfy describing
   the decision needed, and stop. The categories behind a human gate are
   privileged/netns code, new dependencies, licence changes, schema
   migrations, and RPC surface changes.
2. **Finish before you start.** If an earlier phase's exit gate has unmet
   criteria, continue that phase. Do not open a new phase with an old one
   half-closed; the phases are ordered by verifiability for a reason.
3. **Prefer the smallest item that moves a phase's exit gate.** Not the most
   interesting item, the smallest one that produces evidence.

Then output:

- **Phase and item**, by its ROADMAP name.
- **Why this one now**, in one sentence.
- **Scope**, as a concrete list of files to create or change. Be specific.
  "Implement ed2k framing" is not a scope; "create
  `internal/engine/ed2k/framing.go` with opcodes OP_REJECT, OP_SERVERMESSAGE,
  OP_OFFERFILES and their wire structs, plus a fuzz target" is.
- **How to verify**, as the exact commands plus the specific evidence that
  counts as passing. For protocol work, name the oracle client.
- **What must not change**, naming the invariants at risk from
  `docs/ARCHITECTURE.md`.
- **Out of scope**, to stop the work expanding sideways.

Keep it under a page. This output is the entire brief for the rest of the
cycle, so vagueness here becomes wasted effort later.