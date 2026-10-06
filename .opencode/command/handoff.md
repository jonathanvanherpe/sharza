---
description: Write the end-of-cycle handoff note for Sharza. Use as the last step of a build cycle, before committing, so the next agent starts from facts rather than guesses.
---

Write a handoff note at `docs/handoff.md` so the next cycle starts from facts
instead of re-deriving them.

Cover, briefly:

- **What changed**, by file, one line each. Facts, not narrative.
- **Verification actually performed**, with the command and its result. Be
  exact about what was not run and why. "Ran `go test ./...`, passed. Did not
  run the differential test against `amuled`, not installed." An optimistic
  handoff is worse than none, because the next agent will trust it.
- **Known broken or incomplete**, including anything that compiles but has not
  been exercised. This is the most important section; a known-broken thing
  written down is fine, one discovered later is a wasted cycle.
- **Decisions made and why**, where a choice was not obvious from the code.
  If it changes something recorded in `docs/ARCHITECTURE.md`, say so
  explicitly and say whether the doc was updated or deliberately left alone.
- **Recommended next step**, following the selection rules in
  `/next-task`.
- **Open questions for the maintainer**, if any. Anything requiring a human
  decision goes via ntfy as well.

Replace the file rather than appending, so it always describes the current
state. Keep it to one page; a handoff that must be read twice will not be.