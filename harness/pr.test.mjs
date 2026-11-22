// SPDX-License-Identifier: GPL-3.0-or-later
//
// pr.test.mjs - guards the two rules that keep bogus pull requests out of the
// harness: documentation-only cycles do not land, and PR titles describe the
// implementation rather than the selector's raw brief.
//
// Run: node --test harness/pr.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  isDocumentationPath,
  changedPaths,
  codeFilesFromPaths,
  parseImplementationReport,
  taskTitle,
  humanReadableTitle,
  buildPrBody,
} from "./pr.mjs";

test("documentation paths are not code changes", () => {
  assert.equal(isDocumentationPath("docs/handoff.md"), true);
  assert.equal(isDocumentationPath("docs/ARCHITECTURE.md"), true);
  assert.equal(isDocumentationPath("README.md"), true);
  assert.equal(isDocumentationPath("internal/swarm/swarm.go"), false);
  assert.equal(isDocumentationPath("harness/sharza-dev.mjs"), false);
});

test("a docs-only cycle has no code files to commit", () => {
  const paths = changedPaths("docs/handoff.md\n", "");
  assert.deepEqual(paths, ["docs/handoff.md"]);
  assert.deepEqual(codeFilesFromPaths(paths), []);
});

test("tracked and untracked paths are merged without duplicates", () => {
  const paths = changedPaths(
    "internal/swarm/swarm.go\ndocs/handoff.md\n",
    "internal/swarm/swarm_test.go\ninternal/swarm/swarm.go\n",
  );
  assert.deepEqual(paths, [
    "internal/swarm/swarm.go",
    "docs/handoff.md",
    "internal/swarm/swarm_test.go",
  ]);
  assert.deepEqual(codeFilesFromPaths(paths), [
    "internal/swarm/swarm.go",
    "internal/swarm/swarm_test.go",
  ]);
});

test("the builder's markers become a human title and a plain-text summary", () => {
  const report = parseImplementationReport(
    "Checks passed.\n" +
      "HARNESS_TITLE: Add cross-network swarm controller with lease accounting\n" +
      "HARNESS_SUMMARY: Added a Swarm type that hands out disjoint leases and records " +
      "per-network verification. Tests cover two networks racing on one file.\n" +
      "HARNESS_FILES: internal/swarm/swarm.go, internal/swarm/swarm_test.go\n",
  );
  assert.equal(report.title, "Add cross-network swarm controller with lease accounting");
  assert.match(report.summary, /disjoint leases/);
  assert.deepEqual(report.files, ["internal/swarm/swarm.go", "internal/swarm/swarm_test.go"]);
  assert.equal(
    humanReadableTitle({ report, task: "## Task Brief — `/next-task`", codeFiles: [] }),
    "Add cross-network swarm controller with lease accounting",
  );
});

test("a raw 'Task Brief' selector result never becomes the PR title", () => {
  const brief =
    "## Task Brief — `/next-task`\n\n" +
    "- **Phase and item:** P4 — eDonkey2000 and Kad, next slice — " +
    "**ed2k end-to-end client/server data exchange (first integration slice)**.\n";
  const title = humanReadableTitle({
    report: {},
    task: brief,
    codeFiles: ["internal/engine/ed2k/exchange_test.go"],
  });
  assert.match(title, /ed2k end-to-end client\/server data exchange/i);
  assert.doesNotMatch(title, /task brief/i);
});

test("a non-actionable brief falls back to the changed code paths", () => {
  const title = humanReadableTitle({
    report: {},
    task: "Waiting for the harness dry-run to finish.",
    codeFiles: ["internal/engine/ed2k/servertransfer.go"],
  });
  assert.equal(title, "Update code in internal/engine/ed2k");
});

test("taskTitle ignores a bare '/next-task' heading", () => {
  assert.equal(taskTitle("## Task Brief — `/next-task`"), "");
});

test("the PR body leads with what changed, then files, brief and checks", () => {
  const body = buildPrBody({
    task: "## Task Brief — `/next-task`",
    verify: [{ label: "build", ok: true }, { label: "test (race)", ok: true }],
    report: { summary: "Added a Swarm coordinator that leases blocks per network." },
    codeFiles: ["internal/swarm/swarm.go"],
    title: "Add cross-network swarm controller",
  });
  assert.ok(body.indexOf("## What changed") < body.indexOf("## Files changed"));
  assert.ok(body.indexOf("## Files changed") < body.indexOf("## Task"));
  assert.ok(body.indexOf("## Task") < body.indexOf("## Verification"));
  assert.match(body, /Added a Swarm coordinator/);
  assert.match(body, /- `internal\/swarm\/swarm\.go`/);
  assert.match(body, /- pass  test \(race\)/);
});

test("without an agent summary the body still describes detected files", () => {
  const body = buildPrBody({
    task: "Waiting for the harness dry-run to finish.",
    verify: [],
    report: {},
    codeFiles: ["harness/sharza-dev.mjs"],
    title: "Update code in harness",
  });
  assert.match(body, /Implemented update code in harness/);
  assert.match(body, /1 changed code file/);
});
