// SPDX-License-Identifier: GPL-3.0-or-later
//
// router.test.mjs - guards the invariants the adaptive router rests on:
// difficulty decides tier order, a cooled model is skipped, and a quota-shaped
// failure is actually recorded (not just detected).
//
// Run: node --test harness/router.test.mjs
//
// No test framework: node:test ships with Node, and a router this small does
// not justify a dependency. The test restores harness/.state/cooldowns.json
// on the way out so running it never disturbs a real cycle.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";

import {
  route,
  classifyDifficulty,
  reportCooldown,
  cooledDown,
} from "./router.mjs";

const COOLDOWN = new URL("./.state/cooldowns.json", import.meta.url);
let saved = null;

before(() => {
  saved = existsSync(COOLDOWN) ? readFileSync(COOLDOWN, "utf8") : null;
});

after(() => {
  if (saved !== null) writeFileSync(COOLDOWN, saved);
  else if (existsSync(COOLDOWN)) rmSync(COOLDOWN);
});

const EASY_BRIEF = "Add a unit test for the slugify helper.\n\nScope:\n1. test file only";

const HARD_BRIEF =
  "## P0 - Skeleton, exit gate\n\nScope:\n1. Add a test\n2. Change workers.go\n" +
  "3. Change config.go\n\nThis touches the RPC surface, the supervisor and a race. " +
  "It is marked human-gate. ".repeat(40);

test("a small, scoped brief is easy and a large, gate-marked one is not", () => {
  assert.equal(classifyDifficulty(EASY_BRIEF), "easy");
  assert.equal(classifyDifficulty(HARD_BRIEF), "normal");
});

test("the SHARZA_DIFFICULTY override wins over the heuristic", () => {
  try {
    process.env.SHARZA_DIFFICULTY = "easy";
    assert.equal(classifyDifficulty(HARD_BRIEF), "easy");
    process.env.SHARZA_DIFFICULTY = "normal";
    assert.equal(classifyDifficulty(EASY_BRIEF), "normal");
  } finally {
    delete process.env.SHARZA_DIFFICULTY;
  }
});

test("easy tool work starts at the cheap tier, normal at the strong tier", async () => {
  const easy = await route({ needsTools: true, difficulty: "easy" });
  assert.equal(easy.tier, "fast");

  const normal = await route({ needsTools: true, difficulty: "normal" });
  assert.equal(normal.tier, "strong");
});

test("tool-free work is sent to the free local tier", async () => {
  const toolFree = await route({ needsTools: false, difficulty: "normal" });
  assert.equal(toolFree.tier, "local-weak");
});

test("a quota-shaped failure is recorded, an ordinary one is not", async () => {
  assert.equal(
    await reportCooldown("opencode/big-pickle", { stderr: "boom: build failed" }),
    false,
    "a plain build failure must not cool the model down",
  );
  assert.equal(
    await reportCooldown("opencode/big-pickle", {
      stdout: '{"type":"session.error","error":"429 Too Many Requests"}',
    }),
    true,
    "a 429 surfaced in the JSON event stream must be recorded",
  );

  const cooled = await cooledDown();
  assert.ok(cooled.includes("opencode/big-pickle"));
});

test("a model in cooldown is routed around", async () => {
  const cooled = await cooledDown();
  const chosen = await route({ needsTools: true, difficulty: "normal", exclude: cooled });
  assert.ok(chosen.available);
  assert.notEqual(chosen.model, "opencode/big-pickle");
});
