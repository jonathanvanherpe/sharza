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
  discoverModels,
  TIERS,
  classifyDifficulty,
  reportCooldown,
  cooledDown,
  resourceExhaustion,
  RESOURCE_PAUSE_MS,
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

test("available OpenCode Go models precede non-Go fallbacks", async () => {
  const available = new Set((await discoverModels()).map((model) => model.full));
  if (available.size === 0) return; // Discovery outage is covered by route's fallback.

  for (const [difficulty, tierName] of [["easy", "fast"], ["normal", "strong"]]) {
    const tier = TIERS.find((candidate) => candidate.name === tierName);
    const firstGo = tier.candidates.find(
      (candidate) => candidate.startsWith("opencode-go/") && available.has(candidate),
    );
    if (!firstGo) continue;

    const chosen = await route({ needsTools: true, difficulty });
    assert.equal(chosen.model, firstGo, `${tierName} should prefer its first available Go model`);
  }
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

test("the OpenCode allowance wall is recognised as exhaustion, a slow build is not", () => {
  // Both strings below are real: the first is what this opencode build logs
  // when the Go allowance runs out, the second is the Gemini quota wording.
  assert.ok(
    resourceExhaustion({
      stderr: "AI.Error: Go usage limit exceeded",
    }),
    "the Go usage-limit error must count as exhaustion",
  );
  assert.ok(
    resourceExhaustion({
      stdout:
        '{"type":"session.error","error":"You exceeded your current quota, please check your plan"}',
    }),
    "a provider quota error in the event stream must count",
  );

  assert.equal(
    resourceExhaustion({ stderr: "--- FAIL: TestKHL (0.02s)\nbuild failed" }),
    null,
    "a failing test must never pause the harness",
  );
  assert.equal(
    resourceExhaustion({ stderr: "429 Too Many Requests" }),
    null,
    "a per-model 429 stays a cooldown: the next candidate may still work",
  );
});

test("a watchdog kill only counts as exhaustion when the run answered nothing", () => {
  const killed = {
    stderr: "[harness] timed out after 900000ms, killing agent",
  };
  assert.equal(
    resourceExhaustion({ ...killed, silent: true }),
    "the run timed out without producing any answer",
    "a silent timeout is the quota-stall shape and must pause",
  );
  assert.equal(
    resourceExhaustion({ ...killed, silent: false }),
    null,
    "a run that answered and was killed at the limit is slow, not out of quota",
  );
});

test("an exhaustion failure cools the model for the same six hours as the pause", async () => {
  const model = "opencode/quota-test";
  await reportCooldown(model, { stderr: "AI.Error: Go usage limit exceeded" });

  const until = JSON.parse(readFileSync(COOLDOWN, "utf8"))[model].until;
  const hours = (until - Date.now()) / 3_600_000;
  assert.ok(
    hours > 5.9 && hours <= 6,
    `an exhausted quota should cool the model for ~6h, got ${hours.toFixed(2)}h`,
  );
  assert.equal(RESOURCE_PAUSE_MS, 6 * 3_600_000);
});

test("the OpenCode allowance wall is recognised as exhaustion, a slow build is not", () => {
  // Both strings below are real: the first is what this opencode build logs
  // when the Go allowance runs out, the second is the Gemini quota wording.
  assert.ok(
    resourceExhaustion({
      stderr: "AI.Error: Go usage limit exceeded",
    }),
    "the Go usage-limit error must count as exhaustion",
  );
  assert.ok(
    resourceExhaustion({
      stdout:
        '{"type":"session.error","error":"You exceeded your current quota, please check your plan"}',
    }),
    "a provider quota error in the event stream must count",
  );

  assert.equal(
    resourceExhaustion({ stderr: "--- FAIL: TestKHL (0.02s)\nbuild failed" }),
    null,
    "a failing test must never pause the harness",
  );
  assert.equal(
    resourceExhaustion({ stderr: "429 Too Many Requests" }),
    null,
    "a per-model 429 stays a cooldown: the next candidate may still work",
  );
});

test("a watchdog kill only counts as exhaustion when the run answered nothing", () => {
  const killed = {
    stderr: "[harness] timed out after 900000ms, killing agent",
  };
  assert.equal(
    resourceExhaustion({ ...killed, silent: true }),
    "the run timed out without producing any answer",
    "a silent timeout is the quota-stall shape and must pause",
  );
  assert.equal(
    resourceExhaustion({ ...killed, silent: false }),
    null,
    "a run that answered and was killed at the limit is slow, not out of quota",
  );
});

test("an exhaustion failure cools the model for the same six hours as the pause", async () => {
  const model = "opencode/quota-test";
  await reportCooldown(model, { stderr: "AI.Error: Go usage limit exceeded" });

  const until = JSON.parse(readFileSync(COOLDOWN, "utf8"))[model].until;
  const hours = (until - Date.now()) / 3_600_000;
  assert.ok(
    hours > 5.9 && hours <= 6,
    `an exhausted quota should cool the model for ~6h, got ${hours.toFixed(2)}h`,
  );
  assert.equal(RESOURCE_PAUSE_MS, 6 * 3_600_000);
});
