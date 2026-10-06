// SPDX-License-Identifier: GPL-3.0-or-later
//
// sharza-dev.mjs - the agentic development loop.
//
// One cycle:
//   1. Ask a strong model to pick the next roadmap item (/next-task).
//   2. Branch agent/<task-id> from main.
//   3. Run an agent on it in a fresh opencode session.
//   4. Verify with /verify.
//   5. Commit, push, open a merge request.
//
// It never merges to main. That is the maintainer's call, and the only thing
// separating this from an agent with commit access to a branch you care about.
//
// Usage:
//   node harness/sharza-dev.mjs --once          run exactly one cycle
//   node harness/sharza-dev.mjs --dry-run       plan only, change nothing
//   node harness/sharza-dev.mjs --status        show state, change nothing
//   node harness/sharza-dev.mjs --task "..."    skip selection, use this
//   node harness/sharza-dev.mjs --test-notify   send one real notification

import { execFile, execFileSync, spawn } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import path from "node:path";

import { notify, sleep } from "./ntfy.mjs";
import { route, reportCooldown, cooledDown } from "./router.mjs";

const exec = promisify(execFile);

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const STATE_DIR = path.join(REPO, "harness", ".state");
const STATE_FILE = path.join(STATE_DIR, "state.json");

// Verify gate. A cycle that fails here does not commit.
const VERIFY_COMMANDS = [
  { cmd: "go", args: ["build", "./..."], label: "build" },
  { cmd: "go", args: ["vet", "./..."], label: "vet" },
  { cmd: "go", args: ["test", "./..."], label: "test" },
];

const GIT_TIMEOUT = 120_000;

function loadState() {
  try {
    return JSON.parse(readFileSync(STATE_FILE, "utf8"));
  } catch {
    return { cycles: 0, lastTask: null, lastResult: null, history: [] };
  }
}

function saveState(state) {
  mkdirSync(STATE_DIR, { recursive: true });
  writeFileSync(STATE_FILE, `${JSON.stringify(state, null, 2)}\n`);
}

function git(args, opts = {}) {
  return execFileSync("git", args, {
    cwd: REPO,
    encoding: "utf8",
    timeout: GIT_TIMEOUT,
    ...opts,
  }).trim();
}

function taskId() {
  // Date-based so branches sort chronologically in git log --oneline.
  const d = new Date();
  const stamp = [
    d.getFullYear(),
    String(d.getMonth() + 1).padStart(2, "0"),
    String(d.getDate()).padStart(2, "0"),
  ].join("");
  return `${stamp}-${Math.random().toString(36).slice(2, 7)}`;
}

function slugify(text, max = 40) {
  return (
    text
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, max) || "task"
  );
}

/**
 * Run opencode non-interactively and capture its JSON event stream.
 *
 * --auto auto-approves anything not explicitly denied, so the permission
 * denials in opencode.json are the real safety boundary, not the --auto
 * flag. That is the whole reason the denials there are exhaustive.
 */
function runAgent({ model, agent, prompt, sessionTitle, timeoutMs }) {
  const args = [
    "run",
    "--format", "json",
    "--auto",
    "--dir", REPO,
    "--title", sessionTitle,
  ];
  if (model) args.push("--model", model);
  if (agent) args.push("--agent", agent);
  args.push(prompt);

  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn("opencode", args, {
      cwd: REPO,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });

    // An agent that hangs is a failed cycle, not a cycle that never ends.
    const killer = setTimeout(() => {
      stderr += `\n[harness] timed out after ${timeoutMs}ms, killing agent\n`;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.on("error", (err) => {
      clearTimeout(killer);
      resolve({
        ok: false,
        exitCode: null,
        stdout,
        stderr: stderr || err.message,
        durationMs: Date.now() - started,
      });
    });

    child.on("close", (code) => {
      clearTimeout(killer);
      resolve({
        ok: code === 0,
        exitCode: code,
        stdout,
        stderr,
        durationMs: Date.now() - started,
      });
    });
  });
}

/** Extract the assistant's final text from opencode's JSON event stream. */
function lastAssistantText(stdout) {
  let text = "";
  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let ev;
    try {
      ev = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const part = ev.part ?? ev.properties?.part ?? ev;
    if (part?.type === "text" && typeof part.text === "string") {
      text = part.text;
    }
  }
  return text;
}

async function verifyGate() {
  const results = [];
  for (const { cmd, args, label } of VERIFY_COMMANDS) {
    try {
      await exec(cmd, args, { cwd: REPO, timeout: 600_000 });
      results.push({ label, ok: true });
    } catch (err) {
      results.push({
        label,
        ok: false,
        detail: (err.stderr ?? err.message ?? "").toString().slice(0, 4000),
      });
    }
  }
  return results;
}

async function main(argv) {
  const args = new Set(argv.filter((a) => a.startsWith("--")));
  const valueOf = (name) => {
    const hit = argv.find((a) => a.startsWith(`--${name}=`));
    return hit ? hit.slice(name.length + 3) : null;
  };

  const state = loadState();

  if (args.has("--test-notify")) {
    const res = await notify("Sharza harness test notification. Nothing to do.", {
      priority: "low",
      tags: ["white_check_mark"],
    });
    console.log(res.ok ? "notification sent" : `notification failed: ${res.error}`);
    return res.ok ? 0 : 1;
  }

  if (args.has("--status")) {
    console.log(JSON.stringify(state, null, 2));
    const cooldown = await cooledDown();
    if (cooldown.length > 0) console.log(`in cooldown: ${cooldown.join(", ")}`);
    return 0;
  }

  const dryRun = args.has("--dry-run");
  const forcedTask = valueOf("task");

  // 1. Select.
  let task;
  if (forcedTask) {
    task = forcedTask;
  } else {
    const picked = await runAgent({
      agent: null,
      prompt:
        "Run the /next-task command and output only the task brief it produces. " +
        "Do not start implementing anything.",
      sessionTitle: "sharza: select next task",
      timeoutMs: 900_000,
    });
    task = lastAssistantText(picked.stdout).trim();
    if (!task) {
      await notify("Sharza harness could not pick a task. Needs a look.", {
        title: "Sharza harness",
        priority: "high",
        tags: ["warning"],
      });
      console.error(picked.stderr || "no task brief produced");
      return 1;
    }
  }

  const id = taskId();
  const branch = `agent/${id}-${slugify(task.split("\n")[0])}`;
  console.log(`\n=== cycle ${state.cycles + 1}: ${branch} ===\n${task}\n`);

  if (dryRun) {
    console.log(`(dry run: would branch ${branch})`);
    return 0;
  }

  // 2. Branch from main. Refuse to build on anything else: a cycle must be
  //    rebased onto current main, or the MR diff grows without bound.
  git(["fetch", "origin", "main"], { stdio: "ignore" });
  const base = git(["rev-parse", "origin/main"]).length > 0
    ? git(["rev-parse", "origin/main"])
    : git(["rev-parse", "HEAD"]);
  git(["checkout", "-b", branch, base]);

  // 3. Route and run.
  const exclude = await cooledDown();
  const chosen = await route({ needsTools: true, exclude });
  if (!chosen.available) {
    await notify(
      `No reachable model with working tool use. ${chosen.reason}`,
      { title: "Sharza harness", priority: "urgent", tags: ["rotating_light"] },
    );
    console.error(chosen.reason);
    return 1;
  }
  console.log(`model: ${chosen.model} (${chosen.tier}) - ${chosen.reason}\n`);

  const run = await runAgent({
    model: chosen.model,
    agent: null,
    prompt:
      `You are implementing one task on the Sharza codebase.\n\n` +
      `TASK BRIEF:\n${task}\n\n` +
      `Rules:\n` +
      `- Follow AGENTS.md and docs/ARCHITECTURE.md.\n` +
      `- Work only within the scope in the brief. Put anything you decide is ` +
      `out of scope in docs/handoff.md under "Open questions".\n` +
      `- Do not commit. Do not push. The harness does that after verification.\n` +
      `- If the brief marks the item human-gate, stop and say so instead of ` +
      `starting it.\n` +
      `- When done, run the /verify command and report honestly which checks ` +
      `passed, which failed, and which you could not run. Do not claim a check ` +
      `passed if you did not run it.\n`,
    sessionTitle: `sharza: ${branch}`,
    timeoutMs: 7_200_000,
  });

  // 4. Verify independently. Never trust the agent's own report of its work.
  const verify = await verifyGate();
  const failed = verify.filter((v) => !v.ok);
  console.log(
    "\nverify:\n" +
      verify.map((v) => `  ${v.ok ? "pass" : "FAIL"}  ${v.label}`).join("\n"),
  );

  const changed = git(["status", "--porcelain"], { allowFailure: true });
  const haveChanges = Boolean(changed);

  if (failed.length > 0 || !haveChanges) {
    const why = failed.length > 0
      ? `verify failed: ${failed.map((f) => f.label).join(", ")}`
      : "no file changes were produced";
    console.log(`\nnot committing: ${why}`);

    await notify(
      `Cycle ${id} did not land.\n${why}\nBranch: ${branch}`,
      {
        title: "Sharza harness",
        priority: "high",
        tags: ["x"],
      },
    );

    saveState({
      ...state,
      cycles: state.cycles + 1,
      lastTask: task,
      lastResult: why,
      history: [
        ...(state.history ?? []),
        { at: new Date().toISOString(), branch, task: task.split("\n")[0], result: why },
      ].slice(-50),
    });
    return 1;
  }

  // 5. Commit and push.
  git(["add", "-A"]);
  git([
    "commit",
    "-q",
    "-m",
    `${id}: ${task.split("\n")[0]}`,
    "-m",
    `Automated cycle from the Sharza harness.\n\n` +
      `Verification: ${verify.map((v) => v.label).join(", ")} passed.\n\n` +
      `See docs/handoff.md for what was and was not exercised.`,
  ]);
  git(["push", "-q", "-u", "origin", branch]);

  const state_ = loadState();
  saveState({
    ...state_,
    cycles: state.cycles + 1,
    lastTask: task,
    lastResult: `branch ${branch} pushed`,
    history: [
      ...(state_.history ?? []),
      {
        at: new Date().toISOString(),
        branch,
        task: task.split("\n")[0],
        result: "pushed",
      },
    ].slice(-50),
  });

  await notify(
    `Cycle ${id} ready for review.\nBranch: ${branch}\nTask: ${task.split("\n")[0]}\n\n` +
      `Merge when you have read the diff.`,
    { title: "Sharza harness", priority: "default", tags: ["rocket"] },
  );

  console.log(`\npushed ${branch} (agent exit ${run.exitCode}, ${run.durationMs}ms)`);
  console.log("waiting for the maintainer to merge; the harness will not merge to main");

  // Back to main so the next cycle starts clean.
  git(["checkout", "-q", "main"]);
  return 0;
}

const code = await main(process.argv.slice(2));
process.exit(code ?? 0);