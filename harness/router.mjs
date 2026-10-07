// SPDX-License-Identifier: GPL-3.0-or-later
//
// router.mjs - choose a model for a cycle, and notice when one is out of quota.
//
// Design constraints, in priority order:
//
//  1. Never hardcode a spending ceiling. The maintainer's stated policy is to
//     ride whatever quota a provider offers and resume after backoff, so a
//     cap here would be both unwanted and impossible to keep accurate.
//  2. Discover, do not assume. Model ids and quota endpoints differ per
//     provider and change; probing at runtime beats a stale list.
//  3. Degrade honestly. A local model that cannot reliably call tools must not
//     be handed tool-using work just because it is free.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);

/**
 * Capability tiers, best first.
 *
 * `tools: true` is a hard requirement for anything that edits code, because an
 * agent that cannot call a tool cannot build or verify anything.
 */
export const TIERS = [
  {
    name: "strong",
    tools: true,
    candidates: [
      // Filled in from live discovery below; kept explicit so a maintainer
      // can pin a preference without editing discovery logic.
      "opencode/big-pickle",
      "google/gemini-3.5-flash",
      "google/gemini-3.1-pro-preview",
    ],
  },
  {
    // The cheap tool-capable tier. Tried first for briefs the classifier
    // finds easy, and used as the fallback when strong is unavailable.
    // Free OpenCode models come first because they need no separate key and
    // cost nothing; Gemini flash is the paid backstop.
    name: "fast",
    tools: true,
    candidates: [
      "opencode/muse-spark-1.3-contributor-free",
      "opencode/nemotron-3-ultra-free",
      "google/gemini-3.7-flash",
      "google/gemini-2.5-flash",
    ],
  },
  {
    // Local models, listed for tool-free work only. The maintainer's finding
    // is that these are weak at tool use: they will happily claim to have
    // edited a file that does not exist. Handing one an edit task produces a
    // confident, broken result, which is worse than no result.
    name: "local-weak",
    tools: false,
    candidates: [
      "ollama/qwen3:14b",
      "ollama/qwen2.5-coder:7b",
      "ollama/gemma4:e4b",
      "ollama/deepseek-r1:8b",
    ],
  },
];

/**
 * List the models the local opencode installation can actually reach.
 *
 * @returns {Promise<Array<{provider: string, id: string, full: string}>>}
 */
export async function discoverModels() {
  try {
    const { stdout } = await exec("opencode", ["models"], {
      maxBuffer: 8 * 1024 * 1024,
      timeout: 30_000,
    });
    return stdout
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((full) => {
        const slash = full.indexOf("/");
        return {
          full,
          provider: slash > 0 ? full.slice(0, slash) : "",
          id: slash > 0 ? full.slice(slash + 1) : full,
        };
      });
  } catch (err) {
    return [];
  }
}

/**
 * Tier preference order by task difficulty.
 *
 * Normal work starts at the strongest tier. Easy work starts at the cheapest
 * tool-capable tier and only climbs if that is unreachable, because spending
 * the expensive model on work that does not need it is the thing this router
 * exists to avoid. local-weak is last in both orders: it is never a fallback
 * for tool-using work, only the preferred home for explicitly tool-free work.
 */
const ORDER_BY_DIFFICULTY = {
  normal: ["strong", "fast", "local-weak"],
  easy: ["fast", "strong", "local-weak"],
};

/**
 * Classify a brief as "easy" or "normal".
 *
 * Deliberately a bias-toward-hard heuristic. A task wrongly called "normal"
 * costs a little more than it had to; a task wrongly called "easy" is handed
 * to a weaker model and produces a cycle that fails the verify gate. Those are
 * not symmetric, so "normal" is the default and "easy" has to be argued for by
 * the brief itself. An explicit escape hatch overrides the heuristic:
 *
 *   SHARZA_DIFFICULTY=easy|normal
 *
 * @param {string} brief
 * @returns {"easy"|"normal"}
 */
export function classifyDifficulty(brief) {
  const override = process.env.SHARZA_DIFFICULTY;
  if (override === "easy" || override === "normal") return override;

  const text = String(brief ?? "");
  if (!text.trim()) return "normal";

  // Gate-marked work, or anything naming a subsystem the harness has been told
  // to treat carefully, is not easy by definition.
  const HARD = [
    /\bhuman[- ]gate\b/i,
    /\bmigration\b/i,
    /\bschema\b/i,
    /\brefactor\b/i,
    /\bconcurren/i,
    /\bdeadlock\b/i,
    /\brace\b/i,
    /\bprotocol\b/i,
    /\bnetns\b/i,
    /\b(vpn|vopono|iptables|nftables)\b/i,
    /\bdependenc/i,
    /\bgo\.mod\b/i,
    /\bengine\//i,
    /\brpc\b/i,
    /\binterface\b/i,
    /\bsupervisor\b/i,
    /\bsecurity\b/i,
  ];
  if (HARD.some((re) => re.test(text))) return "normal";
  if (text.length > 2500) return "normal";
  const scopeItems = (text.match(/^\s*\d+\.\s/gm) ?? []).length;
  if (scopeItems > 2) return "normal";

  return "easy";
}

/**
 * Pick a model for a cycle.
 *
 * @param {{needsTools?: boolean, difficulty?: "easy"|"normal", prefer?: string, exclude?: string[]}} [req]
 * @returns {Promise<{model: string|null, tier: string|null, difficulty: string, reason: string, available: boolean}>}
 */
export async function route(req = {}) {
  const needsTools = req.needsTools !== false;
  const difficulty = req.difficulty === "easy" ? "easy" : "normal";
  const available = new Set((await discoverModels()).map((m) => m.full));
  const exclude = new Set(req.exclude ?? []);

  let order = ORDER_BY_DIFFICULTY[difficulty];
  if (req.prefer) {
    order = [req.prefer, ...order.filter((name) => name !== req.prefer)];
  }
  // Explicitly tool-free work gets the free local tier first: it is the
  // cheapest option and the one thing those models are trusted with.
  if (!needsTools) {
    order = ["local-weak", ...order.filter((name) => name !== "local-weak")];
  }

  for (const name of order) {
    const tier = TIERS.find((t) => t.name === name);
    if (!tier) continue;
    if (needsTools && !tier.tools) continue;
    for (const candidate of tier.candidates) {
      if (exclude.has(candidate)) continue;
      if (available.size > 0 && !available.has(candidate)) continue;
      return {
        model: candidate,
        tier: tier.name,
        difficulty,
        reason:
          available.size === 0
            ? `model discovery unavailable; using configured candidate ${candidate}`
            : `${candidate} is reachable and ${tier.tools ? "supports tools" : "is tool-free by policy"} (${difficulty} task)`,
        available: true,
      };
    }
  }

  return {
    model: null,
    tier: null,
    difficulty,
    reason: needsTools
      ? "no reachable model with working tool use; refusing to start a cycle that cannot build"
      : "no reachable model",
    available: false,
  };
}

/**
 * Report a rate-limit or quota failure for a model, so the next cycle can
 * prefer something else.
 *
 * Returns true when a cooldown was recorded and false when the failure did not
 * look quota-shaped. The caller uses the return value so "did we act on this"
 * is decided once, here, rather than guessed again at the call site.
 *
 * @param {string} model
 * @param {{status?: number, body?: string, message?: string, stderr?: string, stdout?: string}} err
 * @returns {Promise<boolean>}
 */
export async function reportCooldown(model, err = {}) {
  const signals = [err.body, err.message, err.stderr, err.stdout]
    .filter((s) => typeof s === "string" && s.length > 0)
    .join("\n")
    .toLowerCase();

  const quotaish =
    err.status === 429 ||
    err.status === 503 ||
    signals.includes("rate limit") ||
    signals.includes("ratelimit") ||
    signals.includes("quota") ||
    signals.includes("resource_exhausted") ||
    signals.includes("resourceexhausted") ||
    signals.includes("overloaded") ||
    signals.includes("too many requests") ||
    /\b429\b/.test(signals);

  if (!quotaish) return false;

  // The harness stores this in a plain file rather than a database, because
  // it is a single small list and a dependency here would be worth more than
  // the thing it stores.
  const { mkdirSync, readFileSync, writeFileSync } = await import("node:fs");
  const dir = new URL("./.state/", import.meta.url);
  const path = new URL("./.state/cooldowns.json", import.meta.url);
  mkdirSync(dir, { recursive: true });
  let state = {};
  try {
    state = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    state = {};
  }
  state[model] = { until: Date.now() + 30 * 60_000, at: new Date().toISOString() };
  writeFileSync(path, JSON.stringify(state, null, 2));
  return true;
}

/**
 * Return models currently in cooldown.
 *
 * @returns {Promise<string[]>}
 */
export async function cooledDown() {
  const { readFileSync } = await import("node:fs");
  const path = new URL("./.state/cooldowns.json", import.meta.url);
  try {
    const state = JSON.parse(readFileSync(path, "utf8"));
    const now = Date.now();
    return Object.entries(state)
      .filter(([, v]) => (v.until ?? 0) > now)
      .map(([k]) => k);
  } catch {
    return [];
  }
}