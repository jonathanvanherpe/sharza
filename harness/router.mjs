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
    name: "fast",
    tools: true,
    candidates: [
      "google/gemini-3.7-flash",
      "google/gemini-2.5-flash",
      "opencode/muse-spark-1.3-contributor-free",
      "opencode/nemotron-3-ultra-free",
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
 * Pick a model for a cycle.
 *
 * @param {{needsTools: boolean, prefer?: string, exclude?: string[]}} [req]
 * @returns {Promise<{model: string, tier: string, reason: string, available: boolean}>}
 */
export async function route(req = {}) {
  const needsTools = req.needsTools !== false;
  const available = new Set((await discoverModels()).map((m) => m.full));
  const exclude = new Set(req.exclude ?? []);

  const tiers = req.prefer
    ? [TIERS.find((t) => t.name === req.prefer), ...TIERS].filter(Boolean)
    : TIERS;

  for (const tier of tiers) {
    if (needsTools && !tier.tools) continue;
    for (const candidate of tier.candidates) {
      if (exclude.has(candidate)) continue;
      if (available.size > 0 && !available.has(candidate)) continue;
      return {
        model: candidate,
        tier: tier.name,
        reason:
          available.size === 0
            ? `model discovery unavailable; using configured candidate ${candidate}`
            : `${candidate} is reachable and ${tier.tools ? "supports tools" : "is tool-free by policy"}`,
        available: true,
      };
    }
  }

  return {
    model: null,
    tier: null,
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
 * @param {string} model
 * @param {Error & {status?: number, body?: string}} err
 * @returns {Promise<void>}
 */
export async function reportCooldown(model, err) {
  const text = (err?.body ?? err?.message ?? "").toLowerCase();
  const quotaish =
    (err?.status === 429) ||
    text.includes("rate limit") ||
    text.includes("quota") ||
    text.includes("resource_exhausted") ||
    text.includes("overloaded");

  if (!quotaish) return;

  // The harness stores this in a plain file rather than a database, because
  // it is a single small list and a dependency here would be worth more than
  // the thing it stores.
  const { readFileSync, writeFileSync } = await import("node:fs");
  const path = new URL("./.state/cooldowns.json", import.meta.url);
  let state = {};
  try {
    state = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    state = {};
  }
  state[model] = { until: Date.now() + 30 * 60_000, at: new Date().toISOString() };
  writeFileSync(path, JSON.stringify(state, null, 2));
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