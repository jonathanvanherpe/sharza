// SPDX-License-Identifier: GPL-3.0-or-later
//
// github.mjs - open a pull request for a finished harness cycle.
//
// A cycle pushes to its own agent/<task-id> branch, then this module opens a
// pull request against main so the maintainer can review the diff. Nothing
// merges: a cycle that lands is a branch plus a pull request, never a change
// on main.
//
// Auth is a token in $GITHUB_TOKEN (or $GH_TOKEN) with `pull_requests: write`
// (and `contents: read`) on the repository. Without one the pull request
// cannot be created, and the caller falls back to a compare URL it can hand
// to a human.
//
// Requests use node:https with an IPv4-pinned DNS lookup, exactly as ntfy.mjs
// does and for the same reason: this host has no global IPv6 route and
// api.github.com is dual-stack, so a happy-eyeballs connection can fail
// outright with an AggregateError before GitHub ever sees it.

import https from "node:https";
import dns from "node:dns";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const API_HOST = "api.github.com";

/**
 * Parse an `origin` URL into owner and repo.
 *
 * Handles the two forms git actually uses: the ssh scp-ish form
 * (`git@github.com:owner/repo.git`) and a URL form
 * (`https://github.com/owner/repo.git`, `ssh://git@github.com/owner/repo`).
 *
 * @param {string} url
 * @returns {{owner: string, repo: string} | null}
 */
export function parseRemote(url) {
  if (!url) return null;

  const scp = url.match(/^[^@]+@[^:]+:(.+)$/);
  const pathPart = scp
    ? scp[1]
    : (url.match(/^(?:ssh|https?):\/\/[^/]+\/(.+)$/) ?? [])[1];

  if (!pathPart) return null;

  const clean = pathPart.replace(/\.git$/, "").replace(/\/+$/, "");
  const [owner, repo] = clean.split("/");
  if (!owner || !repo) return null;
  return { owner, repo };
}

/**
 * Resolve a GitHub token from the environment or a project-local, gitignored
 * file, so a token can be kept with the repo without being committed.
 *
 * Lookup order: $GITHUB_TOKEN, $GH_TOKEN, then
 *   harness/.state/github.env  (GITHUB_TOKEN=... or GH_TOKEN=...)
 *   harness/.state/github.token (bare token)
 *
 * @returns {string}
 */
export function resolveGitHubToken() {
  if (process.env.GITHUB_TOKEN) return process.env.GITHUB_TOKEN.trim();
  if (process.env.GH_TOKEN) return process.env.GH_TOKEN.trim();

  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
  const candidates = [
    path.join(root, "harness", ".state", "github.env"),
    path.join(root, "harness", ".state", "github.token"),
  ];
  for (const file of candidates) {
    let raw;
    try {
      raw = readFileSync(file, "utf8").trim();
    } catch {
      continue;
    }
    const m = raw.match(/^(?:GITHUB_TOKEN|GH_TOKEN)\s*=\s*(.+)$/m);
    if (m) return m[1].trim().replace(/^['"]|['"]$/g, "");
    if (/^(ghp_|github_pat_|gho_|ghu_|ghs_)/.test(raw)) return raw;
  }
  return "";
}

/** The URL a human can open to turn a pushed branch into a PR. */
export function compareUrl({ owner, repo, head, base = "main" }) {
  return `https://github.com/${owner}/${repo}/compare/${base}...${head}?expand=1`;
}

/**
 * Open a pull request, or return the existing one if there is already an open
 * PR for the same head branch (which GitHub reports as 422).
 *
 * @returns {Promise<{ok: boolean, url?: string, number?: number, existed?: boolean, error?: string, status?: number}>}
 */
export async function createPullRequest({
  owner,
  repo,
  head,
  base = "main",
  title,
  body,
  token,
  timeoutMs = 20_000,
}) {
  if (!token) return { ok: false, error: "no GITHUB_TOKEN/GH_TOKEN set" };

  const res = await apiRequest({
    method: "POST",
    path: `/repos/${owner}/${repo}/pulls`,
    token,
    timeoutMs,
    body: { title, head, base, body, draft: false },
  });

  if (res.status === 201 && res.json?.html_url) {
    return { ok: true, url: res.json.html_url, number: res.json.number };
  }

  if (res.status === 422) {
    const existing = await findOpenPullRequest({ owner, repo, head, token, timeoutMs });
    if (existing) {
      return { ok: true, url: existing.html_url, number: existing.number, existed: true };
    }
  }

  return {
    ok: false,
    status: res.status,
    error: res.json?.message || res.json?.errors?.map?.((e) => e.message).join("; ") || res.raw,
  };
}

/** @returns {Promise<{html_url: string, number: number} | null>} */
export async function findOpenPullRequest({ owner, repo, head, token, timeoutMs = 20_000 }) {
  const res = await apiRequest({
    method: "GET",
    path: `/repos/${owner}/${repo}/pulls?state=open&head=${encodeURIComponent(`${owner}:${head}`)}`,
    token,
    timeoutMs,
  });
  if (res.status === 200 && Array.isArray(res.json) && res.json.length > 0) return res.json[0];
  return null;
}

function apiRequest({ method, path, token, body, timeoutMs = 20_000 }) {
  return new Promise((resolve) => {
    const payload = body ? JSON.stringify(body) : null;
    const headers = {
      accept: "application/vnd.github+json",
      "user-agent": "sharza-harness",
      "x-github-api-version": "2022-11-28",
    };
    if (token) headers.authorization = `Bearer ${token}`;
    if (payload) {
      headers["content-type"] = "application/json";
      headers["content-length"] = Buffer.byteLength(payload);
    }

    const req = https.request(
      { hostname: API_HOST, path, method, headers, lookup: ipv4Only, timeout: timeoutMs },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          let json = null;
          try {
            json = data ? JSON.parse(data) : null;
          } catch {
            // Leave json null; the raw body carries the detail.
          }
          resolve({ status: res.statusCode ?? 0, json, raw: data.slice(0, 2000) });
        });
      },
    );

    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (err) => resolve({ status: 0, json: null, raw: err.message }));
    if (payload) req.write(payload);
    req.end();
  });
}


/**
 * Fetch the current state of a pull request.
 *
 * @returns {Promise<{ok: boolean, state: string, merged: boolean, url?: string, error?: string}>}
 */
export async function pullRequestState({ owner, repo, number, token, timeoutMs = 20_000 }) {
  const res = await apiRequest({
    method: "GET",
    path: `/repos/${owner}/${repo}/pulls/${number}`,
    token,
    timeoutMs,
  });
  if (res.status < 200 || res.status >= 300 || !res.json) {
    return { ok: false, state: "unknown", merged: false, error: res.raw };
  }
  return {
    ok: true,
    state: res.json.state ?? "unknown",
    merged: Boolean(res.json.merged),
    url: res.json.html_url,
  };
}



/**
 * Assign users to a pull request (via the issues endpoint, which is how
 * GitHub models PR assignees).
 *
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
export async function assignPullRequest({ owner, repo, number, assignees, token, timeoutMs = 20_000 }) {
  if (!token || !assignees || assignees.length === 0) return { ok: true };
  const res = await apiRequest({
    method: "POST",
    path: `/repos/${owner}/${repo}/issues/${number}/assignees`,
    token,
    timeoutMs,
    body: { assignees },
  });
  if (res.status < 200 || res.status >= 300) {
    return { ok: false, error: res.raw };
  }
  return { ok: true };
}


/** DNS lookup that only ever returns IPv4 addresses. See the file header. */
function ipv4Only(hostname, options, callback) {
  const done = typeof options === "function" ? options : callback;
  const opts = typeof options === "function" ? {} : options || {};
  dns.lookup(hostname, { ...opts, family: 4 }, done);
}
