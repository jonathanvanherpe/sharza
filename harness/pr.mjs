// SPDX-License-Identifier: GPL-3.0-or-later
//
// pr.mjs - turn a finished harness cycle into a reviewable pull request.
//
// Two rules matter here:
//   1. A documentation-only cycle is not a code change. It must not produce a
//      commit, a push or a pull request, however green the verify gates are.
//   2. A pull request title and description must say what was implemented.
//      The raw /next-task brief is input to the builder, not a human-facing
//      title: it starts with "## Task Brief — `/next-task`" more often than
//      not. The build agent supplies HARNESS_TITLE/HARNESS_SUMMARY/HARNESS_FILES
//      markers, with a deterministic fallback when it forgets.
//
// This module is deliberately free of process, state and network side effects
// so it can be unit-tested without starting a harness cycle.

import path from "node:path";

const DOCUMENTATION_EXTENSIONS = new Set([".md", ".mdx", ".rst"]);
const DOCUMENTATION_DIRS = new Set(["docs", "documentation"]);

/** True for a path whose change is documentation, not code. */
export function isDocumentationPath(filePath) {
  const normalized = String(filePath ?? "").replace(/\\/g, "/").replace(/^\.\//, "");
  if (!normalized) return false;
  const segments = normalized.split("/");
  if (segments.some((segment) => DOCUMENTATION_DIRS.has(segment.toLowerCase()))) return true;
  return DOCUMENTATION_EXTENSIONS.has(path.posix.extname(normalized).toLowerCase());
}

/** Merge `git diff --name-only` / `git ls-files --others` output into unique paths. */
export function changedPaths(...outputs) {
  const paths = [];
  for (const output of outputs) {
    for (const line of String(output ?? "").split(/\r?\n/)) {
      const entry = line.trim();
      if (entry) paths.push(entry);
    }
  }
  return [...new Set(paths)];
}

/** The subset of changed paths that is actually code. */
export function codeFilesFromPaths(paths) {
  return paths.filter((entry) => !isDocumentationPath(entry));
}

function cleanScalar(text) {
  return String(text ?? "")
    .replace(/\s+/g, " ")
    .trim();
}

/** Strip the markdown a brief or an agent report tends to wrap around a title. */
export function stripMarkdown(text) {
  return String(text ?? "")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`([^`]*)`/g, "$1")
    .replace(/\*\*([^*]*)\*\*/g, "$1")
    .replace(/__([^_]*)__/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/^[\s>#*-]+/, "")
    .replace(/\s+/g, " ")
    .trim();
}

function truncate(text, max) {
  const value = cleanScalar(text);
  return value.length <= max ? value : `${value.slice(0, max - 1).trimEnd()}…`;
}

/**
 * Read the three HARNESS_* markers the builder is asked to end with.
 *
 * A missing marker is fine: humanReadableTitle() and buildPrBody() fall back
 * to the brief and to the detected file list. What is not fine is trusting an
 * agent's own prose about verification, so only the descriptive fields come
 * from here; the verification section is built by the harness's own gates.
 */
export function parseImplementationReport(text) {
  const lines = String(text ?? "").split(/\r?\n/);
  let title = "";
  const summaryLines = [];
  const files = [];
  let inSummary = false;

  for (const raw of lines) {
    const line = raw.trim();
    let match;

    if ((match = line.match(/^HARNESS_TITLE:\s*(.+)$/i))) {
      title = stripMarkdown(match[1]);
      inSummary = false;
      continue;
    }
    if ((match = line.match(/^HARNESS_SUMMARY:\s*(.*)$/i))) {
      if (match[1]) summaryLines.push(stripMarkdown(match[1]));
      inSummary = true;
      continue;
    }
    if ((match = line.match(/^HARNESS_FILES:\s*(.*)$/i))) {
      for (const entry of match[1].split(/[,\n]+/)) {
        const file = entry.trim().replace(/^[-*`\s]+|[-*`\s]+$/g, "");
        if (file) files.push(file);
      }
      inSummary = false;
      continue;
    }
    if (inSummary) {
      if (/^[A-Z][A-Z_]+:\s/.test(line) || /^#{1,6}\s/.test(line)) {
        inSummary = false;
        continue;
      }
      if (line) summaryLines.push(stripMarkdown(line));
    }
  }

  return { title, summary: cleanScalar(summaryLines.join(" ")), files };
}

/** The bolded item in a "- **Phase and item:** ... **the actual item**" line. */
function emphasizedItem(task) {
  for (const raw of String(task ?? "").split(/\r?\n/)) {
    if (!/phase and item:/i.test(raw)) continue;
    const marks = [...raw.matchAll(/\*\*([^*]+)\*\*/g)].map((m) => m[1].trim());
    if (marks.length) return stripMarkdown(marks[marks.length - 1]);
  }
  return "";
}

function phasePrefix(task) {
  for (const raw of String(task ?? "").split(/\r?\n/)) {
    if (!/phase and item:/i.test(raw)) continue;
    const clean = stripMarkdown(raw).replace(/^phase and item:\s*/i, "");
    const match = clean.match(/^(P\d+\s*[—:-]\s*[^,:;]+)/);
    return match ? match[1].trim() : "";
  }
  return "";
}

/** Fallback title from the brief, or "" when the brief is not actionable. */
export function taskTitle(task) {
  const item = emphasizedItem(task);
  if (item) {
    const subject = item.charAt(0).toUpperCase() + item.slice(1);
    const prefix = phasePrefix(task);
    return truncate(prefix ? `${prefix}: ${subject}` : subject, 110);
  }

  const firstLine = String(task ?? "")
    .split(/\r?\n/)
    .map((line) => stripMarkdown(line))
    .find(Boolean);
  if (firstLine && firstLine.length > 8 && !/^(task brief|next task|waiting for)/i.test(firstLine)) {
    return truncate(firstLine, 110);
  }
  return "";
}

/**
 * A short, human-readable PR title describing the change that actually landed.
 *
 * Order: the builder's marker, the brief's named item, then the changed code
 * paths. The raw "Task Brief — /next-task" line is never used as a title.
 */
export function humanReadableTitle({ report = {}, task = "", codeFiles = [], id = "" } = {}) {
  const fromAgent = stripMarkdown(report.title);
  if (fromAgent && fromAgent.length > 8 && !/^(task brief|next task|waiting for)/i.test(fromAgent)) {
    return truncate(fromAgent, 110);
  }

  const fromBrief = taskTitle(task);
  if (fromBrief) return fromBrief;

  if (codeFiles.length > 0) {
    const dirs = [...new Set(codeFiles.map((file) => path.posix.dirname(file)))].filter(
      (dir) => dir && dir !== ".",
    );
    const where = dirs.length
      ? dirs.join(", ")
      : codeFiles.map((file) => path.posix.basename(file)).join(", ");
    return truncate(`Update code in ${where}`, 110);
  }

  return truncate(`Sharza harness cycle ${id || "without a title"}`, 110);
}

/** PR body: what changed first, then the brief and the harness-run checks. */
export function buildPrBody({ task = "", verify = [], report = {}, codeFiles = [], title = "" } = {}) {
  const checks = verify
    .map((result) => `- ${result.ok ? "pass" : "FAIL"}  ${result.label}`)
    .join("\n");
  const summary = cleanScalar(report.summary);
  const description =
    summary ||
    `Implemented ${title ? title.toLowerCase() : "the briefed change"}. ` +
      `The harness detected ${codeFiles.length} changed code file${codeFiles.length === 1 ? "" : "s"}.`;
  const files = codeFiles.length
    ? `## Files changed\n\n${codeFiles.map((file) => `- \`${file}\``).join("\n")}\n\n`
    : "";

  return (
    `Automated cycle from the Sharza harness.\n\n` +
    `## What changed\n\n${description}\n\n` +
    files +
    `## Task\n\n${task}\n\n` +
    `## Verification\n\n` +
    `Run by the harness after the agent stopped, not taken from the agent's\n` +
    `own report:\n\n${checks}\n\n` +
    `Read the diff, and \`docs/handoff.md\` on this branch for what the cycle\n` +
    `did and did not exercise, before merging.\n`
  );
}
