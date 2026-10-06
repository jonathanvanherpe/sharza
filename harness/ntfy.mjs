// SPDX-License-Identifier: GPL-3.0-or-later
//
// ntfy.mjs - push a notification to the maintainer, and read replies.
//
// Uses node:http rather than fetch on purpose. This host has no global IPv6
// route, and Node's fetch/undici turns the resulting IPv6 ENETUNREACH into an
// AggregateError [ETIMEDOUT] for the whole request when the target is
// dual-stack. A custom DNS lookup pinned to family 4 avoids that entirely,
// and needs no dependency.

import http from "node:http";
import https from "node:https";
import dns from "node:dns";
import { URL } from "node:url";

const DEFAULT_TOPIC = process.env.NTFY_TOPIC || "sharza";
const DEFAULT_URL = process.env.NTFY_URL || "https://ntfy.sh";

/**
 * Post a message to an ntfy topic.
 *
 * @param {string} message
 * @param {{title?: string, priority?: "min"|"low"|"default"|"high"|"urgent", tags?: string[], topic?: string, url?: string, baseUrl?: string, timeoutMs?: number}} [opts]
 * @returns {Promise<{ok: boolean, status: number, error?: string}>}
 */
export async function notify(message, opts = {}) {
  const base = opts.baseUrl ?? DEFAULT_URL;
  const topic = opts.topic ?? DEFAULT_TOPIC;
  const target = new URL(`${base.replace(/\/$/, "")}/${encodeURIComponent(topic)}`);

  const body = JSON.stringify({
    topic,
    title: opts.title ?? "Sharza",
    message,
    priority: opts.priority ?? "default",
    tags: opts.tags ?? [],
    ...(opts.url ? { click: opts.url } : {}),
  });

  const transport = target.protocol === "https:" ? https : http;
  const timeoutMs = opts.timeoutMs ?? 10_000;

  return new Promise((resolve) => {
    const req = transport.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: target.pathname,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
        // Pin IPv4. See the file header for why.
        lookup: ipv4Only,
        timeout: timeoutMs,
      },
      (res) => {
        // Drain the response so the socket can close.
        res.resume();
        res.on("end", () =>
          resolve(res.statusCode >= 200 && res.statusCode < 300
            ? { ok: true, status: res.statusCode }
            : { ok: false, status: res.statusCode ?? 0, error: `HTTP ${res.statusCode}` }),
        );
      },
    );

    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", (err) => resolve({ ok: false, status: 0, error: err.message }));
    req.write(body);
    req.end();
  });
}

/**
 * DNS lookup that only ever returns IPv4 addresses.
 *
 * Node passes `all: true` when a happy-eyeballs connection needs multiple
 * candidates; we still filter to IPv4 in that case, otherwise undici will
 * hand back an IPv6 address and try it anyway.
 */
function ipv4Only(hostname, options, callback) {
  const done = typeof options === "function" ? options : callback;
  const opts = typeof options === "function" ? {} : options || {};
  dns.lookup(hostname, { ...opts, family: 4 }, done);
}

/**
 * Wait for a reply on a topic, by polling the ntfy JSON cache.
 *
 * ntfy has no blocking read without holding a streaming connection open, and
 * a harness that must survive being killed is better off polling.
 *
 * @param {{since?: string, topic?: string, baseUrl?: string, timeoutMs?: number, pollMs?: number}} [opts]
 * @returns {Promise<Array<{message: string, time: number}>>}
 */
export async function poll(opts = {}) {
  const base = (opts.baseUrl ?? DEFAULT_URL).replace(/\/$/, "");
  const topic = opts.topic ?? DEFAULT_TOPIC;
  const since = opts.since ?? String(Math.floor(Date.now() / 1000));
  const timeoutMs = opts.timeoutMs ?? 0;
  const pollMs = opts.pollMs ?? 15_000;
  const deadline = timeoutMs > 0 ? Date.now() + timeoutMs : Infinity;

  const url = new URL(`${base}/${encodeURIComponent(topic)}/json?poll=1&since=${since}`);

  for (;;) {
    const body = await httpGet(url, 35_000);
    if (body === null) {
      if (Date.now() > deadline) return [];
      await sleep(pollMs);
      continue;
    }

    const messages = [];
    for (const line of body.split("\n")) {
      if (!line.trim()) continue;
      try {
        const ev = JSON.parse(line);
        if (ev.message) messages.push({ message: ev.message, time: ev.time ?? 0 });
      } catch {
        // A partial line is expected on a streaming response; ignore it.
      }
    }
    if (messages.length > 0) return messages;
    if (Date.now() > deadline) return [];
    await sleep(pollMs);
  }
}

function httpGet(url, timeoutMs) {
  const transport = url.protocol === "https:" ? https : http;
  return new Promise((resolve) => {
    const req = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port || (url.protocol === "https:" ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        method: "GET",
        headers: { accept: "application/json" },
        lookup: ipv4Only,
        timeout: timeoutMs,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(null);
          return;
        }
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        // ntfy's ?poll=1 streams; close once we have a full batch or the
        // server's own poll timeout fires.
        res.on("end", () => resolve(data));
      },
    );
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
    req.on("error", () => resolve(null));
    req.end();
  });
}

export function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}