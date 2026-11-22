// Security review 2026-11-19, findings 1, 6, 7, 8 and the wording rule: what ships in the public repository.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

const ROOT = new URL("..", import.meta.url).pathname;
function files(dir = ROOT, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (["node_modules", ".git"].includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) files(p, out); else out.push(p);
  }
  return out;
}
const shipped = () => files().filter((f) => !/package-lock\.json$|\.(mp4|png|jpg)$/.test(f));

// finding 1: private logs stay out of the repo, and the code doesn't write them into it by default
test("repo: .gitignore keeps logs, keys and dependencies out", () => {
  const gi = fs.existsSync(path.join(ROOT, ".gitignore")) ? fs.readFileSync(path.join(ROOT, ".gitignore"), "utf8") : "";
  for (const p of ["node_modules/", "*.jsonl", "*.export", ".env"]) assert.ok(gi.split("\n").includes(p), `.gitignore lacks ${p}`);
  // The one log meant for publication: the public testnet run (no client data), checked against its own anchor. Named one by one.
  const PUBLIC = new Set(["docs/public-run/audit-public.jsonl"]);
  for (const f of PUBLIC) assert.ok(gi.split("\n").includes("!" + f), `.gitignore must name the public log ${f} explicitly`);
  for (const f of shipped()) if (!PUBLIC.has(path.relative(ROOT, f))) assert.doesNotMatch(path.basename(f), /\.jsonl$|\.export$|^\.env$/, `${path.relative(ROOT, f)} would be published`);
  for (const f of PUBLIC) if (fs.existsSync(path.join(ROOT, f))) assert.doesNotMatch(fs.readFileSync(path.join(ROOT, f), "utf8"), /\/home\/|\/data\/|\/Users\/|secret|BEGIN|privateKey|signKey/i, `${f} holds a local path or key material`);
});
test("repo: default ledger and audit paths are outside the repository", () => {
  const env = { ...process.env }; delete env.GG_LEDGER; delete env.GG_AUDIT; delete env.GG_DATA_DIR;
  const out = execFileSync(process.execPath, ["--input-type=module", "-e",
    `const c = await import(${JSON.stringify(path.join(ROOT, "src/config.mjs"))}); const a = await import(${JSON.stringify(path.join(ROOT, "src/ccd/audit.mjs"))}); console.log(JSON.stringify([c.config.ledgerPath, a.AUDIT_FILE]))`],
  { cwd: ROOT, env, encoding: "utf8" });
  for (const p of JSON.parse(out)) assert.ok(!path.resolve(ROOT, p).startsWith(ROOT), `${p} is inside the repository`);
});

// finding 7: file inputs are confined to the workspace before anything is bought
test("cli: a deliverable or terms file outside the workspace is refused before any purchase", () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "ggws-"));
  const env = { ...process.env, GG_WORKSPACE: ws, TELEGRAPH_NODE: "http://127.0.0.1:9", TELEGRAPH_PAYER_KEY: "0x" + "11".repeat(32), GG_LEDGER: path.join(ws, "l.jsonl"), GG_AUDIT: path.join(ws, "a.jsonl") };
  for (const args of [["ship", "/etc/passwd"], ["ship", ws + "/" + path.relative(ws, "/etc/hostname")], ["claim", JSON.stringify({ wallet: "0x" + "33".repeat(20), chain: "ethereum", token: "USDT", client: "Acme", amountUsd: 5, termsFile: "/etc/passwd" })]]) {
    let err = "";
    try { execFileSync(process.execPath, [path.join(ROOT, "src/cli.mjs"), ...args], { env, encoding: "utf8", stdio: "pipe" }); } catch (e) { err = String(e.stderr); }
    assert.match(err, /outside the workspace/, `${args[0]} ${args[1].slice(0, 40)}: ${err.slice(0, 200)}`);
  }
});

// findings 6 and 8: docs say only true things and link only to files that exist
test("docs: relative links resolve inside the repo, no local machine paths, test count is right", () => {
  const md = shipped().filter((f) => f.endsWith(".md"));
  for (const f of md) {
    const t = fs.readFileSync(f, "utf8");
    assert.doesNotMatch(t, /\/data\/|\/home\/|\/tmp\//, `${path.relative(ROOT, f)} names a local path`);
    for (const [, l] of t.matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)) {
      if (/^[a-z]+:/i.test(l)) continue;
      const target = path.resolve(path.dirname(f), l);
      assert.ok(target.startsWith(ROOT) && fs.existsSync(target), `${path.relative(ROOT, f)} links to missing ${l}`);
    }
    for (const [, n] of t.matchAll(/(\d+) tests\b/g)) assert.ok(Number(n) >= 50, `${path.relative(ROOT, f)} says ${n} tests`);
  }
  // no shipped file points at a private runbook or another local file outside the repo
  for (const f of shipped().filter((f) => f !== new URL(import.meta.url).pathname)) assert.doesNotMatch(fs.readFileSync(f, "utf8"), /RUNBOOK-live|\.\.\/RUNBOOK/, `${path.relative(ROOT, f)} points at a private runbook`);
  const readme = fs.readFileSync(path.join(ROOT, "README.md"), "utf8");
  assert.doesNotMatch(readme, /Nothing is sent on the user's behalf without their yes/);
});

// wording: the public code and docs describe the product only. The list of words to keep out is the maintainers' own and lives
// outside the repository (GG_WORDING_FILE: one regular expression); without it this test is skipped.
// The wording gate fails closed: run it once with a missing and once with an empty list file, each must fail.
test("wording gate: a set but missing or empty GG_WORDING_FILE fails instead of skipping", { skip: process.env.GG_WORDING_META && "inner run" }, () => {
  const empty = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ggw-")), "empty.regex"); fs.writeFileSync(empty, "\n");
  for (const wf of ["/nonexistent/wording.regex", empty]) {
    let failed = false;
    try { execFileSync(process.execPath, ["--test", "--test-name-pattern=maintainers", new URL(import.meta.url).pathname], { env: { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== "NODE_TEST_CONTEXT")), GG_WORDING_FILE: wf, GG_WORDING_META: "1" }, stdio: "pipe" }); }
    catch { failed = true; }
    assert.ok(failed, `GG_WORDING_FILE=${wf} did not fail`);
  }
});
// Skipped only when GG_WORDING_FILE is unset; set but missing, empty or not a valid expression fails (fail closed).
const WF = process.env.GG_WORDING_FILE;
test("wording: public text matches the maintainers' wording list", { skip: !WF && "GG_WORDING_FILE not set" }, () => {
  assert.ok(fs.existsSync(WF), `GG_WORDING_FILE ${WF} does not exist`);
  const src = fs.readFileSync(WF, "utf8").trim();
  assert.ok(src.length > 0, "GG_WORDING_FILE is empty");
  const BAD = new RegExp(src, "i");
  assert.ok(!BAD.test(""), "the wording expression matches everything");
  // "sponsor" only in the Concordium sense: the account that pays transaction fees
  const SPONSOR_OK = /fee|facilitator|sponsored|SPONSOR_KEYFILE|sponsor\.export|sponsor account/i;
  const hits = [];
  for (const f of shipped()) {
    if (f === new URL(import.meta.url).pathname) continue;
    fs.readFileSync(f, "utf8").split("\n").forEach((l, i) => {
      // the published Agent Cards keep their on-chain-hashed bytes (their URL host is the publisher's domain)
      if (/agents\/[\w-]+\.json$/.test(f) && /"url"|"agent_uri"|https:\/\/apps\./.test(l)) return;
      // docs/LIVE.md quotes the Agent Card URIs exactly as they were written on chain
      if (/docs\/LIVE\.md$/.test(f) && /https:\/\/apps\.[\w.-]+\/concordium\/agents\/[\w-]+\.json/.test(l)) return;
      if (BAD.test(l) || (/sponsor/i.test(l) && !SPONSOR_OK.test(l))) hits.push(`${path.relative(ROOT, f)}:${i + 1}: ${l.trim().slice(0, 100)}`);
    });
  }
  assert.deepEqual(hits, []);
});
