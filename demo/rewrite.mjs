#!/usr/bin/env node
// Why the anchor matters: a hash chain alone catches an edit, but not a rewrite that recomputes every hash after it.
// The head anchored on chain catches both, and the scheduled re-anchor refuses to anchor a rewritten log.
//
//   npm run demo:rewrite             offline: uses the published public-run log (docs/public-run/audit-public.jsonl) and the head
//                                    anchored for it on 20 Nov (tx c74cd34f…, value copied below; open the tx to compare)
//   npm run demo:rewrite -- --live   reads the head from the registry instead (read-only, no account)
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { verifyAudit, verifyAnchor, planAnchor, record } from "../src/ccd/audit.mjs";

const LOG = new URL("../docs/public-run/audit-public.jsonl", import.meta.url).pathname;
const ANCHOR_20NOV = "16:26b461288441861481482fbd57d499c75a66f0b2732a1f47f5f3241e17af1b56";
const TX_20NOV = "https://ccdexplorer.io/testnet/transaction/c74cd34f5a7b70c5a065acd6439df298cdef5b0b903852114edac37280182260";
const say = (s = "") => console.log(s);
const ok = (b) => (b ? "\x1b[32mOK\x1b[0m" : "\x1b[31mFAIL\x1b[0m");
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gg-rewrite-"));
const copy = (name, lines) => { const f = path.join(dir, name); fs.writeFileSync(f, lines.join("\n") + "\n"); return f; };

let anchor = ANCHOR_20NOV, source = `anchored 20 Nov 2026, ${TX_20NOV}`;
if (process.argv.includes("--live")) {
  const { readAnchor } = await import("../src/ccd/anchor.mjs");
  anchor = await readAnchor(1272, "gigguard.audit.public.head");
  source = "read now from the Agent Registry (token 1272, gigguard.audit.public.head)";
}
const lines = fs.readFileSync(LOG, "utf8").trim().split("\n");
if (!anchor) { say("No head anchored under gigguard.audit.public.head."); process.exit(10); }
let n = Number(anchor.split(":")[0]);
if (lines.length < n) {   // the published copy is older than the newest anchor: use the 20 Nov anchor it covers
  say(`The published copy has ${lines.length} entries, the newest anchor covers ${n}; using the 20 Nov anchor instead.`);
  anchor = ANCHOR_20NOV; source = `anchored 20 Nov 2026, ${TX_20NOV}`; n = 16;
}
const base = lines.slice(0, Math.max(n, 1));   // check the part the anchor covers
say(`Gig Guard's public-run log: ${base.length} entries. Head on chain: ${anchor.slice(0, 24)}… (${source})`);

say("\n1. The log as written");
let v = verifyAudit(copy("honest.jsonl", base)), a = verifyAnchor(path.join(dir, "honest.jsonl"), anchor);
say(`  chain check: ${ok(v.ok)}   anchor check: ${ok(a.ok)}`);

// The attacker wants the log to show a smaller payment: entry #1 paid 100000 microCCD; make it 10000.
const target = base.findIndex((l) => JSON.parse(l).kind === "payment");
const edited = base.slice(); edited[target] = edited[target].replace('"amount":"100000"', '"amount":"10000"');
say(`\n2. Edit one value: entry #${target} now says it paid 0.01 CCD instead of 0.1`);
v = verifyAudit(copy("edited.jsonl", edited)); a = verifyAnchor(path.join(dir, "edited.jsonl"), anchor);
say(`  chain check: ${ok(v.ok)} (${v.reason}, entry #${v.brokenAt})   anchor check: ${ok(a.ok)}`);

// Same edit, then recompute every hash from there on, so the chain is consistent with itself again.
const sortDeep = (x) => Array.isArray(x) ? x.map(sortDeep) : x && typeof x === "object" ? Object.fromEntries(Object.keys(x).sort().map((k) => [k, sortDeep(x[k])])) : x;
const rehashed = []; let prev = "0".repeat(64);
for (const [i, l] of edited.entries()) {
  const { hash, ...body } = JSON.parse(l);
  if (i >= target) { body.prev = prev; const h = crypto.createHash("sha256").update(JSON.stringify(sortDeep(body))).digest("hex"); rehashed.push(JSON.stringify({ ...body, hash: h })); prev = h; }
  else { rehashed.push(l); prev = hash; }
}
say(`\n3. The same edit, then every hash from entry #${target} on recomputed (a full rewrite)`);
const rf = copy("rewritten.jsonl", rehashed);
v = verifyAudit(rf); a = verifyAnchor(rf, anchor);
say(`  chain check: ${ok(v.ok)} (the rewritten log is consistent with itself)`);
say(`  anchor check: ${ok(a.ok)} (${a.reason})`);
const p = planAnchor(rf, anchor);
say(`  scheduled re-anchor: ${p.action.toUpperCase()} (${p.reason})`);

say("\n4. Appending is fine: one new entry after the anchored part");
const af = copy("appended.jsonl", base);
record("decision", { gate: "recheck", verdict: "still accountable" }, { file: af });
a = verifyAnchor(af, anchor);
const p2 = planAnchor(af, anchor);
say(`  anchor check: ${ok(a.ok)} (${a.anchored_entries} anchored, ${a.after_anchor} after)   scheduled re-anchor: ${p2.action.toUpperCase()} ${p2.value?.slice(0, 24)}…`);
fs.rmSync(dir, { recursive: true, force: true });
