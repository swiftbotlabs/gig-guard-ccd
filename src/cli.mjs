#!/usr/bin/env node
// gig-guard: the three gates as shell commands, plus `run` for an agent loop.
import fs from "node:fs";
import { scoutLead, claimPayment, shipCheck } from "./guards.mjs";
import { writeLedgerPage } from "./page.mjs";
import { publicLedger } from "./redact.mjs";
import { readLedger } from "./ledger.mjs";
import { verifyLedger } from "./verify.mjs";
import { readWorkspaceFile } from "./files.mjs";
import { record, verifyAudit } from "./ccd/audit.mjs";
// Art. 12 style record of every decision (who, what, why, with which evidence, with or without the user's yes).
const logDecision = (it, r) => record("decision", { item: it.id || null, gate: it.gate, verdict: r.verdict, action: r.action || null, approved: it.approved ?? null, reasons: r.reasons, uncertainty: r.uncertainty || [], receipts: r.receipts, cost_usd: r.cost_usd ?? null, cost_ccd: r.cost_ccd || 0 });
const [cmd, ...a] = process.argv.slice(2);
const usage = `gig-guard scout <url> <client> [amountUsd]          triage a job lead and its payer
gig-guard claim <json>                                 overdue payment -> proof + claim draft
     json: {"wallet","chain","token","txHash?","client","amountUsd","termsFile?","dueDate?","contact?","label?","approved?"}
     approved: true|false|absent. A CLAIM is never sent by Gig Guard; without approved:true it waits for the user.
gig-guard ship <file>                                  review a deliverable before handing it over
gig-guard audit [audit.jsonl]                          recompute the decision log's hash chain (exit 10 if edited)
gig-guard run <queue.json> [out.json]                  run every pending item in a queue (agent loop)
gig-guard ledger [out.html] [verify.json]              render the public ledger page (redacted)
gig-guard export [out.jsonl]                           redacted copy of the ledger, safe to publish
gig-guard verify [out.json]                            check every receipt against the node's settled epoch blocks
  Public output replaces client names (or a queue item's "label"), receiving wallets, tx hashes and links.
  ledger.jsonl itself is PRIVATE: never publish it.`;
const GO = ["GO", "PAID", "SHIP"];
async function runItem(it) {
  if (it.gate === "scout") return scoutLead(it);
  if (it.gate === "claim") return claimPayment({ ...it, termsText: it.termsFile ? readWorkspaceFile(it.termsFile) : it.termsText });
  if (it.gate === "ship") return shipCheck(readWorkspaceFile(it.file), { name: String(it.file).split("/").pop() });
  throw new Error(`unknown gate ${it.gate}`);
}
try {
  let d;
  if (cmd === "scout") d = await scoutLead({ url: a[0], client: a[1], amountUsd: Number(a[2]) || undefined });
  else if (cmd === "claim") d = await runItem({ gate: "claim", ...JSON.parse(a[0]) });
  else if (cmd === "ship") d = await runItem({ gate: "ship", file: a[0] });
  else if (cmd === "run") {
    const q = JSON.parse(fs.readFileSync(a[0], "utf8"));
    const out = [];
    for (const it of q.filter((x) => !x.done)) {
      const t0 = Date.now();
      console.error(`[${new Date().toISOString().slice(11, 19)}] ${it.id}: ${it.gate} gate, buying intelligence from Telegraph...`);
      try { const r = await runItem(it); logDecision(it, r);
        console.error(`[${new Date().toISOString().slice(11, 19)}] ${it.id}: ${r.verdict}  ($${Number(r.cost_usd || 0).toFixed(2)}, ${r.receipts.length} receipt${r.receipts.length === 1 ? "" : "s"}, ${((Date.now() - t0) / 1000).toFixed(1)} s)${r.action && r.action !== "none" ? "  next: " + r.action : ""}`);
        for (const x of r.reasons) console.error(`           - ${x.slice(0, 150)}`);
        for (const x of r.uncertainty || []) console.error(`           ? ${x.slice(0, 150)}`);
        out.push({ id: it.id, gate: it.gate, verdict: r.verdict, action: r.action, uncertainty: r.uncertainty, reasons: r.reasons, receipts: r.receipts, cost_usd: r.cost_usd, cost_ccd: r.cost_ccd, claim: r.claim }); it.done = new Date().toISOString(); it.verdict = r.verdict; }
      catch (e) { console.error(`[${new Date().toISOString().slice(11, 19)}] ${it.id}: refused before paying: ${e.message}`); out.push({ id: it.id, gate: it.gate, error: e.message }); if (e.name === "BudgetError") break; }
    }
    fs.writeFileSync(a[0], JSON.stringify(q, null, 2));
    if (a[1]) fs.writeFileSync(a[1], JSON.stringify(out, null, 2));
    console.log(JSON.stringify(out, null, 2)); process.exit(0);
  }
  else if (cmd === "audit") { const v = verifyAudit(a[0]); console.log(JSON.stringify(v)); process.exit(v.ok ? 0 : 10); }
  else if (cmd === "export") { const out = a[0] || "ledger.public.jsonl"; fs.writeFileSync(out, publicLedger(readLedger()).map((e) => JSON.stringify(e)).join("\n") + "\n"); console.log(out); process.exit(0); }
  else if (cmd === "verify") { const v = await verifyLedger(); if (a[0]) fs.writeFileSync(a[0], JSON.stringify(v, null, 2)); const { receipts, ...sum } = v; console.log(JSON.stringify(sum)); process.exit(v.mismatch ? 10 : 0); }
  else if (cmd === "ledger") { console.log(writeLedgerPage(a[0], { verifyFile: a[1] })); process.exit(0); }
  else { console.log(usage); process.exit(cmd ? 2 : 0); }
  logDecision({ gate: cmd, ...(cmd === "claim" ? JSON.parse(a[0]) : {}) }, d);
  console.log(JSON.stringify({ verdict: d.verdict, action: d.action, uncertainty: d.uncertainty, reasons: d.reasons, receipts: d.receipts, cost_usd: d.cost_usd, cost_ccd: d.cost_ccd, ms: d.ms, notes: d.notes, claim: d.claim }, null, 2));
  process.exit(GO.includes(d.verdict) ? 0 : 10);
} catch (e) { console.error("gig-guard:", e.message); process.exit(1); }
