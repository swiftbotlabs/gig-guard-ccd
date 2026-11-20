// Renders ledger.jsonl into a static public page: every decision with the Telegraph receipts behind it.
// Public by design: everything goes through redact.mjs first. A "Check receipts live" button asks the
// Telegraph node (CORS-open) whether each receipt is in its settled epoch block, from the viewer's browser.
import fs from "node:fs";
import { readLedger } from "./ledger.mjs";
import { publicLedger } from "./redact.mjs";
import { config, explorers } from "./config.mjs";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const USEFUL = new Set(["GO", "SKIP", "CAUTION", "CLAIM", "PAID", "SHIP", "FIX"]); // a decision the agent could act on

export function writeLedgerPage(out = "ledger.html", { verifyFile } = {}) {
  const L = publicLedger(readLedger());
  const buys = L.filter((e) => e.kind === "purchase");
  const reuses = L.filter((e) => e.kind === "reuse");
  const decisions = L.filter((e) => e.kind === "decision");
  const byHash = Object.fromEntries(buys.map((b) => [b.receipt?.receipt_hash, b]));
  const spent = buys.reduce((s, b) => s + (b.amount_uusdc || 0), 0) / 1e6;
  const useful = decisions.filter((d) => USEFUL.has(d.verdict)).length;
  const lat = buys.map((b) => b.ms).filter(Number.isFinite).sort((a, b) => a - b);
  const p50 = lat.length ? lat[Math.floor(lat.length / 2)] : 0;
  const ver = {};
  try { if (verifyFile && fs.existsSync(verifyFile)) for (const r of JSON.parse(fs.readFileSync(verifyFile, "utf8")).receipts) ver[r.receipt_hash] = ["SETTLED", "PENDING", "MISMATCH", "NOT_FOUND", "UNREACHABLE", "NO_EPOCH"].includes(r.status) ? r.status : ""; } catch {}
  const NET = { "eip155:84532": "Base Sepolia", "eip155:11155111": "Ethereum Sepolia" };
  const nets = [...new Set(buys.map((b) => `${NET[b.network] || b.network} ${b.rail || "x402"}`))].join(", ") || "testnet";
  const checks = buys.filter((b) => b.receipt?.receipt_hash).map((b) => ({ h: b.receipt.receipt_hash, e: b.receipt.epoch_id, i: b.intent, u: Number(b.amount_uusdc) }));
  const rows = decisions.slice().reverse().map((d) => {
    const rc = d.receipts.map((h) => {
      const b = byHash[h] || {};
      const tx = b.receipt?.tx_hash, ex = explorers[b.network];
      const reused = d.evidence?.some((x) => x.reused === h) ? " · reused (no new charge)" : "";
      const st = ver[h] || "";
      return `<li><code>${esc(b.intent)}</code> miner ${esc(b.miner_id)} · $${esc(b.cost_usd)} · ${esc(b.ms)} ms${reused} · receipt <code title="${esc(h)}">${esc(String(h).slice(0, 14))}…</code> epoch ${esc(b.receipt?.epoch_id)} <span class="st ${esc(st)}" data-h="${esc(h)}">${esc(st)}</span>${tx && ex ? ` · <a href="${ex}${esc(tx)}">tx</a>` : ""}</li>`;
    }).join("");
    const wasted = (d.wasted_receipts || []).map((h) => { const b = byHash[h] || {};
      return `<li><code>${esc(b.intent)}</code> miner ${esc(b.miner_id)} · $${esc(b.cost_usd)} · paid, but the answer was empty or stale · receipt <code title="${esc(h)}">${esc(String(h).slice(0, 14))}…</code> epoch ${esc(b.receipt?.epoch_id)} <span class="st ${esc(ver[h] || "")}" data-h="${esc(h)}">${esc(ver[h] || "")}</span></li>`; }).join("");
    const free = (d.evidence || []).filter((x) => /CHAIN_READ/.test(x.intent || "")).map(() => "<li>free chain read (public RPC) cross-checks the paid answer</li>").join("");
    const unc = (d.uncertainty || []).length ? `<div class="unc">uncertain: ${esc(d.uncertainty.join("; "))}</div>` : "";
    const old = d.policy ? "" : `<div class="old">made by an earlier policy version (before v5); later fixes may decide this case differently</div>`;
    const act = d.action && d.action !== "none" ? `<div class="act">next: ${esc(d.action)}</div>` : "";
    return `<tr><td>${esc(d.ts.slice(5, 10))}<br>${esc(d.ts.slice(11, 16))}</td><td>${esc(d.gate)}</td><td class="v ${esc(d.verdict)}">${esc(d.verdict)}</td><td><code class="in">${esc(JSON.stringify(d.input))}</code><div>${esc(d.reasons.join("; "))}</div>${old}${unc}${act}<ul>${rc}${wasted}${free}</ul></td></tr>`;
  }).join("\n");
  const data = JSON.stringify({ node: config.node, checks }).replace(/</g, "\\u003c");
  const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gig Guard ledger</title>
<style>
:root{--bg:#fbfbf9;--card:#fff;--fg:#16171a;--mut:#62666d;--line:#e3e3df;--ok:#0a7d3b;--bad:#b3261e;--warn:#8a5a00;--acc:#2f5bd3}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121316;--card:#1a1b1f;--fg:#ececea;--mut:#9a9da3;--line:#2c2e33;--ok:#5fd38d;--bad:#ff8a80;--warn:#ffcc66;--acc:#8fb0ff}}
:root[data-theme="dark"]{--bg:#121316;--card:#1a1b1f;--fg:#ececea;--mut:#9a9da3;--line:#2c2e33;--ok:#5fd38d;--bad:#ff8a80;--warn:#ffcc66;--acc:#8fb0ff}
*{box-sizing:border-box}body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0 auto;max-width:1040px;padding:24px 16px}
h1{font-size:1.6rem;margin:0 0 4px}p.lead{color:var(--mut);margin:0 0 20px;max-width:70ch}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:0 0 20px}.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px}.tile b{display:block;font-size:1.35rem;font-variant-numeric:tabular-nums}.tile span{color:var(--mut);font-size:.85rem}
button{font:inherit;background:var(--acc);color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer}#vs{color:var(--mut);margin-left:10px}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}th{text-align:left;color:var(--mut);font-weight:600;font-size:.85rem}td,th{border-top:1px solid var(--line);padding:10px;vertical-align:top;word-break:break-word}td:nth-child(-n+3),th:nth-child(-n+3){white-space:nowrap;word-break:normal}
code.in{font-size:.8rem;color:var(--mut)}ul{margin:6px 0 0;padding-left:18px;color:var(--mut);font-size:.88rem}.v{font-weight:700}
.GO,.SHIP,.PAID{color:var(--ok)}.SKIP,.FIX,.CLAIM{color:var(--bad)}.HOLD,.PENDING,.CAUTION{color:var(--warn)}
.unc{color:var(--warn);font-size:.88rem;margin-top:4px}.old{color:var(--mut);font-size:.85rem;font-style:italic;margin-top:4px}.act{font-size:.88rem;margin-top:4px}.st{font-weight:600}.st.SETTLED{color:var(--ok)}.st.MISMATCH{color:var(--bad)}.st.PENDING{color:var(--warn)}
footer{color:var(--mut);font-size:.85rem;margin-top:16px}
</style>
<h1>Gig Guard ledger</h1>
<p class="lead">Every decision an autonomous freelance agent made, and the Telegraph intelligence it paid for to make it. Testnet only (${esc(nets)}, test USDC, no real money). Client names, receiving wallets and links are replaced with neutral labels.</p>
<div class="tiles">
<div class="tile"><b>${decisions.length}</b><span>decisions</span></div>
<div class="tile"><b>${buys.length}</b><span>paid requests</span></div>
<div class="tile"><b>${reuses.length}</b><span>answers reused (no new charge)</span></div>
<div class="tile"><b>$${spent.toFixed(2)}</b><span>test USDC spent</span></div>
<div class="tile"><b>$${useful ? (spent / useful).toFixed(3) : "n/a"}</b><span>per useful decision</span></div>
<div class="tile"><b>${(p50 / 1000).toFixed(1)} s</b><span>median answer time</span></div>
</div>
<p><button id="vb" type="button">Check receipts live</button><span id="vs">Asks the Telegraph node whether each receipt is in its settled epoch block. No wallet needed.</span></p>
<div class="wrap"><table><tr><th>time (UTC)</th><th>gate</th><th>verdict</th><th>input, reasons, receipts</th></tr>${rows}</table></div>
<footer>SETTLED: the epoch block lists the delivery with the same intent and amount. PENDING: the epoch's block isn't recorded yet (up to about an hour after each 3-hour epoch). Generated ${esc(new Date().toISOString().slice(0, 16).replace("T", " "))} UTC by Gig Guard.</footer>
<script>
const D=${data};
document.getElementById("vb").onclick=async()=>{const vs=document.getElementById("vs");const n={SETTLED:0,PENDING:0,MISMATCH:0,OTHER:0};vs.textContent="checking "+D.checks.length+" receipts…";
for(const c of D.checks){let s="OTHER";try{const r=await fetch(D.node+"/v1/blocks/"+c.e+"/deliveries/"+c.h);const j=await r.json();
if(r.ok){const d=j.delivery||{};s=(d.intent===c.i&&Number(d.usdc)===c.u)?"SETTLED":"MISMATCH"}else if(/no block recorded/.test(j.error||""))s="PENDING";}catch(e){}
n[s]++;document.querySelectorAll('.st[data-h="'+c.h+'"]').forEach(el=>{el.textContent=s;el.className="st "+s});}
vs.textContent=n.SETTLED+" settled, "+n.PENDING+" pending, "+n.MISMATCH+" mismatched, "+n.OTHER+" not checked";};
</script></html>`;
  fs.writeFileSync(out, html);
  return out;
}
