// Policy tests against a fake Telegraph node that speaks real x402 headers (no network, no funds).
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";

const WALLET = "0x3333333333333333333333333333333333333333";
const LEAKW = "0x4444444444444444444444444444444444444444";
const SYMW = "0x5555555555555555555555555555555555555555", STALEW = "0x6666666666666666666666666666666666666666";
const answers = {
  URL_SCAN_VERDICT: (p) => ({ verdict: p.url.includes("evil") ? (p.url.includes("leak") ? "Malicious: reported by Jane Leakname sk_live_LEAKSECRET123" : "Malicious") : "Safe" }),
  WEB_SEARCH_GENERAL: (p) => ({ brief: /shadyco/i.test(p.query) ? "Several freelancers report ShadyCo never paid." : `${p.query.split(" ")[0]} clients report payments within two weeks.`, sources: ["x"] }),
  NEWS_SEARCH_GENERAL: () => ({ brief: "fallback answer", sources: ["n"] }),
  // live shape: on bsc a token SYMBOL gets an all-null answer, a token CONTRACT gets the balance
  WALLET_BALANCE_CHECK_GENERAL: (p) => p.address === SYMW ? { address: p.address, balance: 0, token_symbol: "USDT reported by Jane Leakname", as_of: new Date().toISOString() }
    : p.address === STALEW ? { address: p.address, balance: 0, token_symbol: "USDT", as_of: "sometime last week" }
    : p.address === LEAKW ? { address: p.address, balance: 0, token_symbol: "USDT reported by Jane Leakname sk_live_LEAK", as_of: "pending, call @leakyhandle" } : p.chain === "bsc" && !p.token.startsWith("0x") ? { address: null, chain: null, balance: null, token_symbol: p.token, as_of: null }
    : p.chain === "tron" ? { address: null, chain: null, balance: null, token_symbol: p.token, as_of: null }
    : ({ address: p.address, balance: /USDT|0xdAC17/i.test(p.token) ? 0 : 500, token_symbol: p.token || "ETH", as_of: new Date().toISOString() }),
  ONCHAIN_TX_LOOKUP_GENERAL: (p) => p.tx_hash.endsWith("77") ? { status: "pending, reported by Jane Leakname sk_live_LEAK @leakyhandle", to: "x" } : ({ status: p.tx_hash.endsWith("00") ? "reverted" : "confirmed", to: WALLET.toLowerCase() }),
  CONTRACT_OBLIGATION_AUDIT_GENERAL: () => ({ verdict: "Non-compliant", summary: "Client must pay within 30 days.", obligations: ["pay within 30 days"] }),
  SECURITY_REVIEW_GENERAL: (p) => p.target.includes("nancount") ? { verdict: "Secure", vulnerability_count: "lots", issues: ["CWE-79"] } : p.target.includes("leaky") ? { verdict: "Insecure sk_live_LEAKSECRET123 call +1 555 0100 @leakyhandle", vulnerability_count: 1, issues: ["CWE-863 found by Jane Leakname, bot token 123456:LEAKTOKEN"] } : p.target.includes("nullverdict") ? { verdict: null, vulnerability_count: 1, issues: ["CWE-863"], summary: null } : ({ verdict: p.target.includes("tx.origin") ? "Insecure" : "Secure", vulnerability_count: p.target.includes("tx.origin") ? 1 : 0, issues: ["SWC-115"] }),
  SMART_CONTRACT_AUDIT_GENERAL: (p) => ({ verdict: p.code.includes("tx.origin") ? "High" : "Low" }),
  CODE_REVIEW_GENERAL: () => ({ verdict: "Approve", summary: "ok" }),
};
let failNext = new Set(), emptyNext = new Set(), unrelated = false, poison = false, poison402 = false;
// poison mode: every string a miner or the node sends carries a marker; none may reach reasons, uncertainty or public output
const P = "POISONx sk_live_POISON Jane Poisonname @poisonhandle +1 555 0199 ";
// no-space variant: passes every [A-Za-z0-9_.:|-] field check, so only a field-specific validator stops it
const PN = "sk_live_POISONx.Jane.Poisonname:acme-unpaid.example|";
const poisoned = (v, m = P) => (typeof v === "string" ? m + v : Array.isArray(v) ? v.map(poisoned) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, poisoned(x, m)])) : v);
let rpcUsdt = 400n * 10n ** 6n, staleNext = false;
const srv = http.createServer((req, res) => {
  let b = "";
  req.on("data", (c) => (b += c));
  req.on("end", () => {
    if (req.url.startsWith("/rpc")) { // fake public RPC: balanceOf -> rpcUsdt, decimals -> 6
      const { params } = JSON.parse(b); const sel = params[0]?.data?.slice(0, 10);
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x" + (sel === "0x313ce567" ? 6n : rpcUsdt).toString(16) }));
    }
    if (req.url.startsWith("/v1/blocks/")) { // fake settled block: epoch 8 recorded, 9 not yet
      const [, , , ep, , h] = req.url.split("/");
      if (ep === "9") { res.writeHead(404, { "content-type": "application/json" }); return res.end(JSON.stringify({ error: (poison === "nospace" ? PN : "") + "no block recorded for this epoch" })); }
      res.writeHead(200, { "content-type": "application/json" });
      return res.end(JSON.stringify({ deliveries_root: "0xroot", proof: ["0x1"], delivery: { receipt_hash: h, payer: "0xabc", miner_id: "7", intent: h.endsWith("bad") ? "OTHER" : "WALLET_BALANCE_CHECK_GENERAL", usdc: 10000 } }));
    }
    const { intent, params } = JSON.parse(b);
    if (!req.headers["payment-signature"]) {
      const ch = { x402Version: 2, error: "Payment required", resource: { url: "x", description: "", mimeType: "application/json" },
        accepts: [{ scheme: "exact", network: "eip155:84532", amount: "10000", asset: poison402 ? PN : "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          payTo: "0x72a70e949362670Bf8bceAd24eFC5b8f950aa08b", maxTimeoutSeconds: 60, extra: { name: "USDC", version: "2" } }] };
      res.writeHead(402, { "PAYMENT-REQUIRED": Buffer.from(JSON.stringify(ch)).toString("base64"), "content-type": "application/json" });
      return res.end("{}");
    }
    if (failNext.has(intent) || !answers[intent]) { res.writeHead(503, { "content-type": "application/json" }); return res.end(poison ? JSON.stringify({ error: P }) : '{"error":"no miner"}'); }
    const rc = poison === "nospace" || poison === "receipt" ? { receipt_hash: "0x" + Math.random().toString(16).slice(2).padEnd(64, "0"), tx_hash: PN, amount_uusdc: PN, intent: PN, epoch_id: PN } : { receipt_hash: "0x" + Math.random().toString(16).slice(2).padEnd(64, "0"), tx_hash: "0xfeed", amount_uusdc: 10000, intent, epoch_id: 8 };
    res.writeHead(200, { "X-TELEGRAPH-RECEIPT": Buffer.from(JSON.stringify(rc)).toString("base64"), "content-type": "application/json" });
    if (staleNext && intent === "WALLET_BALANCE_CHECK_GENERAL") { res.end(JSON.stringify({ miner_id: "7", cost_usd: 0.01, result: { address: params.address, balance: 0, token_symbol: "USDT", as_of: "2026-01-01T00:00:00Z" } })); return; }
    const result = unrelated && intent === "WEB_SEARCH_GENERAL" ? { answer: null, brief: null, sources: ["https://coingeek.com/x", "https://example.org/y"] } : emptyNext.has(intent) ? { answer: null, brief: null, sources: [] } : answers[intent](params);
    res.end(JSON.stringify({ miner_id: poison === "nospace" ? PN : poison === true ? P : "7", result: poison === "nospace" ? poisoned(result, PN) : poison === true ? poisoned(result) : result, cost_usd: 0.01 }));
  });
});
await new Promise((r) => srv.listen(0, r));
process.env.TELEGRAPH_NODE = `http://127.0.0.1:${srv.address().port}`;
process.env.TELEGRAPH_PAYER_KEY = "0x" + "11".repeat(32);
process.env.GG_LEDGER = path.join(os.tmpdir(), `gg-${Date.now()}.jsonl`);
process.env.GG_RAIL = "x402";  // the fake node speaks the x402 exact challenge
process.env.GG_NO_RPC = "1";  // tests that want the chain cross-check turn it on and point it at the fake RPC
process.env.GG_REUSE = "0";   // likewise for answer reuse
const g = await import("../src/guards.mjs");
test.after(() => srv.close());

test("scout: reputable client GO, client with unpaid-payment reports CAUTION, malicious link SKIP", async () => {
  assert.equal((await g.scoutLead({ url: "https://jobs.example/board/x", client: "GoodDAO", amountUsd: 225 })).verdict, "GO");
  assert.equal((await g.scoutLead({ url: "https://shadyco.io/job", client: "ShadyCo", amountUsd: 1000 })).verdict, "CAUTION");
  assert.equal((await g.scoutLead({ url: "https://evil.example/claim", client: "GoodDAO" })).verdict, "SKIP");
});
test("scout: search that never mentions the client is CAUTION, not GO (live shape)", async () => {
  emptyNext = new Set(); unrelated = true;
  const d = await g.scoutLead({ url: "https://jobs.example/x", client: "QuietCo" });
  unrelated = false;
  assert.equal(d.verdict, "CAUTION");
  assert.match(d.reasons.join(" "), /no independent record/);
});
test("scout: falls back to a second intent when the first has no supply", async () => {
  failNext = new Set(["WEB_SEARCH_GENERAL"]);
  const d = await g.scoutLead({ url: "https://jobs.example/x", client: "GoodDAO" });
  failNext = new Set();
  assert.equal(d.evidence[1].intent, "NEWS_SEARCH_GENERAL");
  assert.equal(d.receipts.length, 2);
});
test("scout: bad URL refused before any purchase", async () => {
  await assert.rejects(g.scoutLead({ url: "not a url", client: "x" }));
});
test("claim: unpaid payment produces a claim draft with receipts; paid payment does not", async () => {
  const c = await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDT", client: "ExampleCo", amountUsd: 400, termsText: "Invoices are paid within 30 days.", dueDate: "2026-11-15" });
  assert.equal(c.verdict, "CLAIM");
  assert.match(c.claim, /receipt 0x/);
  assert.equal(c.receipts.length, 2);
  const p = await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDC", client: "GoodDAO", amountUsd: 400 });
  assert.equal(p.verdict, "PAID");
  assert.equal(p.claim, undefined);
});
test("claim: client's 'sent' tx that reverted is claimed, confirmed one is PAID", async () => {
  assert.equal((await g.claimPayment({ wallet: WALLET, chain: "base", txHash: "0x" + "ab".repeat(31) + "00", client: "X", amountUsd: 5 })).verdict, "CLAIM");
  assert.equal((await g.claimPayment({ wallet: WALLET, chain: "base", txHash: "0x" + "ab".repeat(32), client: "X", amountUsd: 5 })).verdict, "PAID");
  await assert.rejects(g.claimPayment({ wallet: "nope", chain: "base" }));
});
test("claim: no proof available -> PENDING, never a claim", async () => {
  failNext = new Set(["WALLET_BALANCE_CHECK_GENERAL"]);
  const d = await g.claimPayment({ wallet: WALLET, chain: "base", token: "USDC", client: "X", amountUsd: 5 });
  failNext = new Set();
  assert.equal(d.verdict, "PENDING");
  assert.equal(d.claim, undefined);
});
test("ship: null verdict but counted issues is still sent back (live miner shape)", async () => {
  assert.equal((await g.shipCheck("pragma solidity ^0.8.0; contract B { function g() public { nullverdict(); } }")).verdict, "FIX");
});
test("scout: a paid but empty answer falls through to the next supplier", async () => {
  failNext = new Set(); emptyNext = new Set(["WEB_SEARCH_GENERAL"]);
  const d = await g.scoutLead({ url: "https://jobs.example/x", client: "GoodDAO" });
  emptyNext = new Set();
  assert.equal(d.evidence[1].intent, "NEWS_SEARCH_GENERAL");
  assert.equal(d.evidence[1].tried[0].error, "empty answer");
});
test("ship: tx.origin contract is sent back, clean contract ships", async () => {
  assert.equal((await g.shipCheck("pragma solidity ^0.8.0; contract A { function f() public { require(tx.origin == msg.sender); } }")).verdict, "FIX");
  assert.equal((await g.shipCheck("pragma solidity ^0.8.0; contract A { uint x; }")).verdict, "SHIP");
  await assert.rejects(g.shipCheck("   "));
});
test("every decision carries receipts and the ledger page renders", async () => {
  const { readLedger } = await import("../src/ledger.mjs");
  const ds = readLedger().filter((e) => e.kind === "decision" && e.verdict !== "PENDING");
  assert.ok(ds.length >= 9 && ds.every((d) => d.receipts.length >= 1));
  const { writeLedgerPage } = await import("../src/page.mjs");
  writeLedgerPage(path.join(os.tmpdir(), "gg.html"));
});

test("claim: BSC is asked by token contract (symbol answers come back null), unknown chain is PENDING", async () => {
  const d = await g.claimPayment({ wallet: WALLET, chain: "BNB Smart Chain", token: "USDT", client: "Payment B", amountUsd: 800 });
  assert.equal(d.verdict, "CLAIM");
  assert.match(d.reasons[0], /holds 500 /);
  const u = await g.claimPayment({ wallet: WALLET, chain: "tron", token: "USDT", client: "Payment C", amountUsd: 50 });
  assert.equal(u.verdict, "PENDING");
  assert.match(u.reasons[0], /likely unsupported/);
  assert.equal(u.claim, undefined);
});
test("public page and export never show client names, receiving wallets or client links", async () => {
  await g.scoutLead({ url: "https://acmezeta.example/job", client: "Acme Zeta", amountUsd: 400 });
  await g.claimPayment({ wallet: "0x2222222222222222222222222222222222222222", chain: "ethereum", token: "USDT", client: "Acme Zeta", amountUsd: 400, label: "Payment A" });
  const fs = await import("node:fs");
  const { publicLedger } = await import("../src/redact.mjs");
  const { writeLedgerPage } = await import("../src/page.mjs");
  const out = path.join(os.tmpdir(), `gg-pub-${Date.now()}.html`);
  writeLedgerPage(out);
  const pub = JSON.stringify(publicLedger()) + fs.readFileSync(out, "utf8");
  for (const bad of [/zeta/i, /acme/i, /2222222222222222222222222222222222222222/i, /Invoices are paid/, /To: /]) assert.doesNotMatch(pub, bad);
  assert.match(pub, /Client [A-Z]|Payment A/);
  assert.match(pub, /receipt_hash|receipt <code>0x/); // receipts stay verifiable
});

// Re-review 2, finding 4: raw answer text (terms summaries, search snippets) never reaches public output, and
// e-mail and non-EVM addresses inside any public text are redacted by value.
test("public output: no terms text or search snippets; e-mails and base58 addresses redacted by value", async () => {
  const fs = await import("node:fs");
  const { publicLedger, makeRedactor } = await import("../src/redact.mjs");
  await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDT", client: "Payment G", amountUsd: 400, termsText: "Pay within 30 days." });
  const pub = JSON.stringify(publicLedger());
  assert.doesNotMatch(pub, /Client must pay within 30 days/);   // the terms summary the fake reviewer returns
  assert.doesNotMatch(pub, /clients report payments within two weeks|Several freelancers report/);   // search snippets
  const R = makeRedactor([]);
  const t = R.text("write to billing@acme-corp.example or pay 4n3P1UDZA2usiVTS95mteZRnMB7pizRb9LcsmqrQMstnCgcE9K / TJYeasTPa6gpEEfYqA1ssu3rKwXeGcbLGb");
  assert.doesNotMatch(t, /billing@|acme-corp|4n3P1UDZA2usiVTS95mteZRnMB7pizRb9LcsmqrQMstnCgcE9K|TJYeasTPa6gpEEfYqA1ssu3rKwXeGcbLGb/);
  assert.match(t, /\[email\]/);
});

// Re-review 3, follow-up 2: reviewer and link-scan free text never reaches public reasons; it stays in private notes.
test("public output: reviewer and link-scan free text (secrets, names, handles) stays out of reasons", async () => {
  const { publicLedger } = await import("../src/redact.mjs");
  const s = await g.shipCheck("pragma solidity ^0.8.0; contract L { function f() public { leaky(); require(tx.origin == msg.sender); } }");
  const k = await g.scoutLead({ url: "https://evil-leak.example/x", client: "GoodDAO" });
  assert.equal(s.verdict, "FIX"); assert.equal(k.verdict, "SKIP");
  for (const d of [s, k]) assert.doesNotMatch(JSON.stringify(d.reasons), /LEAK|Leakname|555 0100|leakyhandle/i);
  assert.match(JSON.stringify(s.notes), /LEAKSECRET/);   // the agent still has the detail privately
  assert.match(s.reasons.join(" "), /CWE-863/);
  assert.doesNotMatch(JSON.stringify(publicLedger()), /LEAK|Leakname|555 0100|leakyhandle/i);
});

// Delta review 4, item 2: the claim gate's reasons carry fixed text only: no paid status, token symbol or time text from an answer.
test("claim gate: paid status, token symbol and as_of free text never reach the reasons or the public output", async () => {
  const { publicLedger } = await import("../src/redact.mjs");
  const a = await g.claimPayment({ wallet: LEAKW, chain: "ethereum", client: "Payment L", amountUsd: 5 });
  const b = await g.claimPayment({ wallet: WALLET, chain: "base", txHash: "0x" + "ab".repeat(31) + "77", client: "Payment M", amountUsd: 5 });
  for (const d of [a, b]) assert.doesNotMatch(JSON.stringify(d.reasons), /leak|leakname|leakyhandle/i, JSON.stringify(d.reasons));
  assert.match(b.reasons.join(" "), /is pending/);
  assert.match(JSON.stringify(b.notes), /Leakname/i);   // kept privately
  assert.doesNotMatch(JSON.stringify(publicLedger()), /leakname|leakyhandle|sk_live/i);
});

// Delta review 5, item 3: each guard proven on its own.
test("claim gate: a fresh answer with a leaky token symbol keeps the symbol out (safeSym alone)", async () => {
  const d = await g.claimPayment({ wallet: SYMW, chain: "tron", client: "Payment S", amountUsd: 5 });
  assert.equal(d.verdict, "CLAIM", JSON.stringify(d.reasons));
  assert.doesNotMatch(d.reasons.join(" "), /leakname|reported/i);
});
test("claim gate: a clean answer with an unreadable as_of is stale, so no claim is made on it (stale() fails closed)", async () => {
  const d = await g.claimPayment({ wallet: STALEW, chain: "tron", client: "Payment T", amountUsd: 5 });
  assert.equal(d.verdict, "PENDING", JSON.stringify([d.verdict, d.reasons]));
});
// Delta review 5, item 4: a non-numeric vulnerability_count never reads as "no issues".
test("ship gate: a non-numeric vulnerability count is not reported as no issues", async () => {
  const d = await g.shipCheck("pragma solidity ^0.8.0; contract N { function f() public { nancount(); } }");
  assert.doesNotMatch(d.reasons.join(" "), /no issues/, JSON.stringify(d.reasons));
});

// Full public-text pass (delta review 6): with every miner/node string poisoned, no gate lets it into reasons, uncertainty or the public ledger.
test("poison: miner and node text never reaches reasons, uncertainty or public output, across every gate", async () => {
  const { publicLedger } = await import("../src/redact.mjs");
  poison = true;
  const ds = [];
  try {
    ds.push(await g.scoutLead({ url: "https://jobs-q.example/x", client: "Acme Q", amountUsd: 5 }));
    ds.push(await g.scoutLead({ url: "https://evil.example/claim", client: "Acme Q" }));
    ds.push(await g.claimPayment({ wallet: "0x7777777777777777777777777777777777777777", chain: "ethereum", token: "USDT", client: "Payment P", amountUsd: 5, termsText: "Pay within 30 days." }));
    ds.push(await g.claimPayment({ wallet: WALLET, chain: "base", txHash: "0x" + "cd".repeat(32), client: "Payment Q", amountUsd: 5 }));
    ds.push(await g.claimPayment({ wallet: "0x8888888888888888888888888888888888888888", chain: "tron", token: "USDT", client: "Payment R", amountUsd: 5 }));
    ds.push(await g.shipCheck("pragma solidity ^0.8.0; contract Q { function f() public { require(tx.origin == msg.sender); } }"));
    failNext = new Set(["URL_SCAN_VERDICT", "URL_SAFE_GENERAL"]);
    ds.push(await g.scoutLead({ url: "https://jobs-r.example/x", client: "Acme Q" }));
  } finally { poison = false; failNext = new Set(); }
  for (const d of ds) assert.doesNotMatch(JSON.stringify([d.reasons, d.uncertainty]), /poison/i, JSON.stringify([d.gate, d.reasons, d.uncertainty]));
  assert.doesNotMatch(JSON.stringify(publicLedger()), /poison/i);
});

// Review 7: the no-space marker passes every generic WORD field check, so it proves the field-specific validators (miner_id, receipt fields);
// the x402 refusal for a bad asset must name the field, not echo it; crafted error/evidence lines never reach the public copy.
test("poison (no-space): miner_id, receipt fields, result text and x402 refusals stay out of public output", async () => {
  const { publicLedger } = await import("../src/redact.mjs");
  const { ask } = await import("../src/telegraph.mjs");
  poison = "nospace";
  const ds = [];
  try {
    ds.push(await g.scoutLead({ url: "https://jobs-s.example/x", client: "Acme S", amountUsd: 5 }));
    ds.push(await g.claimPayment({ wallet: "0x9999999999999999999999999999999999999999", chain: "ethereum", token: "USDT", client: "Payment S2", amountUsd: 5, termsText: "Pay in 30 days." }));
    ds.push(await g.shipCheck("pragma solidity ^0.8.0; contract S { uint x; }"));
  } finally { poison = false; }
  const { verifyReceipt } = await import("../src/verify.mjs");
  poison = "nospace";
  let v; try { v = await verifyReceipt({ receipt_hash: "0x" + "ab".repeat(32), epoch_id: 9 }); } finally { poison = false; }
  assert.equal(v.status, "PENDING"); assert.doesNotMatch(JSON.stringify(v), /poison/i, JSON.stringify(v));
  poison402 = true;
  let err = null;
  try { await ask("URL_SAFE_GENERAL", { url: "https://example.org" }); } catch (e) { err = e; } finally { poison402 = false; }
  assert.ok(err, "the bad-asset offer is refused");
  assert.doesNotMatch(String(err.message), /poison/i, String(err.message));
  for (const d of ds) assert.doesNotMatch(JSON.stringify([d.reasons, d.uncertainty]), /poison/i, JSON.stringify([d.gate, d.reasons, d.uncertainty]));
  // the claim letter (sent after the user's yes) carries only well-formed hashes; reviewer text is labelled as such
  poison = "receipt";
  let lc; try { lc = await g.claimPayment({ wallet: "0x1212121212121212121212121212121212121212", chain: "ethereum", token: "USDT", client: "Payment S3", amountUsd: 5000, termsText: "Pay in 30 days." }); } finally { poison = false; }
  const letter = lc.claim || "";
  assert.ok(letter, `a claim letter was drafted (${lc.verdict}) ${JSON.stringify([lc.reasons, lc.uncertainty, lc.evidence?.map((e) => [e.intent, e.ok, e.error, (e.tried || []).map((t) => t.error)])])}`);
  assert.doesNotMatch(letter.replace(/terms, as summarised by a paid reviewer[^\n]*/g, ""), /poison/i, letter);
  assert.match(letter, /as summarised by a paid reviewer \(check before sending\)/);
  const crafted = [{ ts: "2026-11-20T00:00:00Z", kind: "error", intent: PN, error: P + PN, status: PN, body: PN },
    { ts: "2026-11-20T00:00:00Z", kind: "decision", gate: "claim", verdict: "PENDING", input: {}, reasons: [], uncertainty: [], evidence: [{ intent: "X", ok: false, error: P + PN, miner_id: PN, reused: PN }] },
    { ts: "2026-11-20T00:00:00Z", kind: "purchase", intent: "X", miner_id: PN, receipt: { receipt_hash: PN, tx_hash: PN, epoch_id: PN }, rail: P, network: P, payer: PN }];
  assert.doesNotMatch(JSON.stringify(publicLedger()) + JSON.stringify(publicLedger(crafted)), /poison/i);
});

// review 8, positive controls: the x402 refusal check itself, and scheme:// link masking in public reasons
test("x402 refusal names the field only; any scheme:// link is masked in public text", async () => {
  const { x402Refusal } = await import("../src/telegraph.mjs");
  const { publicLedger } = await import("../src/redact.mjs");
  const PN = "sk_live_POISONx.Jane.Poisonname:acme-unpaid.example|";
  for (const r of [{ scheme: PN }, { scheme: "exact", network: PN }, { scheme: "exact", network: "eip155:84532", asset: PN }, { scheme: "exact", network: "eip155:84532", asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", amount: PN }]) {
    const why = x402Refusal(r);
    assert.ok(why, JSON.stringify(r)); assert.doesNotMatch(why, /poison/i, why);
  }
  const pub = JSON.stringify(publicLedger([{ ts: "2026-11-20T00:00:00Z", kind: "decision", gate: "scout", verdict: "CAUTION", input: {}, reasons: ["see ftp://acme-secret.example/x and ipfs://bafyPOISON"], uncertainty: [] }]));
  assert.doesNotMatch(pub, /acme-secret|bafyPOISON/, pub);
});

test("reuse: the same fresh question is answered from the ledger, not paid twice", async () => {
  process.env.GG_REUSE = "1";
  const { readLedger } = await import("../src/ledger.mjs");
  const paid = () => readLedger().filter((e) => e.kind === "purchase").length;
  await g.scoutLead({ url: "https://reuse.example/x", client: "ReuseDAO" });
  const n = paid();
  const d = await g.scoutLead({ url: "https://reuse.example/x", client: "ReuseDAO" });
  process.env.GG_REUSE = "0";
  assert.equal(paid(), n);
  assert.equal(d.cost_usd, 0);
  assert.ok(d.evidence.every((e) => e.reused));
});
test("claim: a free chain read overrules a wrong miner balance and says so", async () => {
  process.env.GG_NO_RPC = "0"; process.env.GG_RPC_ETHEREUM = `${process.env.TELEGRAPH_NODE}/rpc`;
  const d = await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDT", client: "Payment D", amountUsd: 400 });
  rpcUsdt = 0n;
  const c = await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDT", client: "Payment D", amountUsd: 400 });
  process.env.GG_NO_RPC = "1"; rpcUsdt = 400n * 10n ** 6n;
  assert.equal(d.verdict, "PAID");                       // miner said 0, chain says 400
  assert.match(d.uncertainty.join(" "), /disagrees with the chain/);
  assert.equal(c.verdict, "CLAIM");
  assert.match(c.reasons.join(" "), /chain read agrees/);
  assert.match(c.claim, /independent chain read/);
});
test("claim: consent. No approval -> waits; declined -> not sent and no letter kept", async () => {
  const w = await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDT", client: "Payment E", amountUsd: 400 });
  assert.equal(w.action, "awaiting user approval");
  const n = await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDT", client: "Payment E", amountUsd: 400, approved: false });
  assert.equal(n.action, "declined by user: not sent");
  assert.equal(n.claim, undefined);
  const y = await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDT", client: "Payment E", amountUsd: 400, approved: true });
  assert.match(y.action, /^approved/);
});
test("claim: a stale balance reading is not evidence", async () => {
  staleNext = true;
  const d = await g.claimPayment({ wallet: WALLET, chain: "ethereum", token: "USDT", client: "Payment F", amountUsd: 400 });
  staleNext = false;
  assert.equal(d.verdict, "PENDING");
  assert.match(JSON.stringify(d.evidence), /stale answer/);
});
test("ship: miner findings are corroborated by local rules, or marked miner-only", async () => {
  const v = await g.shipCheck("pragma solidity ^0.8.0; contract A { function f() public { require(tx.origin == msg.sender); } }");
  assert.match(v.reasons.join(" "), /confirmed by local rules: tx.origin/);
  const m = await g.shipCheck("pragma solidity ^0.8.0; contract B { function g() public { nullverdict(); } }");
  assert.equal(m.verdict, "FIX");
  assert.match(m.uncertainty.join(" "), /miner-only/);
});
test("verify: receipts are checked against the node's epoch blocks", async () => {
  const { verifyReceipt } = await import("../src/verify.mjs");
  const H = (x) => "0x" + x.padStart(64, "0");
  assert.equal((await verifyReceipt({ receipt_hash: H("aa"), epoch_id: 8, intent: "WALLET_BALANCE_CHECK_GENERAL", amount_uusdc: 10000 })).status, "SETTLED");
  assert.equal((await verifyReceipt({ receipt_hash: H("bad"), epoch_id: 8, intent: "WALLET_BALANCE_CHECK_GENERAL", amount_uusdc: 10000 })).status, "MISMATCH");
  assert.equal((await verifyReceipt({ receipt_hash: H("aa"), epoch_id: 9 })).status, "PENDING");
  // review 8: node-supplied receipt fields are validated before they are looked up or copied out
  const PN = "sk_live_POISONx.Jane.Poisonname:acme-unpaid.example|";
  for (const rc of [{ receipt_hash: PN, epoch_id: 8 }, { receipt_hash: "0x" + "ab".repeat(32), epoch_id: PN }, { receipt_hash: "0x" + "ab".repeat(32) + "/../x", epoch_id: 8 }]) {
    const v = await verifyReceipt(rc);
    assert.match(v.status, /INVALID|NO_EPOCH/); assert.doesNotMatch(JSON.stringify(v), /poison|\.\./i, JSON.stringify(v));
  }
});
