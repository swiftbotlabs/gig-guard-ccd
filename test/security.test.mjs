// Security review 2026-11-19: one regression test (or more) per finding on the Concordium payment path.
// Each test plays a hostile seller against the real @x402/fetch buyer; chain I/O is faked.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

process.env.GG_CCD_MAX_PER_CALL = "5000000";
process.env.GG_CCD_MAX_PER_DAY = "6000000";
const { buyCcd, makePayingFetch, payPolicy, CAIP2 } = await import("../src/ccd/rail.mjs");
const { buildSeller } = await import("../src/ccd/seller.mjs");
const { checkCounterparty } = await import("../src/ccd/registry.mjs");

const SELLER = "4n3P1UDZA2usiVTS95mteZRnMB7pizRb9LcsmqrQMstnCgcE9K";
const BUYER = "4SV3Q1ejRmi3DVNPaZGS8QRRNikquFeMpNXjnLnoNFkRYnL62R";
const OTHER = "32MAVPXN9z4s6XmkXLy4vsNpaimLcEEs95Lfna7BjBbfQ4gn8p";
const GOOD = "MockVerifiedAgent11111", SECOND = "MockSecondAgent666666";
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ggsec-")), "audit.jsonl");

// An Agent Card in the registry's shape; its SHA-256 is what the fake registry reports as the on-chain hash.
const card = (badge, wallet) => JSON.stringify({ name: badge, capabilities: { extensions: [{ uri: "https://docs.concordium.com/a2a-extensions/concordium-badge/v1",
  params: { tokenAddress: `${CAIP2}/cis-2:${badge}`, owner: { account: `${CAIP2}:${wallet}` }, agentWallet: `${CAIP2}:${wallet}` } }] } });
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const CARDS = { [GOOD]: card(GOOD, SELLER), [SECOND]: card(SECOND, OTHER) };
const entry = (badge, owner) => ({ checks: { on_chain_agent_found: true, status_active: true, hash_matches_on_chain: true },
  on_chain: { owner_account: owner, status: "Active", metadata_hash_hex: sha(CARDS[badge]) }, token_id: 7 });
const registry = { [GOOD]: entry(GOOD, SELLER), [SECOND]: entry(SECOND, OTHER) };
const call = async (name, args) => name === "check_badge" ? registry[args.id] || { checks: { on_chain_agent_found: false } } : registry[GOOD] && args.token_id ? SELLER : null;
import { keyFor, fakeAccountInfo } from "../demo/fakekeys.mjs";
import { verifyAccountProof, proofMessage } from "../src/ccd/registry.mjs";
import { AccountAddress, signMessage } from "@concordium/web-sdk";
const verifyProof = (m, sig, a) => verifyAccountProof(m, sig, a, { getAccountInfo: fakeAccountInfo });
const check = (badge, o) => checkCounterparty(badge, { ...o, call, verifyProof });
const sign = (account, message, by = account) => signMessage(AccountAddress.fromBase58(account), message, keyFor(by).signer);

// Counts what the buyer actually signed, whatever happens after.
function signer() {
  const s = { total: 0n, count: 0 };
  s.scheme = { scheme: "exact", async createPaymentPayload(v, req) { s.total += BigInt(req.amount); s.count++; return { x402Version: v, payload: { signedTransaction: { amount: req.amount, to: req.payTo }, sender: BUYER } }; } };
  return s;
}
// A raw hostile seller: offers `accepts`, serves `cardBody` as its agent card, answers key-proof requests per `proof`
// ("own": signs with SELLER's key for its own origin, as the real seller would; "none": 404; "impostor": signs with a key
// it holds (OTHER's) for its own origin; "relay": hands back a proof the real seller signed for the real seller's origin),
// and answers paid requests per `mode`.
async function hostile({ accepts, cardBody, mode = "nohdr", delayMs = 0, proof = "own" }) {
  let origin = null;
  const srv = http.createServer(async (req, res) => {
    if (req.url.startsWith("/.well-known/agent-proof")) {
      const nonce = new URL(req.url, "http://x").searchParams.get("nonce");
      if (proof === "none") { res.writeHead(404); return res.end("{}"); }
      const at = proof === "relay" ? "https://ledger-check.example" : origin;
      const message = proofMessage({ badge: GOOD, origin: at, account: SELLER, nonce });
      const signature = await sign(SELLER, message, proof === "impostor" ? OTHER : SELLER);
      if (proof === "dupkeys") { signature["00"] = signature["0"] ?? signature[0]; }
      res.writeHead(200, { "content-type": "application/json" }); return res.end(JSON.stringify({ message, account: SELLER, signature }));
    }
    if (req.url === "/.well-known/agent-card.json") {
      if (!cardBody) { res.writeHead(404); return res.end("{}"); }
      res.writeHead(200, { "content-type": "application/json" }); return res.end(cardBody);
    }
    if (delayMs) await new Promise((r) => setTimeout(r, delayMs));
    if (!req.headers["payment-signature"] && !req.headers["x-payment"]) {
      const ch = { x402Version: 2, error: "Payment required", resource: { url: "x", description: "", mimeType: "application/json" }, accepts };
      res.writeHead(402, { "PAYMENT-REQUIRED": Buffer.from(JSON.stringify(ch)).toString("base64"), "content-type": "application/json" }); return res.end("{}");
    }
    if (mode === "drop") return req.socket.destroy();
    if (mode === "big") { res.writeHead(200, { "content-type": "application/json" }); return res.end('{"balance":123,"pad":"' + "x".repeat(100000) + '"}'); }
    res.writeHead(200, { "content-type": "application/json" }); res.end('{"balance":123}');
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  origin = `http://127.0.0.1:${srv.address().port}`;
  return { url: `http://127.0.0.1:${srv.address().port}/v1/balance`, close: () => srv.close() };
}
const offer = (o = {}) => ({ scheme: "exact", network: CAIP2, amount: "4000000", asset: "CCD", payTo: SELLER, maxTimeoutSeconds: 120, extra: { agentBadge: GOOD, feePayer: SELLER }, ...o });
const buy = (url, s, auditFile) => buyCcd(url, { body: {}, auditFile, payingFetch: makePayingFetch({ account: { address: BUYER }, scheme: s.scheme, check, auditFile }) });

// ---- finding 2: daily cap bypass ----
for (const mode of ["nohdr", "drop"]) {
  test(`cap: a seller that ${mode === "drop" ? "drops the connection" : "omits the settlement header"} after taking the signed payment can't push spend over the daily cap`, async () => {
    const h = await hostile({ accepts: [offer()], cardBody: CARDS[GOOD], mode });
    const s = signer(), auditFile = tmp();
    try { for (let i = 0; i < 4; i++) await buy(h.url, s, auditFile); } finally { h.close(); }
    assert.ok(s.total <= 6000000n, `signed ${s.total} microCCD against a daily cap of 6000000`);
    assert.equal(s.count, 1);
  });
}
test("cap: concurrent calls can't each pass the daily check before any of them is counted", async () => {
  const h = await hostile({ accepts: [offer()], cardBody: CARDS[GOOD], delayMs: 30 });
  const s = signer(), auditFile = tmp();
  try { await Promise.all([0, 1, 2].map(() => buyCcd(h.url, { body: {}, auditFile, payingFetch: makePayingFetch({ account: { address: BUYER }, scheme: s.scheme, check, auditFile }) }))); }
  finally { h.close(); }
  assert.ok(s.total <= 6000000n, `signed ${s.total} in parallel against a daily cap of 6000000`);
});
for (const amount of ["-1", "0", "1e3", "0x10", " 5", "5.5", "", "99999999999999999999999999999999999"]) {
  test(`cap: amount ${JSON.stringify(amount)} is refused before signing`, async () => {
    const d = await payPolicy(offer({ amount }), { check, auditFile: tmp(), origin: "http://127.0.0.1:1" }).catch((e) => ({ ok: false, reason: "threw " + e.message }));
    assert.equal(d.ok, false);
    assert.match(d.reason, /amount/);
  });
}

// ---- finding 3: badge not bound to the seller ----
test("badge: an endpoint that copies a verified agent's badge but doesn't serve its Agent Card is refused", async () => {
  const h = await hostile({ accepts: [offer()], cardBody: null });
  const s = signer();
  let r; try { r = await buy(h.url, s, tmp()); } finally { h.close(); }
  assert.equal(r.refused, true, JSON.stringify(r));
  assert.match(r.reason, /Agent Card/);
  assert.equal(s.count, 0);
});
test("badge: an endpoint serving another agent's card (valid on chain) is refused", async () => {
  const h = await hostile({ accepts: [offer()], cardBody: CARDS[SECOND] });
  const s = signer();
  let r; try { r = await buy(h.url, s, tmp()); } finally { h.close(); }
  assert.equal(r.refused, true, JSON.stringify(r));
  assert.equal(s.count, 0);
});
test("badge: payTo must be the badge's registered wallet; another verified agent's wallet is refused", async () => {
  const h = await hostile({ accepts: [offer({ payTo: OTHER })], cardBody: CARDS[GOOD] });
  const s = signer();
  let r; try { r = await buy(h.url, s, tmp()); } finally { h.close(); }
  assert.equal(r.refused, true, JSON.stringify(r));
  assert.match(r.reason, /payTo/);
  assert.equal(s.count, 0);
});
// Re-review 2, finding 1 (PoC): an impostor serves the exact public card bytes on its own origin and names the real wallet
// as payTo. Without the key it can't produce a proof for its origin, so nothing is signed.
for (const [what, proof] of [["serves no key proof", "none"], ["signs the proof with a key it holds", "impostor"], ["relays the real seller's proof (signed for the real origin)", "relay"]]) {
  test(`badge: an impostor serving the exact Agent Card bytes that ${what} is refused before signing`, async () => {
    const h = await hostile({ accepts: [offer()], cardBody: CARDS[GOOD], mode: "ok", proof });
    const s = signer();
    let r; try { r = await buy(h.url, s, tmp()); } finally { h.close(); }
    assert.equal(r.refused, true, JSON.stringify(r));
    assert.match(r.reason, /key proof/);
    assert.equal(s.count, 0);
  });
}
// Re-review 2, finding 5: an endpoint can't make us buffer a huge "card"; the read stops past 64 KB.
test("badge: an Agent Card over 64 KB is refused before signing", async () => {
  const h = await hostile({ accepts: [offer()], cardBody: " ".repeat(200000) + CARDS[GOOD] });
  const s = signer();
  let r; try { r = await buy(h.url, s, tmp()); } finally { h.close(); }
  assert.equal(r.refused, true, JSON.stringify(r));
  assert.match(r.reason, /serves no Agent Card/);
  assert.equal(s.count, 0);
});
// Re-review 2, finding 6: a refusal logs the badge the seller CLAIMED under its own name, never as a checked one.
test("badge: a refusal logs the seller's badge as claimed_badge, not seller_badge", async () => {
  const h = await hostile({ accepts: [offer()], cardBody: null });
  const s = signer(), auditFile = tmp();
  try { await buy(h.url, s, auditFile); } finally { h.close(); }
  const ref = fs.readFileSync(auditFile, "utf8").trim().split("\n").map((l) => JSON.parse(l)).find((e) => e.kind === "refusal");
  assert.equal(ref.claimed_badge, GOOD);
  assert.equal(ref.seller_badge, undefined);
});
// Re-review 3, follow-up 3: one paying fetch serves one paid call at a time (its origin binding is per call).
test("rail: a second concurrent call on the same paying fetch is refused, not bound to the first call's origin", async () => {
  const h = await hostile({ accepts: [offer()], cardBody: CARDS[GOOD], mode: "ok", delayMs: 300 });
  const s = signer(), auditFile = tmp();
  const pf = makePayingFetch({ account: { address: BUYER }, scheme: s.scheme, check, auditFile });
  let a, b;
  try { [a, b] = await Promise.all([buyCcd(h.url, { body: {}, auditFile, payingFetch: pf }), buyCcd(h.url, { body: {}, auditFile, payingFetch: pf })]); } finally { h.close(); }
  assert.equal([a, b].filter((r) => r.refused && /one at a time/.test(r.reason)).length, 1, JSON.stringify([a, b]));
  assert.ok(s.count <= 1);
});
// Re-review 3, follow-up 4: the paid call follows no redirect and reads at most 64 KB.
test("rail: a seller that redirects is not followed; one that answers more than 64 KB is not used", async () => {
  // the redirect target is live and answers 200: following it would come back ok, so only the no-redirect rule makes this fail
  const live = http.createServer((req, res) => { res.writeHead(200, { "content-type": "application/json" }); res.end('{"balance":999999}'); });
  await new Promise((r) => live.listen(0, "127.0.0.1", r));
  const red = http.createServer((req, res) => { res.writeHead(302, { location: `http://127.0.0.1:${live.address().port}/v1/balance` }); res.end(); });
  await new Promise((r) => red.listen(0, "127.0.0.1", r));
  const s1 = signer();
  let r1; try { r1 = await buy(`http://127.0.0.1:${red.address().port}/v1/balance`, s1, tmp()); } finally { red.close(); live.close(); }
  assert.equal(r1.ok, false, JSON.stringify(r1)); assert.notEqual(r1.body?.balance, 999999); assert.equal(s1.count, 0);
  const big = await hostile({ accepts: [offer()], cardBody: CARDS[GOOD], mode: "big" });
  const s2 = signer();
  let r2; try { r2 = await buy(big.url, s2, tmp()); } finally { big.close(); }
  assert.equal(r2.ok, false, JSON.stringify(r2).slice(0, 200)); assert.equal(r2.body, null); assert.match(r2.reason, /larger than 65536/);
});
// Re-review 3, follow-up 5: non-canonical signature indexes ("00" next to "0") can't inflate a threshold count.
test("badge: a key proof with non-canonical credential/key indexes is refused", async () => {
  const h = await hostile({ accepts: [offer()], cardBody: CARDS[GOOD], mode: "ok", proof: "dupkeys" });
  const s = signer();
  let r; try { r = await buy(h.url, s, tmp()); } finally { h.close(); }
  assert.equal(r.refused, true, JSON.stringify(r)); assert.match(r.reason, /malformed signature/); assert.equal(s.count, 0);
});
test("seller: the key-proof origin is normalised and the proof route is rate limited", async () => {
  let origin = null;
  const app = buildSeller({ seller: { address: SELLER, signer: keyFor(SELLER).signer }, origin: () => origin + "/some/path?x=1",
    facilitatorClient: { verify: async () => ({ isValid: true }), settle: async () => ({ success: true }), getSupported: async () => ({ kinds: [], extensions: [], signers: {} }) },
    badge: GOOD, auditFile: tmp(), card: CARDS[GOOD], rateLimit: { max: 2, windowMs: 60000 } });
  const srv = app.listen(0); await new Promise((r) => srv.once("listening", r));
  origin = `http://127.0.0.1:${srv.address().port}`;
  try {
    const n = "ef".repeat(16);
    const p = await (await fetch(`${origin}/.well-known/agent-proof?nonce=${n}`)).json();
    assert.equal(p.message, proofMessage({ badge: GOOD, origin, account: SELLER, nonce: n }));
    await fetch(`${origin}/.well-known/agent-proof?nonce=${n}`);
    assert.equal((await fetch(`${origin}/.well-known/agent-proof?nonce=${n}`)).status, 429);
  } finally { srv.close(); }
});
// Delta review 5, item 1 (PoC): case variants of a route must not get a fresh rate-limit bucket or reach any route at all.
test("seller: case and slash variants of the proof and paid routes are refused; the 3rd proof call is 429", async () => {
  await seller({ rateLimit: { max: 2, windowMs: 60000 } }, async (base) => {
    const n = "aa".repeat(16);
    assert.equal((await fetch(`${base}/.well-known/agent-proof?nonce=${n}`)).status, 200);
    assert.equal((await fetch(`${base}/.well-known/agent-proof?nonce=${n}`)).status, 200);
    for (const v of ["/.WELL-known/agent-proof", "/.well-known/Agent-Proof", "//.well-known/agent-proof", "/.well-known//agent-proof"]) {
      const r = await fetch(`${base}${v}?nonce=${n}`);
      assert.notEqual(r.status, 200, v); assert.equal((await r.text()).includes("signature"), false, v);
    }
    assert.equal((await fetch(`${base}/.well-known/agent-proof?nonce=${n}`)).status, 429);
    for (const v of ["/V1/balance", "/v1/Balance", "/v1//balance"]) assert.equal((await fetch(`${base}${v}`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status, 404, v);
  });
});
// Full public-text pass (delta review 6): every string a seller or the registry controls carries a marker; none may reach a refusal reason.
const PZ = "POISONx sk_live_POISON Jane Poisonname poison-host.example ";
test("poison: seller 402 fields, card/proof errors and registry text never reach the refusal reason", async () => {
  const reasons = [];
  for (const o of [{ scheme: PZ }, { network: PZ }, { asset: PZ }, { amount: PZ }, { amount: 7 }, { asset: "sk_live_POISONx" }, { network: "poison-host.example" }, { scheme: "POISONx" }]) reasons.push((await payPolicy(offer(o), { check, auditFile: tmp(), origin: "http://127.0.0.1:1" })).reason);
  // card endpoint answering an error page, proof endpoint answering a non-JSON body that quotes text
  const srv = http.createServer((req, res) => { if (req.url.startsWith("/.well-known/agent-card")) { res.writeHead(500); return res.end(PZ); } res.writeHead(200); res.end(PZ); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${srv.address().port}`;
  try {
    reasons.push(...(await checkCounterparty(GOOD, { call, payTo: SELLER, origin, verifyProof })).reasons);
    reasons.push(...(await checkCounterparty(GOOD, { call, payTo: SELLER, origin, verifyProof, fetchCard: async () => Buffer.from(CARDS[GOOD]) })).reasons);
    reasons.push(...(await checkCounterparty(GOOD, { call, payTo: SELLER, origin, fetchCard: async () => Buffer.from(CARDS[GOOD]), fetchProof: async () => ({ account: SELLER, signature: { 0: { 0: "a".repeat(128) } } }), verifyProof: async () => { throw new Error(PZ); } })).reasons);
  } finally { srv.close(); }
  const badCall = async (name) => { if (name === "check_badge") throw new Error(`registry check_badge: ${PZ}`); };
  reasons.push(...(await checkCounterparty(GOOD, { call: badCall, payTo: SELLER, origin })).reasons);
  const statusCall = async (name) => name === "check_badge" ? { checks: { on_chain_agent_found: true, status_active: false, hash_matches_on_chain: true }, on_chain: { status: PZ, owner_account: SELLER } } : SELLER;
  reasons.push(...(await checkCounterparty(GOOD, { call: statusCall, payTo: SELLER, origin })).reasons);
  // the audit log (whose anchored head is public) records a refusal with only validated fields
  const auditFile = tmp();
  const pf = makePayingFetch({ account: { address: BUYER }, scheme: signer().scheme, check, auditFile });
  const h = await hostile({ accepts: [offer({ asset: PZ, payTo: PZ, amount: PZ, extra: { agentBadge: PZ, feePayer: SELLER } })], cardBody: CARDS[GOOD] });
  try { await buyCcd(h.url, { body: {}, auditFile, payingFetch: pf }); } finally { h.close(); }
  assert.doesNotMatch(fs.readFileSync(auditFile, "utf8"), /poison/i);
  assert.ok(reasons.length >= 10, reasons.length);
  assert.doesNotMatch(JSON.stringify(reasons), /poison/i, JSON.stringify(reasons));
});
// Delta review 6, item 1 (PoC): encoded, case and slash variants of the paid route never reach x402 verify (exact raw-path allow-list).
test("seller: encoded/case/slash variants of /v1/balance are 404 before x402 verify runs; the exact path does reach verify", async () => {
  let verifies = 0;
  const fac = { verify: async () => { verifies++; return { isValid: false, invalidReason: "test" }; }, settle: async () => ({ success: false }),
    getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: CAIP2, extra: { feePayer: SELLER } }], extensions: [], signers: {} }) };
  await seller({ facilitatorClient: fac, rateLimit: { max: 1000, windowMs: 60000 } }, async (base) => {
    const ch = await fetch(`${base}/v1/balance`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    const req = JSON.parse(Buffer.from(ch.headers.get("payment-required"), "base64").toString()).accepts[0];
    const pay = Buffer.from(JSON.stringify({ x402Version: 2, accepted: req, payload: { signedTransaction: { amount: req.amount, to: req.payTo }, sender: BUYER } })).toString("base64");
    const post = (p) => fetch(`${base}${p}`, { method: "POST", headers: { "content-type": "application/json", "payment-signature": pay, "x-payment": pay }, body: "{}" });
    for (const v of ["/v1/b%61lance", "/v1/%62alance", "/%76%31/balance", "/v1/bala%6ece", "/v1/balance%2f", "/v1/balance/", "/V1/balance", "//v1/balance", "/v1//balance"]) {
      const r = await post(v); assert.equal(r.status, 404, v);
    }
    assert.equal(verifies, 0, "a variant reached x402 verify");
    await post("/v1/balance");
    assert.ok(verifies >= 1, "positive control: the exact path reaches verify");
  });
});
// Review 7: body/parse errors answer fixed text (no stack trace, no install path); wrong methods on known paths are 404 too.
test("seller: bad JSON, an oversized body and wrong methods get fixed errors, never a stack trace", async () => {
  await seller({}, async (base) => {
    const bad = await fetch(`${base}/v1/balance`, { method: "POST", headers: { "content-type": "application/json" }, body: "{not json" });
    const big = await fetch(`${base}/v1/balance`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ x: "y".repeat(8000) }) });
    const t1 = await bad.text(), t2 = await big.text();
    assert.equal(bad.status, 400, t1); assert.equal(big.status, 413, t2);
    for (const t of [t1, t2]) { assert.doesNotMatch(t, /node_modules|\bat \w+ \(|Error:|\/data\/|\/home\//, t); }
    assert.equal((await fetch(`${base}/v1/balance`)).status, 404);
    assert.equal((await fetch(`${base}/.well-known/agent-card.json`, { method: "POST" })).status, 404);
    assert.equal((await fetch(`${base}/.well-known/agent-proof?nonce=${"ab".repeat(16)}`, { method: "DELETE" })).status, 404);
  });
});
test("poison (no-space): a card fetch error and a registry status never reach the reasons", async () => {
  const PN = "sk_live_POISONx.Jane.Poisonname:acme-unpaid.example|";
  const r1 = await checkCounterparty(GOOD, { call, payTo: SELLER, origin: "http://127.0.0.1:1", fetchCard: async () => { throw new Error(`HTTP 500 ${PN}`); } });
  const st = async (name) => name === "check_badge" ? { checks: { on_chain_agent_found: true, status_active: false, hash_matches_on_chain: true }, on_chain: { status: "PoisonxStatus", owner_account: SELLER } } : SELLER;
  const r2 = await checkCounterparty(GOOD, { call: st, payTo: SELLER, origin: "http://127.0.0.1:1" });
  const r3 = await payPolicy(offer({ amount: "999999999999999" }), { check, auditFile: tmp(), origin: "http://127.0.0.1:1" });
  assert.doesNotMatch(JSON.stringify([r1.reasons, r2.reasons, r3.reason]), /poison|999999999/i, JSON.stringify([r1.reasons, r2.reasons, r3.reason]));
});
test("badge: a requirement without payTo is refused", async () => {
  const d = await payPolicy(offer({ payTo: undefined }), { check, auditFile: tmp(), origin: "http://127.0.0.1:1" });
  assert.equal(d.ok, false);
});
test("badge: the verified, card-serving seller is still paid, and the log names the badge that was checked", async () => {
  const h = await hostile({ accepts: [offer()], cardBody: CARDS[GOOD], mode: "ok" });
  const s = signer(), auditFile = tmp();
  let r; try { r = await buy(h.url, s, auditFile); } finally { h.close(); }
  assert.equal(s.count, 1, JSON.stringify(r));
  assert.equal(r.seller_badge, GOOD);
});

// ---- finding 4: asset and network unchecked ----
for (const [what, o] of [["another asset (a PLT)", { asset: "EURR" }], ["mainnet", { network: "ccd:9dd9ca4d19e9393877d2c44b70f89acb" }], ["another scheme", { scheme: "upto" }]]) {
  test(`asset: a requirement on ${what} is refused before signing`, async () => {
    const d = await payPolicy(offer(o), { check, auditFile: tmp(), origin: "http://127.0.0.1:1" });
    assert.equal(d.ok, false, JSON.stringify(d));
    assert.match(d.reason, /asset|network|scheme/);
  });
}

// ---- finding 9: seller hardening ----
async function seller(opts, fn) {
  let origin = null;
  const app = buildSeller({ seller: { address: SELLER, signer: keyFor(SELLER).signer }, origin: () => origin, facilitatorClient: { verify: async () => ({ isValid: true }), settle: async () => ({ success: true, transaction: "a".repeat(64) }), getSupported: async () => ({ kinds: [{ x402Version: 2, scheme: "exact", network: CAIP2, extra: { feePayer: SELLER } }], extensions: [], signers: {} }) },
    badge: GOOD, auditFile: tmp(), card: CARDS[GOOD], ...opts });
  const srv = app.listen(0); await new Promise((r) => srv.once("listening", r));
  origin = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(origin); } finally { srv.close(); }
}
test("seller: signs a key proof for its own origin only, checkable against its account keys; bad nonce 400", async () => {
  await seller({}, async (base) => {
    const nonce = "ab".repeat(16);
    const p = await (await fetch(`${base}/.well-known/agent-proof?nonce=${nonce}`)).json();
    assert.equal(p.message, proofMessage({ badge: GOOD, origin: base, account: SELLER, nonce }));
    assert.equal(await verifyProof(p.message, p.signature, SELLER), true);
    assert.equal(await verifyProof(proofMessage({ badge: GOOD, origin: "http://impostor.example", account: SELLER, nonce }), p.signature, SELLER), false);
    assert.equal((await fetch(`${base}/.well-known/agent-proof?nonce=xyz`)).status, 400);
  });
  await seller({ origin: null }, async (base) => assert.equal((await fetch(`${base}/.well-known/agent-proof?nonce=${"cd".repeat(16)}`)).status, 404));
});
test("seller: serves the configured Agent Card bytes exactly", async () => {
  await seller({}, async (base) => {
    const t = await (await fetch(base + "/.well-known/agent-card.json")).text();
    assert.equal(sha(t), sha(CARDS[GOOD]));
  });
});
test("seller: a failing read answers 502 without the internal error text, and bad chain/token are 400", async () => {
  const s = signer();
  const read = async () => { throw new Error("ECONNREFUSED 10.0.0.7:8545 secret-rpc-key"); };
  await seller({ read }, async (base) => {
    const pf = () => makePayingFetch({ account: { address: BUYER }, scheme: s.scheme, check, auditFile: tmp() });
    const r = await buyCcd(base + "/v1/balance", { body: { address: "0x000000000000000000000000000000000000dEaD", chain: "ethereum", token: "USDT" }, auditFile: tmp(), payingFetch: pf() });
    assert.equal(r.status, 502);
    assert.doesNotMatch(JSON.stringify(r.body), /ECONNREFUSED|secret-rpc-key/);
    for (const body of [{ address: "0x000000000000000000000000000000000000dEaD", chain: "narnia", token: "USDT" }, { address: "0x000000000000000000000000000000000000dEaD", chain: "ethereum", token: "<script>" }]) {
      const b = await buyCcd(base + "/v1/balance", { body, auditFile: tmp(), payingFetch: pf() });
      assert.equal(b.status, 400, JSON.stringify(b));
    }
  });
});
test("seller: requests over the rate limit get 429 before any payment is taken", async () => {
  await seller({ rateLimit: { max: 3, windowMs: 60000 } }, async (base) => {
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await fetch(base + "/v1/balance", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status);
    assert.deepEqual(codes, [402, 402, 402, 429, 429]);
  });
});
