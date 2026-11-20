// Concordium accountability layer: offline tests (fake registry, fake facilitator, fake signing scheme).
// The real HTTP 402 flow of @x402/express and @x402/fetch runs end to end; only chain I/O is faked.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

process.env.GG_CCD_MAX_PER_CALL = "5000000";
process.env.GG_CCD_MAX_PER_DAY = "6000000";
const { buyCcd, makePayingFetch, payPolicy, CAIP2 } = await import("../src/ccd/rail.mjs");
const { buildSeller } = await import("../src/ccd/seller.mjs");
const { verifyAudit } = await import("../src/ccd/audit.mjs");
const { checkCounterparty } = await import("../src/ccd/registry.mjs");

const SELLER = "4n3P1UDZA2usiVTS95mteZRnMB7pizRb9LcsmqrQMstnCgcE9K";
const BUYER = "4SV3Q1ejRmi3DVNPaZGS8QRRNikquFeMpNXjnLnoNFkRYnL62R";
const GOOD = "MockVerifiedAgent11111";
// Agent Cards in the registry's shape; their SHA-256 is the on-chain hash the fake registry reports, and each
// seller serves its card, so the buyer can bind the badge to the endpoint it pays.
import crypto from "node:crypto";
const card = (badge, wallet) => JSON.stringify({ name: badge, capabilities: { extensions: [{ uri: "https://docs.concordium.com/a2a-extensions/concordium-badge/v1",
  params: { tokenAddress: `${CAIP2}/cis-2:${badge}`, owner: { account: `${CAIP2}:${wallet}` }, agentWallet: `${CAIP2}:${wallet}` } }] } });
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ggccd-")), "audit.jsonl");

// Fake registry: a verified seller, a revoked one, a tampered card, and one that is down.
const registry = {
  [GOOD]: { checks: { on_chain_agent_found: true, status_active: true, hash_matches_on_chain: true }, on_chain: { owner_account: SELLER, status: "Active", metadata_hash_hex: sha(card(GOOD, SELLER)) }, token_id: 7 },
  MockRevokedAgent22222: { checks: { on_chain_agent_found: true, status_active: false, hash_matches_on_chain: true }, on_chain: { owner_account: SELLER, status: "Revoked" }, token_id: 8 },
  MockTamperedCard33333: { checks: { on_chain_agent_found: true, status_active: true, hash_matches_on_chain: false }, on_chain: { owner_account: SELLER, status: "Active" }, token_id: 9 },
};
const fakeCall = async (name, args) => {
  if (args.id === "MockRegistryDown44444") throw new Error("HTTP 503");
  if (name === "check_badge") return registry[args.id] || { checks: { on_chain_agent_found: false } };
  if (name === "get_agent_wallet") return SELLER;
};
import { keyFor, fakeAccountInfo, fakeOwnerIdentity } from "../demo/fakekeys.mjs";
import { verifyAccountProof } from "../src/ccd/registry.mjs";
const verifyProof = (m, sig, a) => verifyAccountProof(m, sig, a, { getAccountInfo: fakeAccountInfo });
const check = (badge, o) => checkCounterparty(badge, { ownerIdentity: fakeOwnerIdentity, ...o, call: fakeCall, verifyProof });

// Fake signing scheme and facilitator: the payload is a stand-in for the sender-signed V1 transaction.
let settled = 0;
const scheme = { scheme: "exact", async createPaymentPayload(v, req) { return { x402Version: v, payload: { signedTransaction: { amount: req.amount, to: req.payTo }, sender: BUYER } }; } };
const facilitatorClient = {
  async verify(p, r) { return { isValid: p.payload.signedTransaction.to === r.payTo, payer: BUYER }; },
  async settle(p, r) { settled++; return { success: true, transaction: settled.toString(16).padStart(64, "a"), network: r.network, payer: BUYER }; },
  async getSupported() { return { kinds: [{ x402Version: 2, scheme: "exact", network: CAIP2, extra: { feePayer: SELLER } }], extensions: [], signers: {} }; },
};
const read = async () => ({ balance: 0 });

async function withSeller(opts, fn) {
  let origin = null;
  const app = buildSeller({ seller: { address: SELLER, signer: keyFor(SELLER).signer }, origin: () => origin, facilitatorClient, read, auditFile: tmp(), card: opts.badge ? card(opts.badge, SELLER) : null, ...opts });
  const srv = app.listen(0);
  await new Promise((r) => srv.once("listening", r));
  origin = `http://127.0.0.1:${srv.address().port}`;
  try { return await fn(`http://127.0.0.1:${srv.address().port}`); } finally { srv.close(); }
}
const buyer = (auditFile) => makePayingFetch({ account: { address: BUYER, signer: null }, scheme, check, auditFile });
const q = { address: "0x000000000000000000000000000000000000dEaD", chain: "ethereum", token: "USDT" };

test("ccd: a verified seller is paid, the tx is recorded and the audit chain holds", async () => {
  const auditFile = tmp();
  await withSeller({ badge: GOOD }, async (base) => {
    const r = await buyCcd(base + "/v1/balance", { body: q, purpose: "claim", auditFile, payingFetch: buyer(auditFile) });
    assert.equal(r.ok, true, JSON.stringify(r));
    assert.equal(r.body.balance, 0);
    assert.match(r.tx, /^[0-9a-f]{64}$/);
    assert.match(r.explorer, /ccdexplorer/);
  });
  const log = fs.readFileSync(auditFile, "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(log.at(-1).kind, "payment");
  assert.equal(log.at(-1).seller_badge, GOOD);
  assert.equal(log.at(-1).settled, true);
  assert.equal(verifyAudit(auditFile).ok, true);
});

for (const [badge, why] of [["MockRevokedAgent22222", /Revoked/], ["MockTamperedCard33333", /Agent Card/], ["NotRegisteredAgent5555", /not in the Agent Registry/], ["MockRegistryDown44444", /unreachable.*fail closed/], [undefined, /no valid Concordium badge/]]) {
  test(`ccd: refuses before signing when the seller is ${badge || "anonymous"}`, async () => {
    const auditFile = tmp();
    const before = settled;
    await withSeller({ badge }, async (base) => {
      const r = await buyCcd(base + "/v1/balance", { body: q, purpose: "claim", auditFile, payingFetch: buyer(auditFile) });
      assert.equal(r.ok, false);
      assert.equal(r.refused, true, JSON.stringify(r));
      assert.match(r.reason, why);
    });
    assert.equal(settled, before, "nothing settled");
    const log = fs.readFileSync(auditFile, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    assert.equal(log.at(-1).kind, "refusal");
  });
}

test("ccd: a payTo that isn't the seller's registered wallet is refused", async () => {
  const d = await payPolicy({ scheme: "exact", network: CAIP2, asset: "CCD", amount: "100000", payTo: BUYER, extra: { agentBadge: GOOD } }, { check, auditFile: tmp() });
  assert.equal(d.ok, false);
  assert.match(d.reason, /payTo is not this agent's registered wallet/);
});

test("ccd: per-call and daily caps are checked before signing", async () => {
  const over = await payPolicy({ scheme: "exact", network: CAIP2, asset: "CCD", amount: "5000001", payTo: SELLER, extra: { agentBadge: GOOD } }, { check, auditFile: tmp() });
  assert.match(over.reason, /per-call cap/);
  const auditFile = tmp();
  await withSeller({ badge: GOOD, price: "4000000" }, async (base) => {
    const a = await buyCcd(base + "/v1/balance", { body: q, auditFile, payingFetch: buyer(auditFile) });
    assert.equal(a.ok, true, JSON.stringify(a));
    const b = await buyCcd(base + "/v1/balance", { body: q, auditFile, payingFetch: buyer(auditFile) });
    assert.equal(b.refused, true);
    assert.match(b.reason, /daily cap/);
  });
});

test("ccd: editing or deleting an audit entry is detected", async () => {
  const auditFile = tmp();
  await withSeller({ badge: GOOD }, async (base) => {
    await buyCcd(base + "/v1/balance", { body: q, auditFile, payingFetch: buyer(auditFile) });
    await buyCcd(base + "/v1/balance", { body: q, auditFile, payingFetch: buyer(auditFile) });
  });
  const lines = fs.readFileSync(auditFile, "utf8").trim().split("\n");
  fs.writeFileSync(auditFile, [lines[0].replace(/"amount":"\d+"/, '"amount":"1"'), ...lines.slice(1)].join("\n") + "\n");
  assert.match(verifyAudit(auditFile).reason, /edited/);
  fs.writeFileSync(auditFile, lines.slice(1).join("\n") + "\n");
  assert.equal(verifyAudit(auditFile).ok, false);
});

test("ccd: the offline walkthrough runs with no accounts and shows 1 payment, 5 refusals (one for an owner with no verified identity) and a caught edit", async () => {
  const { execFileSync } = await import("node:child_process");
  const out = execFileSync(process.execPath, [new URL("../demo/offline.mjs", import.meta.url).pathname], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } }).replace(/\x1b\[[0-9;]*m/g, "");
  assert.match(out, /Payments settled: 1 of 6 attempts\. Refused before signing: 5/);
  assert.match(out, /no live identity credential from an accepted Concordium identity provider/);
  assert.match(out, /owner ID by Concordium testnet IP/);
  assert.match(out, /audit: OK, 8 entries/);
  assert.match(out, /audit: FAIL at entry #0: entry edited/);
});

test("ccd: the log is checked against an anchored head; appending is fine, rewriting the anchored part is not", async () => {
  const { record, verifyAnchor } = await import("../src/ccd/audit.mjs");
  const file = tmp();
  for (let i = 0; i < 3; i++) record("decision", { i }, { file });
  const v = verifyAudit(file);
  const anchor = `${v.entries}:${v.head}`;
  assert.equal(verifyAnchor(file, anchor).ok, true);
  record("decision", { i: 3 }, { file });                       // later entries may follow
  const after = verifyAnchor(file, anchor);
  assert.equal(after.ok, true);
  assert.equal(after.after_anchor, 1);
  const lines = fs.readFileSync(file, "utf8").trim().split("\n");
  fs.writeFileSync(file, lines.slice(0, 2).join("\n") + "\n");   // anchored entries removed
  assert.match(verifyAnchor(file, anchor).reason, /removed/);
  fs.writeFileSync(file, [lines[0].replace('"i":0', '"i":9'), ...lines.slice(1)].join("\n") + "\n");
  assert.match(verifyAnchor(file, anchor).reason, /inside the anchored part/);
  assert.equal(verifyAnchor(file, "garbage").ok, false);
});

// Live run 2 (11-19): the paid Concordium reading was bought and settled, but the claim decision reported no receipt,
// no cost and "paid balance check unavailable". The decision must name the paid call (tx, cost) and not deny it.
test("claim: a settled Concordium agent reading shows in the decision (receipt ccd:<tx>, cost_ccd) and is not reported as unavailable", async () => {
  const http = await import("node:http");
  const rpc = http.createServer((req, res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    const sel = JSON.parse(b).params[0]?.data?.slice(0, 10);
    res.writeHead(200, { "content-type": "application/json" }); res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x" + (sel === "0x313ce567" ? 6n : 0n).toString(16) })); }); });
  await new Promise((r) => rpc.listen(0, "127.0.0.1", r));
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "ggclaim-"));
  Object.assign(process.env, { GG_RPC_ETHEREUM: `http://127.0.0.1:${rpc.address().port}/rpc`, TELEGRAPH_NODE: "http://127.0.0.1:9", TELEGRAPH_PAYER_KEY: "0x" + "11".repeat(32), GG_LEDGER: path.join(ws, "l.jsonl"), GG_AUDIT: path.join(ws, "a.jsonl") });
  const g = await import("../src/guards.mjs");
  const auditFile = path.join(ws, "a.jsonl");
  let d;
  try {
    await withSeller({ badge: GOOD }, async (base) => {
      process.env.GG_CCD_SELLER_URL = base;
      d = await g.claimPayment({ wallet: "0x000000000000000000000000000000000000dEaD", chain: "ethereum", token: "USDT", client: "Acme", amountUsd: 400 },
        { ccd: { auditFile, payingFetch: buyer(auditFile) } });
    });
  } finally { delete process.env.GG_CCD_SELLER_URL; rpc.close(); }
  const paid = fs.readFileSync(auditFile, "utf8").trim().split("\n").map((l) => JSON.parse(l)).find((e) => e.kind === "payment");
  assert.ok(paid?.tx, "the payment was settled");
  assert.ok(d.receipts.includes(`ccd:${paid.tx}`), JSON.stringify(d.receipts));
  assert.equal(d.cost_ccd, 0.1);
  assert.ok(!d.uncertainty.some((u) => /decided on the free chain read alone/.test(u)), JSON.stringify(d.uncertainty));
  assert.ok(d.evidence.some((e) => e.intent === "CCD_AGENT_BALANCE" && e.tx === paid.tx));
});

// Delta review 6, items 3 and 4 (claim gate, Concordium seller): an unreadable seller balance is never evidence (no CLAIM on it, cost still
// counted), and a failed seller call puts only fixed text in the public uncertainty, the raw error in private notes.
test("claim: an unreadable seller balance is refused as evidence; a failed seller call shows fixed text only", async () => {
  const ws = fs.mkdtempSync(path.join(os.tmpdir(), "ggclaim2-"));
  Object.assign(process.env, { GG_NO_RPC: "1", TELEGRAPH_NODE: "http://127.0.0.1:9", TELEGRAPH_PAYER_KEY: "0x" + "11".repeat(32), GG_LEDGER: path.join(ws, "l.jsonl"), GG_AUDIT: path.join(ws, "a.jsonl") });
  const g = await import("../src/guards.mjs");
  const auditFile = path.join(ws, "a.jsonl");
  let a, b;   // GG_NO_RPC: no free chain read, so the seller's reading would be the only proof
  try {
    await withSeller({ badge: GOOD, read: async () => ({ balance: "lots" }) }, async (base) => {
      process.env.GG_CCD_SELLER_URL = base;
      a = await g.claimPayment({ wallet: "0x000000000000000000000000000000000000dEaD", chain: "ethereum", token: "USDT", client: "Acme", amountUsd: 400 },
        { ccd: { auditFile, payingFetch: buyer(auditFile) } });
    });
    process.env.GG_CCD_SELLER_URL = "http://127.0.0.1:9";
    const P = "POISONx sk_live_POISON Jane Poisonname";
    const failing = { fetch: async () => { throw new Error(P); }, last: { decision: null, origin: null, busy: false }, account: { address: BUYER } };
    b = await g.claimPayment({ wallet: "0x000000000000000000000000000000000000dEaD", chain: "tron", token: "USDT", client: "Acme", amountUsd: 400 }, { ccd: { auditFile, payingFetch: failing } });
  } finally { delete process.env.GG_CCD_SELLER_URL; delete process.env.GG_NO_RPC; }
  assert.equal(a.verdict, "PENDING", JSON.stringify([a.verdict, a.reasons, a.uncertainty]));
  assert.ok(a.uncertainty.includes("Concordium agent reading unreadable: not used"), JSON.stringify(a.uncertainty));
  assert.equal(a.cost_ccd, 0.1);
  assert.ok(b.uncertainty.includes("Concordium seller failed"), JSON.stringify(b.uncertainty));
  assert.doesNotMatch(JSON.stringify([b.reasons, b.uncertainty]), /poison/i);
  assert.match(JSON.stringify(b.notes), /POISON/);
});

// The human behind the badge: the owner's identity credential must come from a known identity provider and still be valid.
test("owner identity: a live credential from a known identity provider passes; unknown provider, expired, none or unreadable fail closed", async () => {
  const { checkOwnerIdentity } = await import("../src/ccd/registry.mjs");
  const { fakeIdentityProviders } = await import("../demo/fakekeys.mjs");
  const info = (cred) => async () => ({ accountCredentials: cred === null ? {} : { 0: { value: { type: "normal", contents: cred } } } });
  const now = new Date("2026-11-20T00:00:00Z");
  const run = (cred, o = {}) => checkOwnerIdentity(SELLER, { getAccountInfo: info(cred), identityProviders: fakeIdentityProviders, now, ...o });
  const good = await run({ ipIdentity: 0, policy: { validTo: "202711" } });
  assert.deepEqual([good.ok, good.idp, good.idpName, good.validTo], [true, 0, "Concordium testnet IP", "202711"]);
  assert.equal((await run({ ipIdentity: 0, policy: { validTo: "202611" } })).ok, true, "valid through the end of its month");
  for (const [why, cred, o] of [["unknown provider", { ipIdentity: 99, policy: { validTo: "202711" } }], ["expired", { ipIdentity: 0, policy: { validTo: "202610" } }],
    ["no credential", null], ["malformed month", { ipIdentity: 0, policy: { validTo: "2027-11" } }], ["not on the allow-list", { ipIdentity: 0, policy: { validTo: "202711" } }, { allow: [3] }],
    ["node down", { ipIdentity: 0, policy: { validTo: "202711" } }, { identityProviders: async () => { throw new Error("UNAVAILABLE"); } }]]) {
    const r = await run(cred, o);
    assert.equal(r.ok, false, why); assert.match(r.reason, /identity/, why);
  }
});
