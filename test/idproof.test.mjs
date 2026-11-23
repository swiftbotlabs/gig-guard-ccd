// Identity attribute proof gate: offline. The SDK's ZK verification against a node is replaced by a stub that returns what
// verifyWithNode returns, and the credential -> account lookup by a stub; everything we check ourselves (challenge, replay, account
// binding, statement strength, status, provider) is real.
import { test } from "node:test";
import assert from "node:assert/strict";
const { idProofGate, dobCutoff, accountKey, PER_ACCOUNT_OPEN } = await import("../src/ccd/idproof.mjs");

const NOW = new Date("2026-11-23T12:00:00Z");
const ACCT = "4SV3Q1ejRmi3DVNPaZGS8QRRNikquFeMpNXjnLnoNFkRYnL62R", OTHER = "4n3P1UDZA2usiVTS95mteZRnMB7pizRb9LcsmqrQMstnCgcE9K";
const K = accountKey(ACCT), CRED = "a1".repeat(48);
// A presentation in the JSON shape VerifiablePresentationV1.fromJSON reads (proof values are opaque to our checks).
const vpFor = (ch, { conn = ch.connectionId, resource = ch.resource, nonce = ch.nonce } = {}) => ({
  type: ["VerifiablePresentation", "ConcordiumVerifiablePresentationV1"],
  presentationContext: { type: "ConcordiumContextInformationV1",
    given: [{ label: "Nonce", context: nonce }, { label: "ConnectionID", context: conn }, { label: "ResourceID", context: resource }],
    requested: [{ label: "BlockHash", context: "ab".repeat(32) }] },
  verifiableCredential: [], proof: { created: NOW.toISOString(), proofValue: "00", type: "ConcordiumWeakLinkingProofV1" } });
// What the SDK reports after checking the proofs: the request that was proven, and each credential's status.
// Default: exactly the statement our own challenge asks for (the SDK's exclusive bound, "20081124" on 2026-11-23).
const proven = ({ upper = "20081124", idp = 0, status = 0, type = "AttributeInRange", tag = "dob", kind = "ConcordiumAccountBasedSubjectClaims", id = `did:ccd:testnet:cred:${CRED}` } = {}) => async () => ({ type: "success", result: {
  credentialsStatus: [status],
  request: { subjectClaims: [{ type: ["ConcordiumSubjectClaimsV1", kind], id, issuer: `did:ccd:testnet:idp:${idp}`,
    statement: [{ type, attributeTag: tag, lower: "18000101", upper }] }] } } });
const gate = (o = {}) => idProofGate({ now: () => NOW, allow: [], accountOf: async () => ACCT, ...o });

test("dobCutoff: 18 on 2026-11-23 means born on or before 2008-11-23", () => {
  assert.equal(dobCutoff(18, NOW), "20081123");
});
test("a valid account-based proof of age >= 18, with the exact statement our challenge asks for, is accepted once", async () => {
  const g0 = gate();
  const asked = g0.challenge(K).claims[0].statements[0];
  assert.equal(asked.attributeTag, "dob");
  const g = gate({ verifyWithNode: proven({ upper: asked.upper }) });
  const ch = g.challenge(K);
  const r = await g.check(vpFor(ch), K);
  assert.deepEqual([r.ok, r.idp, r.proven], [true, 0, ["age >= 18"]], r.reason);
  const again = await g.check(vpFor(ch), K);
  assert.equal(again.ok, false); assert.match(again.reason, /replay/);
});
test("refused: unknown nonce, another connection, another resource, expired challenge", async () => {
  const g = gate({ verifyWithNode: proven() });
  assert.match((await g.check(vpFor(g.challenge(K), { nonce: "00".repeat(32) }))).reason, /nonce unknown/);
  assert.match((await g.check(vpFor(g.challenge(K), { conn: "b" }))).reason, /another connection/);
  assert.match((await g.check(vpFor(g.challenge(K)), "b")).reason, /another connection/);
  assert.match((await g.check(vpFor(g.challenge(K), { resource: "other" }))).reason, /another resource/);
  let t = NOW; const g2 = idProofGate({ now: () => t, allow: [], accountOf: async () => ACCT, verifyWithNode: proven() }); const ch = g2.challenge(K);
  t = new Date(NOW.getTime() + 11 * 60000);
  assert.match((await g2.check(vpFor(ch))).reason, /expired/);
});
test("refused: proof for hire (identity-based, or made by another account's credential), malformed credential id, unreadable account", async () => {
  let g = gate({ verifyWithNode: proven({ kind: "ConcordiumIdBasedSubjectClaims" }) });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /account-based/);
  g = gate({ verifyWithNode: proven(), accountOf: async () => OTHER });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /different account/);
  g = gate({ verifyWithNode: proven({ id: "did:ccd:testnet:cred:zz" }) });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /malformed/);
  g = gate({ verifyWithNode: proven(), accountOf: async () => { throw new Error("node down"); } });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /fail closed/);
});
test("refused: the proof is weaker than asked (born after the cutoff), or proves another attribute", async () => {
  // one day weaker than what the challenge asks (the SDK dates its bound on the machine's local clock, so derive it from the ask)
  const asked = gate().challenge(K).claims[0].statements[0].upper;
  const d = new Date(Date.UTC(+asked.slice(0, 4), +asked.slice(4, 6) - 1, +asked.slice(6, 8) + 1)).toISOString().slice(0, 10).replace(/-/g, "");
  let g = gate({ verifyWithNode: proven({ upper: d }) });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /at least 18/);
  g = gate({ verifyWithNode: proven({ tag: "nationality", type: "AttributeInSet" }) });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /at least 18/);
});
test("refused: SDK says failed, SDK throws, credential outside its validity window, provider not accepted, garbage input (fail closed)", async () => {
  let g = gate({ verifyWithNode: async () => ({ type: "failed", error: new Error("invalid proof") }) });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /verification failed: invalid proof/);
  g = gate({ verifyWithNode: async () => { throw new Error("node down"); } });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /fail closed/);
  g = gate({ verifyWithNode: proven({ status: 2 }) });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /not active/);
  g = gate({ allow: [1, 2, 3], verifyWithNode: proven({ idp: 0 }) });
  assert.match((await g.check(vpFor(g.challenge(K)))).reason, /provider not accepted/);
  assert.equal((await g.check("{not json")).ok, false);
  assert.equal((await g.check({ x: "y".repeat(70000) })).ok, false);
  assert.throws(() => g.challenge("bad id with spaces"));
});
test("a flood of challenges for other accounts can't evict a buyer's open challenge; each account keeps at most a few open", async () => {
  const g = gate({ verifyWithNode: proven(), max: 50 });
  const ch = g.challenge(K);
  for (let i = 0; i < 49; i++) g.challenge(`flood${i}`);
  assert.throws(() => g.challenge("flood-more"), /too many open/);
  assert.equal((await g.check(vpFor(ch), K)).ok, true, "the buyer's challenge survived the flood");
  const g2 = gate({ verifyWithNode: proven() });
  const first = g2.challenge(K); for (let i = 0; i < PER_ACCOUNT_OPEN; i++) g2.challenge(K);
  assert.match((await g2.check(vpFor(first))).reason, /nonce unknown/);
  assert.equal(g2.pending(), PER_ACCOUNT_OPEN);
});

// Seller wiring: Ledger Check with GG_CCD_SELLER_ID_PROOF. Same fake facilitator and paying fetch as test/ccd.test.mjs.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
const { buildSeller } = await import("../src/ccd/seller.mjs");
const { buyCcd, makePayingFetch, CAIP2 } = await import("../src/ccd/rail.mjs");
const SELLER = "4n3P1UDZA2usiVTS95mteZRnMB7pizRb9LcsmqrQMstnCgcE9K", BUYER = "4SV3Q1ejRmi3DVNPaZGS8QRRNikquFeMpNXjnLnoNFkRYnL62R";
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ggccd-id-")), "audit.jsonl");
let settled = 0;
const scheme = { scheme: "exact", async createPaymentPayload(v, req) { return { x402Version: v, payload: { signedTransaction: { amount: req.amount, to: req.payTo, header: { sender: BUYER } }, sender: BUYER } }; } };
const facilitatorClient = {
  async verify(p, r) { return { isValid: p.payload.signedTransaction.to === r.payTo, payer: BUYER }; },
  async settle(p, r) { settled++; return { success: true, transaction: settled.toString(16).padStart(64, "a"), network: r.network, payer: BUYER }; },
  async getSupported() { return { kinds: [{ x402Version: 2, scheme: "exact", network: CAIP2, extra: { feePayer: SELLER } }], extensions: [], signers: {} }; },
};
const okCheck = async () => ({ ok: true, counterparty: { badge: "MockVerifiedAgent11111", owner: SELLER } });
async function withIdSeller(idProof, fn) {
  const app = buildSeller({ seller: { address: SELLER, signer: null }, origin: null, facilitatorClient, read: async () => ({ balance: 0 }), auditFile: tmp(), card: null, badge: "MockVerifiedAgent11111", idProof });
  const srv = app.listen(0, "127.0.0.1"); await new Promise((r) => srv.once("listening", r));
  try { return await fn(`http://127.0.0.1:${srv.address().port}`); } finally { srv.close(); }
}
const q = { address: "0x000000000000000000000000000000000000dEaD", chain: "ethereum", token: "USDT" };
const pay = (base, headers) => buyCcd(base + "/v1/balance", { body: q, purpose: "claim", auditFile: tmp(), headers,
  payingFetch: makePayingFetch({ account: { address: BUYER, signer: null }, scheme, check: okCheck, auditFile: tmp() }) });
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64");

test("seller: a buyer with a valid proof for its own account is served and charged; without one, refused and NOT charged", async () => {
  const g = idProofGate({ now: () => new Date(), allow: [], accountOf: async () => BUYER, verifyWithNode: proven({ upper: dobCutoff(18, new Date()) }), resource: "ledger-check/balance" });
  await withIdSeller(g, async (base) => {
    const ch = await (await fetch(`${base}/v1/id-challenge?account=${BUYER}`)).json();
    assert.equal(ch.minAge, 18);
    let before = settled;
    const none = await pay(base, {});
    assert.equal(none.ok, false); assert.equal(settled, before, "charged without a proof");
    before = settled;
    const r = await pay(base, { "X-ID-Presentation": b64(vpFor(ch)) });
    assert.equal(r.ok, true, JSON.stringify(r)); assert.equal(settled, before + 1);
    before = settled;
    const replay = await pay(base, { "X-ID-Presentation": b64(vpFor(ch)) });
    assert.equal(replay.ok, false); assert.equal(settled, before, "a replayed proof was charged");
  });
});
test("seller: a proof made for another account is refused (not charged); bad account on the challenge is a 400; gate off -> 404", async () => {
  const g = idProofGate({ now: () => new Date(), allow: [], accountOf: async () => BUYER, verifyWithNode: proven({ upper: dobCutoff(18, new Date()) }), resource: "ledger-check/balance" });
  await withIdSeller(g, async (base) => {
    const other = await (await fetch(`${base}/v1/id-challenge?account=${SELLER}`)).json();
    const before = settled;
    assert.equal((await pay(base, { "X-ID-Presentation": b64(vpFor(other)) })).ok, false); assert.equal(settled, before);
    assert.equal((await fetch(`${base}/v1/id-challenge?account=nope`)).status, 400);
  });
  await withIdSeller(null, async (base) => assert.equal((await fetch(`${base}/v1/id-challenge?account=${BUYER}`)).status, 404));
});
test("seller: a bad request body never consumes the buyer's proof; GG_CCD_SELLER_ID_PROOF=1 without GG_CCD_IDP_ALLOW refuses to start", async () => {
  const g = idProofGate({ now: () => new Date(), allow: [], accountOf: async () => BUYER, verifyWithNode: proven({ upper: dobCutoff(18, new Date()) }), resource: "ledger-check/balance" });
  await withIdSeller(g, async (base) => {
    const ch = await (await fetch(`${base}/v1/id-challenge?account=${BUYER}`)).json();
    const h = { "X-ID-Presentation": b64(vpFor(ch)) };
    const bad = await buyCcd(base + "/v1/balance", { body: { address: "nope" }, purpose: "claim", auditFile: tmp(), headers: h,
      payingFetch: makePayingFetch({ account: { address: BUYER, signer: null }, scheme, check: okCheck, auditFile: tmp() }) });
    assert.equal(bad.ok, false);
    assert.equal((await pay(base, h)).ok, true, "the proof was consumed by a request that failed on its body");
  });
  process.env.GG_CCD_SELLER_ID_PROOF = "1"; const prev = process.env.GG_CCD_IDP_ALLOW; delete process.env.GG_CCD_IDP_ALLOW;
  try { assert.throws(() => buildSeller({ seller: { address: SELLER, signer: null }, facilitatorClient, read: async () => ({ balance: 0 }), auditFile: tmp(), badge: "MockVerifiedAgent11111" }), /GG_CCD_IDP_ALLOW/); }
  finally { delete process.env.GG_CCD_SELLER_ID_PROOF; if (prev !== undefined) process.env.GG_CCD_IDP_ALLOW = prev; }
});
