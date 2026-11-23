// Identity attribute proof gate: offline. The SDK's ZK verification against a node is replaced by a stub that returns what
// verifyWithNode returns; everything we check ourselves (challenge, replay, statement strength, status, provider) is real.
import { test } from "node:test";
import assert from "node:assert/strict";
const { idProofGate, dobCutoff } = await import("../src/ccd/idproof.mjs");

const NOW = new Date("2026-11-23T12:00:00Z");
// A presentation in the JSON shape VerifiablePresentationV1.fromJSON reads (proof values are opaque to our checks).
const vpFor = (ch, { conn = ch.connectionId, resource = ch.resource, nonce = ch.nonce } = {}) => ({
  type: ["VerifiablePresentation", "ConcordiumVerifiablePresentationV1"],
  presentationContext: { type: "ConcordiumContextInformationV1",
    given: [{ label: "Nonce", context: nonce }, { label: "ConnectionID", context: conn }, { label: "ResourceID", context: resource }],
    requested: [{ label: "BlockHash", context: "ab".repeat(32) }] },
  verifiableCredential: [], proof: { created: NOW.toISOString(), proofValue: "00", type: "ConcordiumWeakLinkingProofV1" } });
// What the SDK reports after checking the proofs: the request that was proven, and each credential's status.
const proven = ({ upper = dobCutoff(18, NOW), idp = 0, status = 0, type = "AttributeInRange", tag = "dob" } = {}) => async () => ({ type: "success", result: {
  credentialsStatus: [status],
  request: { subjectClaims: [{ type: ["ConcordiumSubjectClaimsV1", "ConcordiumIdBasedSubjectClaims"], issuer: `did:ccd:testnet:idp:${idp}`,
    statement: [{ type, attributeTag: tag, lower: "18000101", upper }] }] } } });
const gate = (o = {}) => idProofGate({ now: () => NOW, allow: [], ...o });

test("dobCutoff: 18 on 2026-11-23 means born on or before 2008-11-23", () => {
  assert.equal(dobCutoff(18, NOW), "20081123");
});
test("a valid proof of age >= 18 for our challenge is accepted, once", async () => {
  const g = gate({ verifyWithNode: proven() });
  const ch = g.challenge("order-42");
  assert.equal(ch.claims[0].statements[0].attributeTag, "dob");
  const r = await g.check(vpFor(ch), "order-42");
  assert.deepEqual([r.ok, r.idp, r.proven], [true, 0, ["age >= 18"]]);
  const again = await g.check(vpFor(ch), "order-42");
  assert.equal(again.ok, false); assert.match(again.reason, /replay/);
});
test("refused: unknown nonce, another connection, another resource, expired challenge", async () => {
  const g = gate({ verifyWithNode: proven() });
  assert.match((await g.check(vpFor(g.challenge("a"), { nonce: "00".repeat(32) }))).reason, /nonce unknown/);
  assert.match((await g.check(vpFor(g.challenge("a"), { conn: "b" }))).reason, /another connection/);
  assert.match((await g.check(vpFor(g.challenge("a")), "b")).reason, /another connection/);
  assert.match((await g.check(vpFor(g.challenge("a"), { resource: "other" }))).reason, /another resource/);
  let t = NOW; const g2 = idProofGate({ now: () => t, allow: [], verifyWithNode: proven() }); const ch = g2.challenge("a");
  t = new Date(NOW.getTime() + 11 * 60000);
  assert.match((await g2.check(vpFor(ch))).reason, /expired/);
});
test("refused: the proof is weaker than asked (born after the cutoff), or proves another attribute", async () => {
  let g = gate({ verifyWithNode: proven({ upper: "20091231" }) });
  assert.match((await g.check(vpFor(g.challenge("a")))).reason, /at least 18/);
  g = gate({ verifyWithNode: proven({ tag: "nationality", type: "AttributeInSet" }) });
  assert.match((await g.check(vpFor(g.challenge("a")))).reason, /at least 18/);
});
test("refused: SDK says failed, SDK throws, credential revoked, provider not accepted, garbage input (fail closed)", async () => {
  let g = gate({ verifyWithNode: async () => ({ type: "failed", error: new Error("invalid proof") }) });
  assert.match((await g.check(vpFor(g.challenge("a")))).reason, /verification failed: invalid proof/);
  g = gate({ verifyWithNode: async () => { throw new Error("node down"); } });
  assert.match((await g.check(vpFor(g.challenge("a")))).reason, /fail closed/);
  g = gate({ verifyWithNode: proven({ status: 1 }) });
  assert.match((await g.check(vpFor(g.challenge("a")))).reason, /not active/);
  g = idProofGate({ now: () => NOW, allow: [1, 2, 3], verifyWithNode: proven({ idp: 0 }) });
  assert.match((await g.check(vpFor(g.challenge("a")))).reason, /provider not accepted/);
  assert.equal((await g.check("{not json")).ok, false);
  assert.equal((await g.check({ x: "y".repeat(70000) })).ok, false);
  assert.throws(() => g.challenge("bad id with spaces"));
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
  const g = idProofGate({ now: () => new Date(), allow: [], verifyWithNode: proven({ upper: dobCutoff(18, new Date()) }), resource: "ledger-check/balance" });
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
  const g = idProofGate({ now: () => new Date(), allow: [], verifyWithNode: proven({ upper: dobCutoff(18, new Date()) }), resource: "ledger-check/balance" });
  await withIdSeller(g, async (base) => {
    const other = await (await fetch(`${base}/v1/id-challenge?account=${SELLER}`)).json();
    const before = settled;
    assert.equal((await pay(base, { "X-ID-Presentation": b64(vpFor(other)) })).ok, false); assert.equal(settled, before);
    assert.equal((await fetch(`${base}/v1/id-challenge?account=nope`)).status, 400);
  });
  await withIdSeller(null, async (base) => assert.equal((await fetch(`${base}/v1/id-challenge?account=${BUYER}`)).status, 404));
});
