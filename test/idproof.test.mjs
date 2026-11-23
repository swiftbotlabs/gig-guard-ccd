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
