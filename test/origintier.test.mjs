// Origin-bound trust tier (opt-in per origin): an outside seller that serves no /.well-known/agent-proof may be paid, at low
// caps, when the operator pinned its origin to its badge and every other registry check holds. Offline; chain I/O is faked.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";

process.env.GG_CCD_MAX_PER_CALL = "5000000";
process.env.GG_CCD_MAX_PER_DAY = "50000000";
delete process.env.GG_CCD_ORIGIN_TIER; delete process.env.GG_CCD_ORIGIN_TIER_MAX_PER_CALL; delete process.env.GG_CCD_ORIGIN_TIER_MAX_PER_DAY;
const { buyCcd, makePayingFetch, payPolicy, parseOriginTier, ORIGIN_PINS, TIER_MAX_PER_CALL, TIER_MAX_PER_DAY, CAIP2 } = await import("../src/ccd/rail.mjs");
const { buildSeller } = await import("../src/ccd/seller.mjs");
const { checkCounterparty } = await import("../src/ccd/registry.mjs");
import { keyFor, fakeOwnerIdentity } from "../demo/fakekeys.mjs";

const WALLET = "4n3P1UDZA2usiVTS95mteZRnMB7pizRb9LcsmqrQMstnCgcE9K";   // the outside seller's registered agent wallet
const OWNER2 = "32MAVPXN9z4s6XmkXLy4vsNpaimLcEEs95Lfna7BjBbfQ4gn8p";   // an owner account that is not the agent wallet
const BUYER = "4SV3Q1ejRmi3DVNPaZGS8QRRNikquFeMpNXjnLnoNFkRYnL62R";
const BADGE = "MockPinnedAgent99xyz7";
const ORIGIN = "https://outside-seller.example";
const card = (wallet = WALLET, owner = wallet) => JSON.stringify({ name: "Outside", capabilities: { extensions: [{ uri: "https://docs.concordium.com/a2a-extensions/concordium-badge/v1",
  params: { tokenAddress: `${CAIP2}/cis-2:${BADGE}`, owner: { account: `${CAIP2}:${owner}` }, agentWallet: `${CAIP2}:${wallet}` } }] } });
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ggtier-")), "audit.jsonl");
const log = (f) => fs.readFileSync(f, "utf8").trim().split("\n").map((l) => JSON.parse(l));

// A registry entry as check_badge returns it; `over` replaces fields to play a tampered or changed entry.
const entry = ({ origin = ORIGIN, cardBody = card(), owner = WALLET, hashOk = true, hash } = {}) => ({
  checks: { on_chain_agent_found: true, status_active: true, hash_matches_on_chain: hashOk },
  on_chain: { owner_account: owner, status: "Active", agent_uri: `${origin}/.well-known/agent-card.json`, metadata_hash_hex: hash ?? sha(cardBody) }, token_id: 990 });
const fakeCall = (e, wallet = WALLET) => async (name) => name === "check_badge" ? e : { agent_wallet: wallet };
const no404 = async () => { throw Object.assign(new Error("HTTP 404"), { status: 404 }); };
const checkWith = ({ e = entry(), wallet = WALLET, cardBody = card(), fetchProof = no404 } = {}) => (badge, o) =>
  checkCounterparty(badge, { ...o, call: fakeCall(e, wallet), fetchCard: async () => Buffer.from(cardBody), fetchProof, ownerIdentity: fakeOwnerIdentity, verifyProof: async () => false });
const PINS = new Map([[ORIGIN, BADGE]]);
const offer = (amount = "500000", payTo = WALLET, extra = {}) => ({ scheme: "exact", network: CAIP2, asset: "CCD", amount, payTo, extra });

test("origin tier: off by default (no pins), so a seller with no key proof is refused as before", async () => {
  assert.equal(ORIGIN_PINS.size, 0);
  const d = await payPolicy(offer("500000", WALLET, { agentBadge: BADGE }), { check: checkWith(), auditFile: tmp(), origin: ORIGIN });
  assert.equal(d.ok, false);
  assert.match(d.reason, /gives no key proof \(HTTP 404\)/);
});

test("origin tier: a pinned same-origin seller, payTo = its registered agent wallet, under the cap, is allowed and tagged origin-bound", async () => {
  const d = await payPolicy(offer(), { check: checkWith(), auditFile: tmp(), origin: ORIGIN, originPins: PINS });   // offer names no badge: the pin supplies it
  assert.equal(d.ok, true, d.reason);
  assert.equal(d.counterparty.tier, "origin-bound");
  assert.equal(d.counterparty.endpointBound, false);
  assert.equal(d.counterparty.originBound, true);
});

test("origin tier: over its per-call cap is refused (the general cap would allow it)", async () => {
  assert.equal(TIER_MAX_PER_CALL, 1000000n);
  const d = await payPolicy(offer("1000001"), { check: checkWith(), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
  assert.equal(d.ok, false);
  assert.match(d.reason, /origin-bound tier \(no key proof\): amount is over its per-call cap 1000000/);
});

test("origin tier: payTo that is not the registered agent wallet is refused, even when it is the registered owner", async () => {
  // payTo = owner account, the agent wallet is another account: the key-proof tier would accept the owner, this tier does not
  const cardBody = card(WALLET, OWNER2);
  const d1 = await payPolicy(offer("500000", OWNER2), { check: checkWith({ e: entry({ cardBody, owner: OWNER2 }), cardBody }), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
  assert.equal(d1.ok, false);
  assert.match(d1.reason, /origin-bound tier refused: payTo is not the registered agent wallet/);
  // payTo = some other account altogether
  const d2 = await payPolicy(offer("500000", BUYER), { check: checkWith(), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
  assert.equal(d2.ok, false);
  assert.match(d2.reason, /payTo is not this agent's registered wallet/);
});

test("origin tier: a tampered registry entry is refused (hash flag off, on-chain hash of another card, agent_uri on another origin)", async () => {
  const run = (e) => payPolicy(offer(), { check: checkWith({ e }), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
  const a = await run(entry({ hashOk: false }));
  assert.equal(a.ok, false); assert.match(a.reason, /does not match its on-chain hash/);
  const b = await run(entry({ hash: sha(card() + " ") }));
  assert.equal(b.ok, false); assert.match(b.reason, /served by the seller endpoint does not match the on-chain hash/);
  const c = await run(entry({ origin: "https://elsewhere.example" }));
  assert.equal(c.ok, false); assert.match(c.reason, /registered agent_uri is not on the origin being paid/);
  // registry changed its wallet: payTo no longer matches
  const d = await payPolicy(offer(), { check: checkWith({ wallet: OWNER2 }), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
  assert.equal(d.ok, false);
});

test("origin tier: a proof that is served but wrong, or an unreachable proof endpoint, never falls back to the tier", async () => {
  const bad = async () => ({ account: WALLET, signature: { 0: { 0: "a".repeat(128) } } });
  const d1 = await payPolicy(offer(), { check: checkWith({ fetchProof: bad }), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
  assert.equal(d1.ok, false); assert.match(d1.reason, /not signed by the payTo account/);
  const d2 = await payPolicy(offer(), { check: checkWith({ fetchProof: async () => { throw Object.assign(new Error("HTTP 500"), { status: 500 }); } }), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
  assert.equal(d2.ok, false); assert.match(d2.reason, /gives no key proof \(HTTP 500\)/);
  // a proof served with 200 whose unparsable body reads "HTTP 404" (the parse error quotes it) is not "no proof served"
  const { fetchEndpointProof } = await import("../src/ccd/registry.mjs");
  const http = await import("node:http");
  const srv = http.createServer((q, r) => { r.writeHead(200); r.end("HTTP 404"); }).listen(0); await new Promise((r) => srv.once("listening", r));
  try {
    const d3 = await payPolicy(offer(), { check: checkWith({ fetchProof: fetchEndpointProof.bind(null, `http://127.0.0.1:${srv.address().port}`) }), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
    assert.equal(d3.ok, false); assert.match(d3.reason, /gives no key proof/);
  } finally { srv.close(); }
});

test("origin tier: an offer naming another badge than the pinned one is refused; another origin is not pinned", async () => {
  const d1 = await payPolicy(offer("500000", WALLET, { agentBadge: "SomeQtherBadge1234567" }), { check: checkWith(), auditFile: tmp(), origin: ORIGIN, originPins: PINS });
  assert.equal(d1.ok, false); assert.match(d1.reason, /another badge than the one pinned/);
  const d2 = await payPolicy(offer("500000", WALLET, { agentBadge: BADGE }), { check: checkWith({ e: entry({ origin: "https://copy.example" }) }), auditFile: tmp(), origin: "https://copy.example", originPins: PINS });
  assert.equal(d2.ok, false); assert.match(d2.reason, /gives no key proof/);
});

test("origin tier: pins must be https origins with a well-formed badge", () => {
  assert.equal(parseOriginTier(`${ORIGIN}=${BADGE}`).get(ORIGIN), BADGE);
  assert.throws(() => parseOriginTier(`http://outside-seller.example=${BADGE}`), /https origin/);
  assert.throws(() => parseOriginTier(`${ORIGIN}/x402/review=${BADGE}`), /https origin/);
  assert.throws(() => parseOriginTier(`${ORIGIN}=not a badge`), /bad badge/);
  assert.throws(() => parseOriginTier(`${ORIGIN}=${BADGE},${ORIGIN}=SomeQtherBadge1234567`), /pinned twice/);
});

// End to end over real x402 (@x402/express seller, @x402/fetch buyer): a seller that serves no key proof (origin unset -> 404).
let settled = 0;
const scheme = { scheme: "exact", async createPaymentPayload(v, req) { return { x402Version: v, payload: { signedTransaction: { amount: req.amount, to: req.payTo, header: { sender: BUYER } }, sender: BUYER } }; } };
const facilitatorClient = {
  async verify(p, r) { return { isValid: p.payload.signedTransaction.to === r.payTo, payer: BUYER }; },
  async settle(p, r) { settled++; return { success: true, transaction: settled.toString(16).padStart(64, "b"), network: r.network, payer: BUYER }; },
  async getSupported() { return { kinds: [{ x402Version: 2, scheme: "exact", network: CAIP2, extra: { feePayer: WALLET } }], extensions: [], signers: {} }; },
};
test("origin tier: end to end, 0.5 CCD buys are paid up to the tier's daily cap (2 CCD), then refused; every decision logs trust_tier", async () => {
  assert.equal(TIER_MAX_PER_DAY, 2000000n);
  const auditFile = tmp();
  const app = buildSeller({ seller: { address: WALLET, signer: keyFor(WALLET).signer }, origin: null, facilitatorClient, read: async () => ({ balance: 0 }), auditFile: tmp(), card: card(), badge: BADGE, price: "500000" });
  const srv = app.listen(0); await new Promise((r) => srv.once("listening", r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const pins = new Map([[base, BADGE]]);
  const check = (badge, o) => checkCounterparty(badge, { ...o, call: fakeCall(entry({ origin: base })), ownerIdentity: fakeOwnerIdentity, verifyProof: async () => false });
  const payingFetch = makePayingFetch({ account: { address: BUYER, signer: null }, scheme, check, auditFile, originPins: pins });
  const q = { address: "0x000000000000000000000000000000000000dEaD", chain: "ethereum", token: "USDT" };
  const out = [];
  try { for (let i = 0; i < 5; i++) out.push(await buyCcd(base + "/v1/balance", { body: q, purpose: "tier", auditFile, payingFetch })); } finally { srv.close(); }
  assert.deepEqual(out.map((r) => r.ok), [true, true, true, true, false], JSON.stringify(out.at(-1)));
  assert.match(out[4].reason, /origin-bound tier \(no key proof\): its daily cap 2000000/);
  const l = log(auditFile);
  const auth = l.filter((e) => e.kind === "authorized"), pay = l.filter((e) => e.kind === "payment"), ref = l.filter((e) => e.kind === "refusal");
  assert.equal(auth.length, 4); assert.equal(pay.length, 4); assert.equal(ref.length, 1);
  for (const e of [...auth, ...pay, ...ref]) assert.equal(e.trust_tier, "origin-bound");
});
