// Concordium payment rail: Gig Guard pays other agents over x402 (exact scheme, V1 sponsored transactions),
// so it never needs CCD for fees. Before anything is signed, the seller must prove an accountable owner
// through the Concordium Agent Registry, and the price must fit the caps. Every payment and every refusal
// is written to the audit log.
import fs from "node:fs";
import { AccountAddress, parseWallet, buildAccountSigner } from "@concordium/web-sdk";
import { x402Client } from "@x402/core/client";
import { wrapFetchWithPayment } from "@x402/fetch";
import { ExactConcordiumScheme } from "@x402/concordium/exact/client";
import { CONCORDIUM_TESTNET_CAIP2, CONCORDIUM_MAINNET_CAIP2, getExplorerTxUrl } from "@x402/concordium";
import { checkCounterparty, readCapped, ORIGIN_TIER } from "./registry.mjs";
import { record, AUDIT_FILE } from "./audit.mjs";

export const CAIP2 = (process.env.GG_CCD_NETWORK || "testnet") === "mainnet" ? CONCORDIUM_MAINNET_CAIP2 : CONCORDIUM_TESTNET_CAIP2;
// Caps in atomic units (microCCD, or the PLT's smallest unit). Defaults: 5 CCD per call, 50 CCD per day.
export const MAX_PER_CALL = BigInt(process.env.GG_CCD_MAX_PER_CALL || "5000000");
export const MAX_PER_DAY = BigInt(process.env.GG_CCD_MAX_PER_DAY || "50000000");

// Origin-bound tier (opt-in, off unless set): GG_CCD_ORIGIN_TIER="https://seller.example=<badge>[,...]" pins an outside
// seller's origin to its registry badge. A pinned seller that serves no key proof may still be paid if every other check
// holds (registry.mjs), but only up to its own low caps: default 1 CCD per call and 2 CCD per day across all pinned
// sellers. Every decision for it is logged with trust_tier "origin-bound".
export function parseOriginTier(spec = "") {
  const m = new Map();
  for (const part of String(spec).split(",").map((x) => x.trim()).filter(Boolean)) {
    const i = part.lastIndexOf("=");
    const u = new URL(part.slice(0, i)), badge = part.slice(i + 1);
    if (u.protocol !== "https:" || u.origin !== part.slice(0, i).replace(/\/$/, "")) throw new Error(`GG_CCD_ORIGIN_TIER: ${part.slice(0, i)} is not an https origin`);
    if (!/^[1-9A-HJ-NP-Za-km-z]{12,40}$/.test(badge)) throw new Error("GG_CCD_ORIGIN_TIER: bad badge");
    if (m.has(u.origin)) throw new Error(`GG_CCD_ORIGIN_TIER: ${u.origin} is pinned twice`);
    m.set(u.origin, badge);
  }
  return m;
}
export const ORIGIN_PINS = parseOriginTier(process.env.GG_CCD_ORIGIN_TIER || "");
export const TIER_MAX_PER_CALL = BigInt(process.env.GG_CCD_ORIGIN_TIER_MAX_PER_CALL || "1000000");
export const TIER_MAX_PER_DAY = BigInt(process.env.GG_CCD_ORIGIN_TIER_MAX_PER_DAY || "2000000");

// Loads the account from a Concordium wallet export (Browser Wallet: Export private key) or from
// GG_CCD_ADDRESS + GG_CCD_SIGN_KEY. Returns the address, the raw sign key (for the facilitator) and a signer.
export function loadAccount(file = process.env.GG_CCD_KEYFILE) {
  if (file) {
    const w = parseWallet(fs.readFileSync(file, "utf8"));
    const keys = w.value.accountKeys.keys;
    const signKey = keys[0]?.keys?.[0]?.signKey;
    return { address: w.value.address, signKey, signer: buildAccountSigner(w) };
  }
  const address = process.env.GG_CCD_ADDRESS, signKey = process.env.GG_CCD_SIGN_KEY;
  if (!address || !signKey) throw new Error("no Concordium account: set GG_CCD_KEYFILE (wallet export) or GG_CCD_ADDRESS + GG_CCD_SIGN_KEY");
  return { address, signKey, signer: buildAccountSigner(signKey) };
}

// Assets we pay in on CAIP2 (comma list; "CCD" = native CCD, anything else = a PLT token id). Caps apply per asset,
// in that asset's atomic units. Any other network, scheme or asset is refused before signing.
export const ASSETS = (process.env.GG_CCD_ASSETS || "CCD").split(",").map((s) => s.trim()).filter(Boolean);
const AMOUNT = /^[1-9][0-9]{0,29}$/;                       // a positive integer in atomic units, nothing else
const CCD_ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{50}$/;

// Day spend per asset from the audit log. A payment counts the moment we authorise signing it ("authorized"),
// whether or not the seller ever reports settlement: a seller holding a signed transfer can submit it itself.
// Older logs have only "payment" lines; those count too, unless they point at an "authorized" line already counted.
function spentToday(file, asset, tier = null) {
  const day = new Date().toISOString().slice(0, 10);
  if (!file || !fs.existsSync(file)) return 0n;
  return fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l))
    .filter((e) => e.ts?.startsWith(day) && (e.asset ?? "CCD") === asset && (e.kind === "authorized" || (e.kind === "payment" && !e.authorization)))
    .filter((e) => !tier || (e.kind === "authorized" && e.trust_tier === tier))
    .reduce((s, e) => s + (AMOUNT.test(String(e.amount)) ? BigInt(e.amount) : 0n), 0n);
}

// Cross-process lock around "check the day's spend + write the authorisation" (same process: that block is synchronous).
const sleepMs = (ms) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
function withLock(file, fn) {
  const lock = file + ".lock";
  for (let i = 0; ; i++) {
    try { fs.closeSync(fs.openSync(lock, "wx")); break; }
    catch (e) {
      if (e.code !== "EEXIST") throw e;
      try { if (Date.now() - fs.statSync(lock).mtimeMs > 30000) fs.rmSync(lock, { force: true }); } catch { /* raced */ }
      if (i > 500) throw new Error("audit log is locked by another payer (fail closed)");
      sleepMs(10);
    }
  }
  try { return fn(); } finally { fs.rmSync(lock, { force: true }); }
}

// payPolicy(): the decision before signing, exported for tests. `origin` is the seller endpoint we called.
export async function payPolicy(req, { check = checkCounterparty, auditFile, origin, originPins = ORIGIN_PINS } = {}) {
  const no = (reason, extra = {}) => ({ ok: false, reason, ...extra });
  // Reasons can become public: they never echo what the seller sent, only which field failed and our own limits.
  if (!req || req.scheme !== "exact") return no("payment scheme is not \"exact\"");
  if (req.network !== CAIP2) return no(`payment network is not ${CAIP2}`);
  if (!ASSETS.includes(String(req.asset))) return no(`payment asset is not one we pay in (${ASSETS.join(", ")})`);
  if (typeof req.amount !== "string" || !AMOUNT.test(req.amount)) return no("payment amount is not a positive integer in atomic units");
  if (typeof req.payTo !== "string" || !CCD_ADDRESS.test(req.payTo)) return no("payTo is missing or not a Concordium account address");
  const amount = BigInt(req.amount);
  if (amount > MAX_PER_CALL) return no(`payment amount is over the per-call cap ${MAX_PER_CALL}`);
  if (spentToday(auditFile, req.asset) + amount > MAX_PER_DAY) return no(`the daily cap ${MAX_PER_DAY} would be exceeded`);
  // A pinned origin is checked against its pinned badge (an outside seller's offer may name none); a different badge is refused.
  const pinned = origin ? originPins.get(origin) : undefined;
  let badge = req.extra?.agentBadge;
  if (pinned) { if (badge !== undefined && badge !== pinned) return no("the offer names another badge than the one pinned for this origin"); badge = pinned; }
  const cp = await check(badge, { payTo: req.payTo, origin, allowOriginTier: !!pinned });
  if (!cp.ok) return no(`seller not accountable: ${cp.reasons.join("; ")}`, { counterparty: cp });
  if (cp.tier === ORIGIN_TIER) {
    if (!pinned) return no("origin-bound tier used for an origin that is not pinned", { counterparty: cp });   // never: the check gets allowOriginTier only when pinned
    if (amount > TIER_MAX_PER_CALL) return no(`origin-bound tier (no key proof): amount is over its per-call cap ${TIER_MAX_PER_CALL}`, { counterparty: cp });
    if (spentToday(auditFile, req.asset, ORIGIN_TIER) + amount > TIER_MAX_PER_DAY) return no(`origin-bound tier (no key proof): its daily cap ${TIER_MAX_PER_DAY} would be exceeded`, { counterparty: cp });
  }
  return { ok: true, counterparty: cp };
}

// Returns fetch that pays on 402 when, and only when, the policy allows it.
export function makePayingFetch({ account = loadAccount(), scheme: injected, grpcUrl = process.env.GG_CCD_GRPC, auditFile = AUDIT_FILE, check, purpose = "", originPins } = {}) {
  const scheme = injected || new ExactConcordiumScheme(
    { accountAddress: AccountAddress.fromBase58(account.address), signer: account.signer },
    grpcUrl ? { grpcUrl, useTls: !/^localhost|^127\./.test(grpcUrl) } : undefined,
  );
  // Our own caps (GG_CCD_MAX_PER_CALL / _PER_DAY, in atomic units) replace the library's USD spend controls,
  // which only know default assets.
  const client = x402Client.fromConfig({ schemes: [{ network: "ccd:*", client: scheme }], spendControls: false });
  const last = { decision: null, origin: null, busy: false };   // one paid call at a time per paying fetch (the origin binding is per call)
  client.onBeforePaymentCreation(async ({ selectedRequirements: req }) => {
    let d = await payPolicy(req, { check, auditFile, origin: last.origin, ...(originPins ? { originPins } : {}) });
    // The registry check awaited the network, so re-check the day's spend and write the authorisation in one
    // synchronous, locked step: no other call can pass the cap between the check and the write.
    if (d.ok) d = withLock(auditFile, () => {
      if (spentToday(auditFile, req.asset) + BigInt(req.amount) > MAX_PER_DAY) return { ok: false, reason: `the daily cap ${MAX_PER_DAY} would be exceeded`, counterparty: d.counterparty };
      if (d.counterparty.tier === ORIGIN_TIER && spentToday(auditFile, req.asset, ORIGIN_TIER) + BigInt(req.amount) > TIER_MAX_PER_DAY) return { ok: false, reason: `origin-bound tier (no key proof): its daily cap ${TIER_MAX_PER_DAY} would be exceeded`, counterparty: d.counterparty };
      const authorization = record("authorized", { purpose, trust_tier: d.counterparty.tier, payTo: req.payTo, amount: req.amount, asset: req.asset, network: req.network, seller_badge: d.counterparty.badge, seller_owner: d.counterparty.owner, seller_owner_idp: d.counterparty.ownerIdp?.name ?? null, origin: last.origin }, { file: auditFile });
      return { ...d, authorization };
    });
    last.decision = { ...d, req };
    if (!d.ok) {
      record("refusal", { purpose, payTo: typeof req?.payTo === "string" && CCD_ADDRESS.test(req.payTo) ? req.payTo : null, amount: typeof req?.amount === "string" && AMOUNT.test(req.amount) ? req.amount : null,
        asset: ASSETS.includes(String(req?.asset)) ? req.asset : null, trust_tier: d.counterparty?.tier ?? null, claimed_badge: typeof req?.extra?.agentBadge === "string" && /^[1-9A-HJ-NP-Za-km-z]{12,40}$/.test(req.extra.agentBadge) ? req.extra.agentBadge : null, reason: d.reason }, { file: auditFile });
      return { abort: true, reason: d.reason };
    }
  });
  const paid = wrapFetchWithPayment(fetch, client);
  // Use the returned fetch only through buyCcd(): buyCcd holds the one-call-at-a-time lock and sets the origin the badge is bound to.
  return { fetch: paid, last, account };
}

// One paid request. Returns {ok, status, body, tx, explorer, refused}.
// `headers`: extra request headers (e.g. X-ID-Presentation for a seller that asks for an identity attribute proof).
export async function buyCcd(url, { body, purpose = "", headers = {}, ...opts } = {}) {
  const auditFile = opts.auditFile || AUDIT_FILE;
  const { fetch: paid, last, account } = opts.payingFetch || makePayingFetch({ ...opts, auditFile, purpose });
  if (last.busy) return { ok: false, refused: true, reason: "another paid call is in progress on this paying fetch (one at a time)" };
  last.busy = true;
  try { return await buyOnce(url, { body, purpose, auditFile, paid, last, account, headers }); } finally { last.busy = false; }
}
async function buyOnce(url, { body, purpose, auditFile, paid, last, account, headers = {} }) {
  const t0 = Date.now();
  last.decision = null;
  last.origin = new URL(url).origin;   // the endpoint we chose to call: the badge must be bound to it
  const logPayment = (extra) => {
    const r = last.decision.req;
    record("payment", { purpose, url, trust_tier: last.decision.counterparty?.tier ?? null, payTo: r.payTo, amount: r.amount, asset: r.asset, seller_badge: last.decision.counterparty?.badge, seller_owner: last.decision.counterparty?.owner, payer: account.address, authorization: last.decision.authorization, ...extra }, { file: auditFile });
  };
  let res;
  try {
    // 30 s, no redirects (a redirect would leave the origin the badge was bound to)
    const init = { redirect: "error", signal: AbortSignal.timeout(Number(process.env.GG_CCD_CALL_TIMEOUT_MS || 30000)) };
    const extra = Object.fromEntries(Object.entries(headers || {}).filter(([k, v]) => /^x-[\w-]{1,40}$/i.test(k) && typeof v === "string"));
    res = await paid(url, body ? { ...init, method: "POST", headers: { ...extra, "content-type": "application/json" }, body: JSON.stringify(body) } : { ...init, headers: extra });
  } catch (e) {
    if (last.decision && !last.decision.ok) return { ok: false, refused: true, reason: last.decision.reason };
    if (last.decision?.ok) logPayment({ tx: null, settled: false, error: String(e.message || e).slice(0, 200) });   // signed, outcome unknown: still counted
    return { ok: false, reason: String(e?.message || e).slice(0, 300) };   // private detail (callers put it in notes, never in public text)
  }
  const settle = decodeHeader(res.headers.get("payment-response") || res.headers.get("x-payment-response"));
  const tx = typeof settle?.transaction === "string" && /^[0-9a-f]{64}$/i.test(settle.transaction) ? settle.transaction : null;
  let parsed = null, tooBig = false;
  try { parsed = JSON.parse((await readCapped(res, 65536, "response")).toString("utf8")); } catch (e) { tooBig = /larger than/.test(String(e.message)); }
  const out = { ok: res.ok && !tooBig, status: res.status, body: tooBig ? null : parsed, ...(tooBig ? { reason: "seller response larger than 65536 bytes" } : {}), tx, explorer: tx ? getExplorerTxUrl(CAIP2, tx) : null, ms: Date.now() - t0,
    seller_badge: last.decision?.ok ? last.decision.counterparty?.badge : null, trust_tier: last.decision?.counterparty?.tier ?? null,
    amount_ccd: last.decision?.ok && last.decision.req?.asset === "CCD" ? Number(last.decision.req.amount) / 1e6 : null };
  if (last.decision?.ok) logPayment({ tx, settled: !!tx && res.ok, http: res.status });
  return out;
}

function decodeHeader(h) {
  if (!h) return null;
  try { return JSON.parse(Buffer.from(h, "base64").toString("utf8")); } catch { try { return JSON.parse(h); } catch { return null; } }
}
