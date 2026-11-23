// A small paid agent that Gig Guard can hire on Concordium: "Ledger Check" sells an on-chain balance
// reading (the free public-RPC read Gig Guard already trusts, now offered as a paid, receipted service).
// It is registered in the Agent Registry and advertises its badge in every x402 offer (extra.agentBadge),
// so buyers can check who stands behind it before they pay. It runs its own facilitator: a sponsor account
// pays the transaction fee, so the buyer needs no CCD for gas.
//
//   GG_CCD_KEYFILE=<seller wallet export>  GG_CCD_SELLER_BADGE=<CIS-2 token address>  node src/ccd/seller.mjs
//   GG_CCD_SELLER_ORIGIN=<the public origin buyers call, e.g. https://ledger-check.example>  (needed for the key proof)
//   optional: GG_CCD_SPONSOR_KEYFILE (defaults to the seller account), GG_CCD_PRICE (microCCD, default 100000 = 0.1 CCD), PORT
//   GG_CCD_SELLER_BUYER_ID=1: serve only buyers whose paying account holds a live identity credential from an accepted Concordium
//   identity provider (the same check buyers run on sellers; GG_CCD_IDP_ALLOW narrows the providers). A refused buyer is not charged.
//   GG_CCD_SELLER_ID_PROOF=1: also require a zero-knowledge identity attribute proof (default: 18 or older, GG_CCD_ID_MIN_AGE) made for
//   the paying account: GET /v1/id-challenge?account=<payer> returns the request; the buyer's wallet proves it and the buyer sends the
//   presentation (base64 JSON) in X-ID-Presentation with the paid call. A missing or failed proof is refused before settlement (not charged).
import express from "express";
import fs from "node:fs";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { x402Facilitator } from "@x402/core/facilitator";
import { ExactConcordiumScheme as ServerScheme } from "@x402/concordium/exact/server";
import { ExactConcordiumScheme as FacilitatorScheme } from "@x402/concordium/exact/facilitator";
import { toConcordiumFacilitatorSigner, getConcordiumGrpcUrl, parseGrpcUrl } from "@x402/concordium";
import { loadAccount, CAIP2 } from "./rail.mjs";
import { proofMessage, checkOwnerIdentity } from "./registry.mjs";
import { AccountAddress, signMessage } from "@concordium/web-sdk";
import { chainBalance } from "../chain.mjs";
import { TOKENS, normChain } from "../tokens.mjs";
import { record, SELLER_AUDIT_FILE } from "./audit.mjs";
import { idProofGate, accountKey } from "./idproof.mjs";

// The paying account: the sender in the header of the signed V1 transaction the buyer sent (the facilitator has already
// verified that signature by the time the route runs). Anything else, or anything malformed, is no payer at all.
export function payerOf(req) {
  try {
    const h = req.get("payment-signature") || req.get("x-payment");
    if (!h || h.length > 16384 || !/^[A-Za-z0-9+/=_-]+$/.test(h)) return null;
    const p = JSON.parse(Buffer.from(h, "base64").toString("utf8"));
    const sender = p?.payload?.signedTransaction?.header?.sender;
    return typeof sender === "string" ? AccountAddress.fromBase58(sender).address : null;
  } catch { return null; }
}

// Wraps an in-process x402Facilitator as the FacilitatorClient the resource server expects.
export function localFacilitator(fac) {
  return { verify: (p, r) => fac.verify(p, r), settle: (p, r) => fac.settle(p, r), getSupported: async () => fac.getSupported() };
}

export function buildSeller({ seller = loadAccount(), sponsor = process.env.GG_CCD_SPONSOR_KEYFILE ? loadAccount(process.env.GG_CCD_SPONSOR_KEYFILE) : seller,
  badge = process.env.GG_CCD_SELLER_BADGE, price = process.env.GG_CCD_PRICE || "100000", facilitatorClient, read = chainBalance, auditFile = process.env.GG_SELLER_AUDIT || SELLER_AUDIT_FILE,
  card = process.env.GG_CCD_SELLER_CARD ? fs.readFileSync(process.env.GG_CCD_SELLER_CARD) : null,
  origin: originIn = process.env.GG_CCD_SELLER_ORIGIN || null,   // the public origin buyers call; key proofs name it and nothing else
  rateLimit = { max: Number(process.env.GG_SELLER_RATE_MAX || 60), windowMs: Number(process.env.GG_SELLER_RATE_WINDOW_MS || 60000) },
  // Seller-side gate: (account) => {ok, idpName, reason}. On for the CLI with GG_CCD_SELLER_BUYER_ID=1; tests pass their own.
  buyerIdentity = process.env.GG_CCD_SELLER_BUYER_ID === "1" ? (a) => checkOwnerIdentity(a) : null,
  // Optional identity attribute proof gate (see src/ccd/idproof.mjs); on for the CLI with GG_CCD_SELLER_ID_PROOF=1.
  idProof = process.env.GG_CCD_SELLER_ID_PROOF === "1" ? idProofGate({ resource: "ledger-check/balance" }) : null } = {}) {
  // An empty provider allow-list would accept testnet's self-service test identities (or any provider): name them explicitly.
  if (process.env.GG_CCD_SELLER_ID_PROOF === "1" && !(process.env.GG_CCD_IDP_ALLOW || "").trim()) throw new Error("GG_CCD_SELLER_ID_PROOF=1 needs GG_CCD_IDP_ALLOW (e.g. 1,2,3 on mainnet; 0 = testnet test identities, demo only)");
  if (!facilitatorClient) {
    const [host, port] = parseGrpcUrl(process.env.GG_CCD_GRPC || getConcordiumGrpcUrl(CAIP2));
    const signer = toConcordiumFacilitatorSigner(sponsor.address, sponsor.signKey, { host, port, useTls: true });
    facilitatorClient = localFacilitator(new x402Facilitator().register(CAIP2, new FacilitatorScheme({ signer })));
  }
  // Buyer verdicts are cached per account for 5 minutes (bounded), so replays and repeat buyers cost no node reads.
  const ID_TTL_MS = 300000, ID_CACHE_MAX = 1000, idCache = new Map(), refusedAt = new Map();
  const server = new x402ResourceServer(facilitatorClient).register(CAIP2, new ServerScheme());
  const app = express();
  app.set("case sensitive routing", true);
  app.set("strict routing", true);
  // Exact raw-path allow-list, checked on the path as the client sent it (never decoded): /v1/b%61lance, /V1/balance, /v1/balance/,
  // /v1/balance%2f or //v1/balance are refused here, before any route, rate limit or payment step (the x402 middleware would
  // otherwise decode and normalise them into its paid route without passing our limiter).
  const EXACT = new Map([["/.well-known/agent-card.json", "GET"], ["/.well-known/agent-proof", "GET"], ["/v1/balance", "POST"], ["/v1/id-challenge", "GET"]]);
  app.use((req, res, next) => {
    const raw = String(req.originalUrl || "").split("?")[0];
    const m = EXACT.get(raw);
    return m && (req.method === m || (m === "GET" && req.method === "HEAD")) ? next() : res.status(404).json({ error: "not found" });
  });
  // The exact bytes whose hash is on chain (buyers bind the badge to this endpoint with it). Read once at start.
  const cardBytes = card == null ? null : Buffer.from(card);
  app.get("/.well-known/agent-card.json", (req, res) => {
    if (cardBytes) return res.type("application/json").send(cardBytes);
    res.status(404).json({ error: "no agent card configured" });
  });
  // The origin key proofs name, normalised (scheme://host[:port], no path); a function is resolved per request (tests).
  const norm = (o) => { if (!o) return null; const u = new URL(o); if (!/^https?:$/.test(u.protocol) || u.origin === "null") throw new Error(`GG_CCD_SELLER_ORIGIN must be an http(s) origin, got ${o}`); return u.origin; };
  if (typeof originIn === "string") norm(originIn);   // a bad origin stops the seller at startup, not at the first buyer
  const ownOrigin = () => norm(typeof originIn === "function" ? originIn() : originIn);
  // Fixed-window rate limit per client address on the paid route and the key proof (signing costs CPU), before any work.
  const hits = new Map();   // one bucket per client and route: proofs can't be starved by paid calls, or the reverse
  // The bucket is named by the route we mount it on, never by the path the client typed (a case variant gets the same bucket).
  const limit = (route) => (req, res, next) => {
    const now = Date.now(), k = `${route}|${req.ip || req.socket.remoteAddress || "?"}`;
    let h = hits.get(k);
    if (!h || now - h.t >= rateLimit.windowMs) { h = { t: now, n: 0 }; hits.set(k, h); }
    if (hits.size > 10000) for (const [key, v] of hits) if (now - v.t >= rateLimit.windowMs) hits.delete(key);
    if (++h.n > rateLimit.max) return res.status(429).json({ error: "too many requests" });
    next();
  };
  app.use("/v1/balance", limit("paid"));
  app.use("/.well-known/agent-proof", limit("proof"));
  app.use("/v1/id-challenge", limit("idchallenge"));
  // The identity proof is bound to the paying account without its alias bytes (all 2^24 aliases sign with the same keys).
  app.get("/v1/id-challenge", (req, res) => {
    if (!idProof) return res.status(404).json({ error: "no identity proof required" });
    let key; try { key = accountKey(String(req.query.account || "")); } catch { return res.status(400).json({ error: "account must be a Concordium account address" }); }
    let ch; try { ch = idProof.challenge(key); } catch { return res.status(503).json({ error: "too many open identity challenges, retry later" }); }
    res.json({ nonce: ch.nonce, connectionId: ch.connectionId, resource: ch.resource, minAge: ch.minAge, claims: ch.claims, expiresAt: ch.expiresAt });
  });
  app.use("/v1/balance", express.json({ limit: "4kb" }));   // parsed only after the rate limit, so bad or oversized bodies count too
  // Key proof: sign the buyer's fresh nonce with the seller's own wallet key, for our configured origin only, so a
  // copycat endpoint serving our card can't borrow it (a relayed proof names our origin, not the copycat's).
  app.get("/.well-known/agent-proof", async (req, res) => {
    const nonce = String(req.query.nonce || "");
    if (!/^[0-9a-f]{32}$/.test(nonce)) return res.status(400).json({ error: "nonce must be 32 hex characters" });
    let origin = null;
    try { origin = ownOrigin(); } catch { origin = null; }
    if (!origin || !seller.signer || !badge) return res.status(404).json({ error: "no key proof configured" });
    try {
      const message = proofMessage({ badge, origin, account: seller.address, nonce });
      const signature = await signMessage(AccountAddress.fromBase58(seller.address), message, seller.signer);
      res.json({ message, account: seller.address, signature });
    } catch { res.status(500).json({ error: "signing failed" }); }
  });
  app.use(paymentMiddleware({
    "POST /v1/balance": {
      accepts: { scheme: "exact", network: CAIP2, payTo: seller.address, price: { amount: String(price), asset: "CCD" }, maxTimeoutSeconds: 120, extra: { agentBadge: badge } },
      description: "On-chain ERC-20 balance reading (USDT/USDC on 6 EVM chains), read live from a public RPC",
      mimeType: "application/json",
    },
  }, server));
  app.post("/v1/balance", async (req, res) => {
    // Runs after the facilitator verified the signed payment and before it is settled: an error status here cancels the
    // settlement, so a buyer we refuse is never charged. The payer is the sender of the verified, signed transaction.
    if (buyerIdentity) {
      const payer = payerOf(req);
      let id = { ok: false, reason: "no payer account in the payment" };
      // Cache key: the account without its alias bytes (an account has 2^24 alias addresses, all signing with the same keys).
      const acct = payer ? Buffer.from(AccountAddress.fromBase58(payer).decodedAddress.subarray(0, 29)).toString("hex") : null;
      const hit = acct && idCache.get(acct);
      if (hit && Date.now() - hit.at < ID_TTL_MS) id = hit.id;
      else if (payer) {
        try {
          id = await buyerIdentity(payer);
          if (!id?.readError) { idCache.delete(acct); idCache.set(acct, { at: Date.now(), id }); if (idCache.size > ID_CACHE_MAX) idCache.delete(idCache.keys().next().value); }
        } catch { id = { ok: false, reason: "the buyer's identity could not be read (fail closed)" }; }   // read errors are not cached
      }
      if (!id?.ok) {
        // One refusal line per account per 2 minutes (a signed payment can be replayed until it expires): the log stays bounded.
        const key = acct || "-", last = refusedAt.get(key);
        if (!last || Date.now() - last > 120000) {
          refusedAt.delete(key); refusedAt.set(key, Date.now()); if (refusedAt.size > ID_CACHE_MAX) refusedAt.delete(refusedAt.keys().next().value);
          const why = String(id?.reason || "").replace(/[^\w .,()'-]/g, "").slice(0, 160);
          record("refusal", { role: "seller", service: "balance", buyer: payer, reason: `buyer has no verified human behind it: ${why}` }, { file: auditFile, agent: badge, owner: seller.address });
        }
        return res.status(403).json({ error: "buyer not accepted: the paying account needs a live identity credential from an accepted Concordium identity provider; nothing was charged" });
      }
      req.buyerIdp = String(id.idpName || "").replace(/[^\w .,()-]/g, "").slice(0, 64);
    }
    const { address, token: t } = req.body || {};
    if (!/^0x[0-9a-fA-F]{40}$/.test(address || "")) return res.status(400).json({ error: "address must be a 0x address" });
    const chain = normChain(req.body?.chain);
    if (!Object.hasOwn(TOKENS, chain)) return res.status(400).json({ error: `chain must be one of ${Object.keys(TOKENS).join(", ")}` });
    const token = /^0x[0-9a-fA-F]{40}$/.test(String(t || "")) ? t : String(t || "").toUpperCase();
    if (!/^0x[0-9a-fA-F]{40}$/.test(token) && !Object.hasOwn(TOKENS[chain], token)) return res.status(400).json({ error: `token must be a 0x contract or one of ${Object.keys(TOKENS[chain]).join(", ")}` });
    // Identity proof last: a bad body or a refused buyer identity never consumes the buyer's single-use proof.
    if (idProof) {
      const payer = payerOf(req), h = req.get("x-id-presentation") || "";
      let r = { ok: false, reason: "no identity proof sent (X-ID-Presentation)" };
      if (payer && h && h.length <= 16000 && /^[A-Za-z0-9+/=_-]+$/.test(h)) {
        try { r = await idProof.check(Buffer.from(h, "base64").toString("utf8"), accountKey(payer)); } catch { r = { ok: false, reason: "identity proof could not be checked (fail closed)" }; }
      } else if (!payer) r = { ok: false, reason: "no payer account in the payment" };
      if (!r.ok) {
        const why = String(r.reason || "").replace(/[^\w .,()'>=-]/g, "").slice(0, 160);
        const key = payer || "-", last = refusedAt.get(`id|${key}`);
        if (!last || Date.now() - last > 120000) {
          refusedAt.delete(`id|${key}`); refusedAt.set(`id|${key}`, Date.now()); if (refusedAt.size > ID_CACHE_MAX) refusedAt.delete(refusedAt.keys().next().value);
          record("refusal", { role: "seller", service: "balance", buyer: payer, reason: `no valid identity attribute proof: ${why}` }, { file: auditFile, agent: badge, owner: seller.address });
        }
        // A fixed message to the client; the reason stays in the seller's own log.
        return res.status(403).json({ error: "buyer not accepted: a valid identity attribute proof for the paying account is required (GET /v1/id-challenge); nothing was charged" });
      }
      req.buyerProof = r.proven.join(",");
    }
    try {
      const r = await read(address, chain, token);
      record("decision", { role: "seller", service: "balance", chain, token, ok: !!r, ...(buyerIdentity ? { buyer: payerOf(req), buyer_idp: req.buyerIdp } : {}), ...(idProof ? { buyer: payerOf(req), buyer_proved: req.buyerProof } : {}) }, { file: auditFile, agent: badge, owner: seller.address });
      res.json({ address, chain, token, balance: r?.balance ?? null, as_of: new Date().toISOString(), source: "public RPC balanceOf", seller_badge: badge });
    } catch (e) {
      record("decision", { role: "seller", service: "balance", chain, token, ok: false, error: String(e.message || e).slice(0, 200) }, { file: auditFile, agent: badge, owner: seller.address });
      res.status(502).json({ error: "balance read failed upstream" });   // details stay in the seller's own log
    }
  });
  // Last: every error (bad JSON 400, body over 4 KB 413, bad charset 415, anything thrown) answers a fixed message, never a stack trace or a path.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err?.status === 413 || err?.type === "entity.too.large" ? 413 : Number.isInteger(err?.status) && err.status >= 400 && err.status < 500 ? 400 : 500;
    res.status(status).json({ error: status === 413 ? "body too large" : status === 400 ? "bad request" : "internal error" });
  });
  return app;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(process.env.PORT || 4021);
  buildSeller().listen(port, () => console.log(`Ledger Check seller on :${port} (${CAIP2})`));
}
