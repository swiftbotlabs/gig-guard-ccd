// A small paid agent that Gig Guard can hire on Concordium: "Ledger Check" sells an on-chain balance
// reading (the free public-RPC read Gig Guard already trusts, now offered as a paid, receipted service).
// It is registered in the Agent Registry and advertises its badge in every x402 offer (extra.agentBadge),
// so buyers can check who stands behind it before they pay. It runs its own facilitator: a sponsor account
// pays the transaction fee, so the buyer needs no CCD for gas.
//
//   GG_CCD_KEYFILE=<seller wallet export>  GG_CCD_SELLER_BADGE=<CIS-2 token address>  node src/ccd/seller.mjs
//   GG_CCD_SELLER_ORIGIN=<the public origin buyers call, e.g. https://ledger-check.example>  (needed for the key proof)
//   optional: GG_CCD_SPONSOR_KEYFILE (defaults to the seller account), GG_CCD_PRICE (microCCD, default 100000 = 0.1 CCD), PORT
import express from "express";
import fs from "node:fs";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { x402Facilitator } from "@x402/core/facilitator";
import { ExactConcordiumScheme as ServerScheme } from "@x402/concordium/exact/server";
import { ExactConcordiumScheme as FacilitatorScheme } from "@x402/concordium/exact/facilitator";
import { toConcordiumFacilitatorSigner, getConcordiumGrpcUrl, parseGrpcUrl } from "@x402/concordium";
import { loadAccount, CAIP2 } from "./rail.mjs";
import { proofMessage } from "./registry.mjs";
import { AccountAddress, signMessage } from "@concordium/web-sdk";
import { chainBalance } from "../chain.mjs";
import { TOKENS, normChain } from "../tokens.mjs";
import { record, SELLER_AUDIT_FILE } from "./audit.mjs";

// Wraps an in-process x402Facilitator as the FacilitatorClient the resource server expects.
export function localFacilitator(fac) {
  return { verify: (p, r) => fac.verify(p, r), settle: (p, r) => fac.settle(p, r), getSupported: async () => fac.getSupported() };
}

export function buildSeller({ seller = loadAccount(), sponsor = process.env.GG_CCD_SPONSOR_KEYFILE ? loadAccount(process.env.GG_CCD_SPONSOR_KEYFILE) : seller,
  badge = process.env.GG_CCD_SELLER_BADGE, price = process.env.GG_CCD_PRICE || "100000", facilitatorClient, read = chainBalance, auditFile = process.env.GG_SELLER_AUDIT || SELLER_AUDIT_FILE,
  card = process.env.GG_CCD_SELLER_CARD ? fs.readFileSync(process.env.GG_CCD_SELLER_CARD) : null,
  origin: originIn = process.env.GG_CCD_SELLER_ORIGIN || null,   // the public origin buyers call; key proofs name it and nothing else
  rateLimit = { max: Number(process.env.GG_SELLER_RATE_MAX || 60), windowMs: Number(process.env.GG_SELLER_RATE_WINDOW_MS || 60000) } } = {}) {
  if (!facilitatorClient) {
    const [host, port] = parseGrpcUrl(process.env.GG_CCD_GRPC || getConcordiumGrpcUrl(CAIP2));
    const signer = toConcordiumFacilitatorSigner(sponsor.address, sponsor.signKey, { host, port, useTls: true });
    facilitatorClient = localFacilitator(new x402Facilitator().register(CAIP2, new FacilitatorScheme({ signer })));
  }
  const server = new x402ResourceServer(facilitatorClient).register(CAIP2, new ServerScheme());
  const app = express();
  app.set("case sensitive routing", true);
  app.set("strict routing", true);
  // Exact raw-path allow-list, checked on the path as the client sent it (never decoded): /v1/b%61lance, /V1/balance, /v1/balance/,
  // /v1/balance%2f or //v1/balance are refused here, before any route, rate limit or payment step (the x402 middleware would
  // otherwise decode and normalise them into its paid route without passing our limiter).
  const EXACT = new Map([["/.well-known/agent-card.json", "GET"], ["/.well-known/agent-proof", "GET"], ["/v1/balance", "POST"]]);
  app.use((req, res, next) => {
    const raw = String(req.originalUrl || "").split("?")[0];
    const m = EXACT.get(raw);
    return m && (req.method === m || (m === "GET" && req.method === "HEAD")) ? next() : res.status(404).json({ error: "not found" });
  });
  app.use(express.json({ limit: "4kb" }));
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
    const { address, token: t } = req.body || {};
    if (!/^0x[0-9a-fA-F]{40}$/.test(address || "")) return res.status(400).json({ error: "address must be a 0x address" });
    const chain = normChain(req.body?.chain);
    if (!Object.hasOwn(TOKENS, chain)) return res.status(400).json({ error: `chain must be one of ${Object.keys(TOKENS).join(", ")}` });
    const token = /^0x[0-9a-fA-F]{40}$/.test(String(t || "")) ? t : String(t || "").toUpperCase();
    if (!/^0x[0-9a-fA-F]{40}$/.test(token) && !Object.hasOwn(TOKENS[chain], token)) return res.status(400).json({ error: `token must be a 0x contract or one of ${Object.keys(TOKENS[chain]).join(", ")}` });
    try {
      const r = await read(address, chain, token);
      record("decision", { role: "seller", service: "balance", chain, token, ok: !!r }, { file: auditFile, agent: badge, owner: seller.address });
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
