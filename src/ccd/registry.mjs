// Concordium Agent Registry (CIS-8004) lookups through Concordium's hosted Agent Registry MCP server.
// Used before every payment: a counterparty must be registered, Active and Verified by Concordium
// (its Agent Card's SHA-256 equals the hash committed on chain), and the x402 payTo must be its agent wallet.
// The badge is also bound to the endpoint being paid: that endpoint must serve, at /.well-known/agent-card.json,
// the exact Agent Card whose SHA-256 is on chain (naming this badge and the payTo account), AND prove it holds the
// registered wallet's key: it signs a fresh challenge naming the origin we are paying (/.well-known/agent-proof),
// and we check that signature against the account's keys on chain. Serving a copy of the public card is not enough.
// Fail closed: if the registry or the card can't be reached, nothing is paid.
import crypto from "node:crypto";
import { AccountAddress, verifyMessageSignature } from "@concordium/web-sdk";

export const REGISTRY_MCP = process.env.GG_CCD_REGISTRY || "https://agent-registry-mcp.concordium.com/mcp";
export const NETWORK = process.env.GG_CCD_NETWORK || "testnet";
const BADGE = /^[1-9A-HJ-NP-Za-km-z]{12,40}$/;

let rpcId = 0;
export async function mcpCall(name, args, { url = REGISTRY_MCP, timeoutMs = 20000 } = {}) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name, arguments: args } }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`registry ${name}: HTTP ${res.status}`);
  let body = await res.text();
  // Streamable HTTP may answer as an SSE frame.
  if (body.startsWith("event:") || body.startsWith("data:")) body = body.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5)).join("");
  const msg = JSON.parse(body);
  if (msg.error) throw new Error(`registry ${name}: ${msg.error.message}`);
  if (msg.result?.isError) throw new Error(`registry ${name}: ${msg.result.content?.[0]?.text?.slice(0, 200)}`);
  const text = msg.result?.content?.[0]?.text;
  return text ? JSON.parse(text) : null;
}

// Fetches the seller endpoint's Agent Card: no redirects, 10 s, at most 64 KB.
// Reads a response body, aborting as soon as it passes `max` bytes (a hostile endpoint can't make us buffer more).
export async function readCapped(res, max, what) {
  const chunks = []; let n = 0;
  for await (const c of res.body) { n += c.length; if (n > max) { try { await res.body.cancel(); } catch {} throw new Error(`${what} larger than ${max} bytes`); } chunks.push(Buffer.from(c)); }
  return Buffer.concat(chunks);
}
export async function fetchEndpointCard(origin) {
  const res = await fetch(origin + "/.well-known/agent-card.json", { redirect: "error", signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return readCapped(res, 65536, "card");
}

// The challenge the seller signs with its registered wallet key. Fixed template, built on both sides.
export const proofMessage = ({ badge, origin, account, nonce }) =>
  `gig-guard endpoint proof v1\nbadge: ${badge}\norigin: ${origin}\naccount: ${account}\nnonce: ${nonce}`;
export async function fetchEndpointProof(origin, nonce) {
  const res = await fetch(`${origin}/.well-known/agent-proof?nonce=${nonce}`, { redirect: "error", signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return JSON.parse((await readCapped(res, 4096, "proof")).toString("utf8"));
}
// Checks a message signature against the account's credential keys read from a Concordium node.
export async function verifyAccountProof(message, signature, account, { getAccountInfo } = {}) {
  const addr = AccountAddress.fromBase58(account);
  const info = getAccountInfo ? await getAccountInfo(addr) : await (await import("./chaintx.mjs")).nodeClient().getAccountInfo(addr);
  return verifyMessageSignature(message, signature, info);
}
const canon = (k) => /^(0|[1-9]\d{0,2})$/.test(k) && Number(k) <= 255;
const canonicalSig = (sig) => Object.entries(sig).length > 0 && Object.entries(sig).every(([c, ks]) => canon(c) && ks && typeof ks === "object" && Object.keys(ks).length > 0
  && Object.entries(ks).every(([k, v]) => canon(k) && typeof v === "string" && /^[0-9a-f]{128}$/i.test(v)));
// Errors become fixed text: at most an HTTP status code we parsed ourselves; no error message (it can quote a remote body).
const httpOf = (e) => { const m = /\bHTTP (\d{3})\b/.exec(String(e?.message || "")); return m ? ` (HTTP ${m[1]})` : ""; };
const STATUSES = new Set(["Active", "Suspended", "Revoked", "Inactive", "Pending", "Deregistered"]);
const lastPart = (s) => String(s ?? "").split(":").pop();

// Returns a normalized verdict for one badge (CIS-2 token address). `origin` = the seller endpoint being paid.
// The human behind the badge: the owner account must hold a live identity credential issued by one of the chain's
// Concordium identity providers. Read from the node: only the provider id and the credential's validity month, no
// personal data. GG_CCD_IDP_ALLOW (comma-separated provider ids) narrows the accepted providers, e.g. on mainnet.
// On testnet the "Concordium testnet IP" (id 0) issues test identities without document checks; on mainnet use 1,2,3
// (Notabene, Digital Trust Solutions, Global FinReg, read from a mainnet node on 22 Nov 2026). See docs/MAINNET.md.
const ALLOW_IDP = (process.env.GG_CCD_IDP_ALLOW || "").split(",").map((x) => x.trim()).filter(Boolean).map(Number);
let IP_CACHE = null;   // the provider list changes rarely: read it at most every 10 minutes
async function nodeIdentityProviders() {
  if (IP_CACHE && Date.now() - IP_CACHE.at < 600000) return IP_CACHE.list;
  const out = []; for await (const ip of (await import("./chaintx.mjs")).nodeClient().getIdentityProviders()) out.push({ id: Number(ip.ipIdentity), name: String(ip.ipDescription?.name || "").replace(/[^\w .,()-]/g, "").slice(0, 64) });
  if (out.length) IP_CACHE = { at: Date.now(), list: out };   // never cache an empty list
  return out;
}
export async function checkOwnerIdentity(owner, { getAccountInfo, identityProviders = nodeIdentityProviders, now = new Date(), allow = ALLOW_IDP } = {}) {
  const res = { ok: false, idp: null, idpName: null, validTo: null, reason: null };
  let info, ips;
  try {
    const addr = AccountAddress.fromBase58(owner);
    info = getAccountInfo ? await getAccountInfo(addr) : await (await import("./chaintx.mjs")).nodeClient().getAccountInfo(addr);
    ips = await identityProviders();
  } catch { res.reason = "the account's identity could not be read from the chain (fail closed)"; res.readError = true; return res; }
  const month = now.getUTCFullYear() * 100 + now.getUTCMonth() + 1;
  const known = new Map((ips || []).map((ip) => [ip.id, ip.name]));
  for (const c of Object.values(info?.accountCredentials || {})) {
    const k = c?.value?.contents, ip = Number(k?.ipIdentity), validTo = String(k?.policy?.validTo || "");
    if (!Number.isInteger(ip) || !known.has(ip) || (allow.length && !allow.includes(ip))) continue;
    if (!/^\d{6}$/.test(validTo) || Number(validTo) < month) continue;   // valid through the end of the month it names
    Object.assign(res, { ok: true, idp: ip, idpName: known.get(ip), validTo }); return res;
  }
  res.reason = "the owner account has no live identity credential from an accepted Concordium identity provider";
  return res;
}

// Trust tiers. "key-proof" (default, the only one unless the operator pins an origin): the endpoint signs our challenge
// with the registered wallet's key. "origin-bound" (opt-in per origin, see rail.mjs GG_CCD_ORIGIN_TIER, low caps): for an
// outside seller that serves no /.well-known/agent-proof at all (HTTP 404). Everything else must still hold, plus:
// the registry's agent_uri is on the origin being paid, and payTo is the registered agent wallet itself (not just the owner).
// A proof that is served but wrong, unreadable or unverifiable never falls back to this tier.
export const ORIGIN_TIER = "origin-bound";
export async function checkCounterparty(badge, { network = NETWORK, payTo = null, origin = null, allowOriginTier = false, call = mcpCall, fetchCard = fetchEndpointCard, fetchProof = fetchEndpointProof, verifyProof = verifyAccountProof, ownerIdentity = checkOwnerIdentity } = {}) {
  const out = { badge, network, ok: false, tier: null, found: false, active: false, cardMatches: false, endpointBound: false, originBound: false, walletMatches: false, ownerVerified: false, ownerIdp: null, owner: null, agentWallet: null, tokenId: null, reasons: [], source: "concordium-agent-registry" };
  if (typeof badge !== "string" || !BADGE.test(badge)) { out.reasons.push("no valid Concordium badge given"); return out; }
  let b;
  try { b = await call("check_badge", { id: badge, network }); }
  catch (e) { out.reasons.push(`registry unreachable${httpOf(e)} (fail closed)`); out.unreachable = true; return out; }
  const chk = b?.checks || {};
  out.found = !!chk.on_chain_agent_found;
  out.active = !!chk.status_active;
  out.cardMatches = !!chk.hash_matches_on_chain;
  out.owner = b?.on_chain?.owner_account || null;
  out.tokenId = b?.token_id ?? null;
  if (!out.found) out.reasons.push("not in the Agent Registry");
  else if (!out.active) out.reasons.push(`registry status ${STATUSES.has(String(b?.on_chain?.status)) ? b.on_chain.status : "unknown"}`);
  if (out.found && !out.cardMatches) out.reasons.push("Agent Card does not match its on-chain hash");
  if (out.found && out.tokenId != null) {
    try { const w = await call("get_agent_wallet", { token_id: out.tokenId, network }); out.agentWallet = (typeof w === "string" ? w : w?.agent_wallet ?? w?.wallet ?? null) || null; }
    catch { out.agentWallet = null; }
  }
  // payTo must be the badge's registered agent wallet or owner (on chain): the money can only reach that account.
  const allowed = [out.agentWallet, out.owner].filter(Boolean);
  out.walletMatches = typeof payTo === "string" && allowed.includes(payTo);
  if (!out.walletMatches) out.reasons.push(payTo ? "x402 payTo is not this agent's registered wallet or owner" : "no x402 payTo given");
  // Endpoint binding: the endpoint we are about to pay serves the on-chain-hashed card for this badge and this payTo.
  const onChainHash = String(b?.on_chain?.metadata_hash_hex || "").toLowerCase();
  if (out.found) {
    if (!origin) out.reasons.push("seller endpoint unknown: the badge can't be bound to it");
    else if (!/^[0-9a-f]{64}$/.test(onChainHash)) out.reasons.push("registry gave no on-chain Agent Card hash");
    else {
      let buf = null;
      try { buf = await fetchCard(origin); } catch (e) { out.reasons.push(`seller endpoint serves no Agent Card${httpOf(e)}`); }
      if (buf) {
        const h = crypto.createHash("sha256").update(buf).digest("hex");
        let params = null;
        try { params = JSON.parse(buf.toString("utf8"))?.capabilities?.extensions?.find((x) => /concordium-badge/.test(String(x?.uri)))?.params || null; } catch { params = null; }
        const cardWallets = params ? [lastPart(params.agentWallet), lastPart(params.owner?.account)].filter(Boolean) : [];
        if (h !== onChainHash) out.reasons.push("the Agent Card served by the seller endpoint does not match the on-chain hash");
        else if (!params || !String(params.tokenAddress || "").endsWith(`cis-2:${badge}`)) out.reasons.push("the seller endpoint's Agent Card is for another agent");
        else if (!cardWallets.includes(payTo)) out.reasons.push("the seller endpoint's Agent Card does not name the payTo account");
        else {
          // Key proof: only the holder of the payTo account's key can sign a fresh challenge naming this origin.
          const nonce = crypto.randomBytes(16).toString("hex");
          const message = proofMessage({ badge, origin, account: payTo, nonce });
          let p = null, good = false;
          let noProof = false;
          try { p = await fetchProof(origin, nonce); } catch (e) {
            noProof = httpOf(e) === " (HTTP 404)";
            // Origin-bound tier: only for an origin the operator pinned, only when no proof is served at all.
            let uriOrigin = null; try { uriOrigin = new URL(String(b?.on_chain?.agent_uri || "")).origin; } catch { uriOrigin = null; }
            if (allowOriginTier && noProof && uriOrigin === origin && out.agentWallet && payTo === out.agentWallet) out.originBound = true;
            else if (allowOriginTier && noProof) out.reasons.push(`origin-bound tier refused: ${uriOrigin !== origin ? "the registered agent_uri is not on the origin being paid" : "payTo is not the registered agent wallet"}`);
            else out.reasons.push(`the seller endpoint gives no key proof${httpOf(e)}`);
          }
          if (p) {
            if (p.message !== undefined && p.message !== message) out.reasons.push("the seller endpoint's key proof names another origin, badge or account");
            else if (p.account !== payTo || !p.signature || typeof p.signature !== "object") out.reasons.push("the seller endpoint's key proof is not for the payTo account");
            // credential and key indexes must be canonical ("0", not "00"): the SDK counts object keys toward the thresholds
            else if (!canonicalSig(p.signature)) out.reasons.push("the seller endpoint's key proof has a malformed signature");
            else {
              try { good = await verifyProof(message, p.signature, payTo); } catch (e) { out.reasons.push(`key proof could not be checked (fail closed)`); good = null; }
              if (good === false) out.reasons.push("the seller endpoint's key proof is not signed by the payTo account");
            }
          }
          out.endpointBound = good === true;
        }
      }
    }
  }
  // Last, and only when everything else passed (one more node read): a verified human stands behind the owner account.
  const bound = out.endpointBound || out.originBound;
  if (out.found && out.active && out.cardMatches && out.walletMatches && bound) {
    let id;
    try { id = out.owner ? await ownerIdentity(out.owner) : { ok: false, reason: "registry gave no owner account" }; }
    catch { id = { ok: false, reason: "the owner's identity could not be read from the chain (fail closed)" }; }
    out.ownerVerified = id?.ok === true;
    if (out.ownerVerified) out.ownerIdp = { id: id.idp, name: id.idpName, validTo: id.validTo };
    else out.reasons.push(id?.reason || "the owner's identity is not verified");
  }
  out.ok = out.found && out.active && out.cardMatches && out.walletMatches && bound && out.ownerVerified;
  out.tier = out.endpointBound ? "key-proof" : out.originBound ? ORIGIN_TIER : null;
  return out;
}
