// Identity attribute proof (Concordium ID, zero-knowledge): before a seller serves a buyer, or a buyer pays a seller, the other
// side can be asked to PROVE an attribute of the identity behind its account (for example "18 or older") without revealing it.
// The proof is a Concordium Verifiable Presentation (VerifiablePresentationV1) made by the holder's wallet from an identity
// issued by a Concordium identity provider; we verify it with the SDK against a node (verifyWithNode: the ZK proofs, the
// credential's on-chain metadata and its status) and then check, ourselves, that it answers OUR challenge:
//   1. the presentation's context carries the exact nonce and connection id we issued (single use, 10-minute expiry: no replay);
//   2. every statement we asked for is proven (a weaker one, e.g. a later date-of-birth bound, does not count);
//   3. every credential is Active and issued by an accepted identity provider (GG_CCD_IDP_ALLOW; testnet's id 0 issues test
//      identities without document checks, see docs/MAINNET.md).
// Anything else, including any error from the SDK or the node, is a refusal (fail closed). Nothing personal is stored: only
// the verdict, the provider index and the proven statement types.
import crypto from "node:crypto";
import { VerificationRequestV1, VerifiablePresentationV1 } from "@concordium/web-sdk";

const NETWORK = process.env.GG_CCD_NETWORK === "mainnet" ? "Mainnet" : "Testnet";
const ALLOW_IDP = (process.env.GG_CCD_IDP_ALLOW || "").split(",").map((x) => x.trim()).filter(Boolean).map(Number);
export const CHALLENGE_TTL_MS = 600000;

/** The date-of-birth bound that "at least `age` years old on `now`" means (YYYYMMDD string, inclusive). */
export function dobCutoff(age, now = new Date()) {
  const d = new Date(Date.UTC(now.getUTCFullYear() - age, now.getUTCMonth(), now.getUTCDate()));
  return d.toISOString().slice(0, 10).replace(/-/g, "");
}

const hex = (v) => {
  if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
  if (typeof v === "string") return /^[0-9a-f]+$/i.test(v) ? v.toLowerCase() : null;
  if (v && typeof v === "object" && Object.keys(v).every((k) => /^\d+$/.test(k))) return Buffer.from(Object.values(v)).toString("hex");
  return null;
};

/** Issues challenges and checks presentations against them. One instance per service (in memory, bounded). */
export function idProofGate({ minAge = Number(process.env.GG_CCD_ID_MIN_AGE || 18), resource = "gig-guard", allow = ALLOW_IDP, network = NETWORK,
  verifyWithNode = null, now = () => new Date(), max = 1000 } = {}) {
  const open = new Map();   // nonce hex -> { connectionId, at }

  function challenge(connectionId) {
    if (typeof connectionId !== "string" || !/^[\w.:-]{1,128}$/.test(connectionId)) throw new Error("connection id: 1-128 word characters");
    const nonce = crypto.randomBytes(32);
    open.set(nonce.toString("hex"), { connectionId, at: now().getTime() });
    while (open.size > max) open.delete(open.keys().next().value);
    const context = VerificationRequestV1.createSimpleContext(new Uint8Array(nonce), connectionId, resource);
    const claims = VerificationRequestV1.claimsBuilder().addAccountOrIdentityClaims([], (b) => b.addMinimumAge(minAge)).getClaims();
    return { nonce: nonce.toString("hex"), connectionId, resource, minAge, context, claims, expiresAt: new Date(now().getTime() + CHALLENGE_TTL_MS).toISOString() };
  }

  async function check(presentationJson, connectionId) {
    const refuse = (reason) => ({ ok: false, reason });
    let p;
    if (typeof presentationJson === "string" && presentationJson.length > 65536) return refuse("presentation missing or too large");
    try { p = typeof presentationJson === "string" ? JSON.parse(presentationJson) : presentationJson; } catch { return refuse("presentation is not JSON"); }
    if (!p || typeof p !== "object" || JSON.stringify(p).length > 65536) return refuse("presentation missing or too large");
    // 1. our challenge, once
    const given = p.presentationContext?.given || [];
    const get = (label) => given.find((g) => g?.label === label)?.context;
    const nonce = hex(get("Nonce")), conn = get("ConnectionID");
    const ch = nonce && open.get(nonce);
    if (!ch) return refuse("nonce unknown, expired or already used (replay)");
    open.delete(nonce);   // single use, whatever the outcome
    if (now().getTime() - ch.at > CHALLENGE_TTL_MS) return refuse("challenge expired");
    if (conn !== ch.connectionId || (connectionId !== undefined && conn !== connectionId)) return refuse("presentation was made for another connection");
    if (get("ResourceID") !== resource) return refuse("presentation was made for another resource");
    // 2. the SDK checks the zero-knowledge proofs, the credentials' on-chain metadata and status against a node
    let v;
    try {
      const vp = VerifiablePresentationV1.fromJSON(p);
      v = verifyWithNode ? await verifyWithNode(vp, network) : await defaultVerify(vp, network);
    } catch (e) { return refuse(`presentation could not be verified (fail closed): ${String(e?.message || e).slice(0, 120)}`); }
    if (v?.type !== "success") return refuse(`proof verification failed: ${String(v?.error?.message || v?.error || "unknown").slice(0, 120)}`);
    const statuses = v.result?.credentialsStatus || [];
    // CredentialStatus: Active = 0 (Revoked 1, Expired 2, NotActivated 3)
    if (!statuses.length || statuses.some((s) => s !== 0 && s !== "Active")) return refuse(`credential not active (${statuses.join(",") || "none"})`);
    // 3. the proven statements must include ours, from an accepted identity provider
    const claims = v.result?.request?.subjectClaims || [];
    const cutoff = dobCutoff(minAge, now());
    const idpOf = (c) => Number(String(c?.issuer || "").match(/:idp:(\d+)$/)?.[1]);
    const ageProven = claims.some((c) => (c.statement || []).some((s) => s?.type === "AttributeInRange" && s.attributeTag === "dob"
      && /^\d{8}$/.test(String(s.upper)) && String(s.upper) <= cutoff));
    if (!ageProven) return refuse(`no proof that the holder is at least ${minAge}`);
    const idps = claims.map(idpOf);
    if (idps.some((i) => !Number.isInteger(i)) || (allow.length && idps.some((i) => !allow.includes(i)))) return refuse(`identity provider not accepted (${idps.join(",")})`);
    return { ok: true, idp: idps[0], proven: [`age >= ${minAge}`], reason: null };
  }
  return { challenge, check, pending: () => open.size };
}

async function defaultVerify(vp, network) {
  const { nodeClient } = await import("./chaintx.mjs");
  return VerifiablePresentationV1.verifyWithNode(vp, nodeClient(), network);
}
