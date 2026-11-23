// Identity attribute proof (Concordium ID, zero-knowledge): before a seller serves a buyer, or a buyer pays a seller, the other
// side can be asked to PROVE an attribute of the identity behind its account (for example "18 or older") without revealing it.
// The proof is a Concordium Verifiable Presentation (VerifiablePresentationV1) made by the holder's wallet from an identity
// issued by a Concordium identity provider; we verify it with the SDK against a node (verifyWithNode: the ZK proofs, the
// credential's on-chain metadata and its status) and then check, ourselves, that it answers OUR challenge:
//   1. the presentation's context carries the exact nonce and connection id we issued (single use, 10-minute expiry: no replay);
//   2. every statement we asked for is proven (a weaker one, e.g. a later date-of-birth bound, does not count);
//   3. every credential is account-based and belongs to the account we asked about (the credential's registration id is looked up
//      on chain and must resolve to that account: an anonymous identity-based proof, or one made by a different account, is refused);
//   4. every credential is inside its validity window ("Active" as the SDK reports it; note the SDK does not report revocation of
//      identity credentials) and issued by an accepted identity provider (GG_CCD_IDP_ALLOW; testnet's id 0 issues test identities
//      without document checks, see docs/MAINNET.md).
// Anything else, including any error from the SDK or the node, is a refusal (fail closed). Nothing personal is stored: only
// the verdict, the provider index and the proven statement types.
import crypto from "node:crypto";
import { VerificationRequestV1, VerifiablePresentationV1, AccountAddress, CredentialRegistrationId } from "@concordium/web-sdk";

const NETWORK = process.env.GG_CCD_NETWORK === "mainnet" ? "Mainnet" : "Testnet";
const ALLOW_IDP = (process.env.GG_CCD_IDP_ALLOW || "").split(",").map((x) => x.trim()).filter(Boolean).map(Number);
export const CHALLENGE_TTL_MS = 600000;
export const PER_ACCOUNT_OPEN = 3;   // open challenges per account: a flood from other clients can't evict a real buyer's challenge

/** An account's key without its alias bytes (all 2^24 aliases of an account sign with the same keys). */
export const accountKey = (base58) => Buffer.from(AccountAddress.fromBase58(base58).decodedAddress.subarray(0, 29)).toString("hex");

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
  verifyWithNode = null, accountOf = null, now = () => new Date(), max = 1000 } = {}) {
  const open = new Map();   // nonce hex -> { connectionId, at }

  function challenge(connectionId) {
    if (typeof connectionId !== "string" || !/^[\w.:-]{1,128}$/.test(connectionId)) throw new Error("connection id: 1-128 word characters");
    const nonce = crypto.randomBytes(32);
    const mine = [...open].filter(([, c]) => c.connectionId === connectionId);
    if (mine.length >= PER_ACCOUNT_OPEN) open.delete(mine[0][0]);   // the account's own oldest, never someone else's
    const entry = { connectionId, at: now().getTime(), asked: null };
    open.set(nonce.toString("hex"), entry);
    for (const [k, c] of open) { if (open.size <= max) break; if (now().getTime() - c.at > CHALLENGE_TTL_MS) open.delete(k); }
    if (open.size > max) { open.delete(nonce.toString("hex")); throw new Error("too many open identity challenges, retry later"); }
    const context = VerificationRequestV1.createSimpleContext(new Uint8Array(nonce), connectionId, resource);
    const claims = VerificationRequestV1.claimsBuilder().addAccountClaims([], (b) => b.addMinimumAge(minAge)).getClaims();
    // The SDK dates the bound with the machine's LOCAL clock: keep the exact bound we asked for, so a proof of our own
    // statement is accepted whatever the time zone (before, a VM ahead of UTC refused every real proof near midnight).
    const up = String(claims?.[0]?.statements?.find((x) => x?.attributeTag === "dob")?.upper || "");
    entry.asked = /^\d{8}$/.test(up) ? up : null;
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
    // CredentialStatus: Active = 0 (Expired 2, NotActivated 3): the validity window
    if (!statuses.length || statuses.some((s) => s !== 0 && s !== "Active")) return refuse(`credential not active (${statuses.join(",") || "none"})`);
    // 3. account-based credentials of the account we challenged
    const claims = v.result?.request?.subjectClaims || [];
    if (!claims.length) return refuse("no claims proven");
    for (const c of claims) {
      if (!Array.isArray(c?.type) || !c.type.includes("ConcordiumAccountBasedSubjectClaims")) return refuse("only account-based proofs are accepted (an identity-based proof is tied to no account)");
      const credId = String(c.id || "").match(/^did:ccd:(?:testnet|mainnet):cred:([0-9a-f]{96})$/i)?.[1];
      if (!credId) return refuse("credential id missing or malformed");
      let acct;
      try { acct = accountOf ? await accountOf(credId) : await defaultAccountOf(credId); } catch { return refuse("credential's account could not be read (fail closed)"); }
      let key; try { key = accountKey(String(acct)); } catch { return refuse("credential's account could not be read (fail closed)"); }
      if (key !== ch.connectionId) return refuse("the proof was made by a different account");
    }
    // 4. the proven statements must include ours, from an accepted identity provider. The SDK's addMinimumAge bound is exclusive
    // (born before the day after the cutoff, e.g. "20081124" for 18 on 2026-11-23), so compare with tomorrow's cutoff.
    // The bound we asked for in this challenge also counts (the SDK computed it on the local clock, see challenge()).
    const computed = dobCutoff(minAge, new Date(now().getTime() + 86400000));
    const cutoff = ch.asked && ch.asked > computed ? ch.asked : computed;
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

async function defaultAccountOf(credId) {
  const { nodeClient } = await import("./chaintx.mjs");
  const info = await nodeClient().getAccountInfo(CredentialRegistrationId.fromHexString(credId));
  return info.accountAddress.address;
}

async function defaultVerify(vp, network) {
  const { nodeClient } = await import("./chaintx.mjs");
  return VerifiablePresentationV1.verifyWithNode(vp, nodeClient(), network);
}
