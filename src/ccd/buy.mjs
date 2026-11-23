// One paid call to any x402 seller on Concordium, through every Gig Guard check (registry, card, caps, audit log).
//   node src/ccd/buy.mjs <url> <request-body.json>      -> one JSON line: ok, refused, status, tx, explorer, tier, reason_code
// The seller's reply and any error text are untrusted: they go to <GG_AUDIT>.response.json (marked untrusted), never to stdout.
// Needs GG_CCD_KEYFILE (the paying account) and GG_AUDIT (the log). For an outside seller that serves no key proof, pin its
// origin to its badge with GG_CCD_ORIGIN_TIER="https://seller.example=<badge>" (origin-bound tier: 1 CCD/call, 2 CCD/day).
import fs from "node:fs";
import { buyCcd } from "./rail.mjs";

const [url, bodyFile] = process.argv.slice(2);
if (!url || !/^https:\/\//.test(url)) { console.error("usage: node src/ccd/buy.mjs <https url> [request-body.json]"); process.exit(2); }
const body = bodyFile ? JSON.parse(fs.readFileSync(bodyFile, "utf8")) : undefined;
const auditFile = process.env.GG_AUDIT;
if (!auditFile) { console.error("set GG_AUDIT to the audit log path"); process.exit(2); }
const r = await buyCcd(url, { body, purpose: process.env.GG_PURPOSE || "outside-seller", auditFile });
const code = r.ok ? "ok" : r.refused ? "refused" : r.status ? `http_${Number(r.status)}` : "error";
// Refusal reasons are our own fixed text (rail.mjs); other errors can quote the seller, so they stay in the file.
fs.writeFileSync(auditFile + ".response.json", JSON.stringify({ untrusted_seller_data: true, status: r.status ?? null, body: r.body ?? null, error: r.refused ? null : r.reason ?? null }, null, 1));
console.log(JSON.stringify({ ok: r.ok, refused: !!r.refused, status: Number(r.status) || null, tx: r.tx ?? null, explorer: r.explorer ?? null,
  tier: r.trust_tier ?? null, reason_code: code, refusal: r.refused ? String(r.reason).replace(/[^\w .,:;()'"=<>/-]/g, "").slice(0, 400) : null }));
process.exit(r.ok ? 0 : 1);
