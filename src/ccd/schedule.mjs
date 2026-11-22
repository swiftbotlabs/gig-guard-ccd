// The scheduled job (run by a timer, e.g. every 3 hours): re-check the agents Gig Guard pays, log it, re-anchor the log.
//
//   node src/ccd/schedule.mjs <own token id> <audit.jsonl> <seller badge> [more badges...] [--dry-run]
//
// 1. Reads the head already anchored on chain and checks the log still reaches it. If it doesn't (an anchored entry was
//    edited, removed, or the whole log was re-hashed), it stops: nothing is logged, nothing is anchored, exit 11.
// 2. Re-checks each seller in the registry (status, card hash) and its owner's identity credential, read-only, and logs one
//    "recheck" decision per seller: a seller that is no longer accountable shows up in the log within one period.
// 3. Re-anchors the grown log (one registry metadata update, fee paid in test CCD on testnet).
// --dry-run does 1 and 2 against a copy of the log and signs nothing.
// Env: GG_CCD_KEYFILE (own key), GG_CCD_ANCHOR_KEY, GG_CCD_BADGE / GG_CCD_OWNER (named in each entry), GG_LIVE_LOG.
// GG_SCHEDULE_UNTIL (ISO time): after it, the job does nothing (so a published copy of the log stays current).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mcpCall, NETWORK, checkOwnerIdentity } from "./registry.mjs";
import { record } from "./audit.mjs";
import { anchorKey, readAnchor, anchorIfSafe } from "./anchor.mjs";
import { planAnchor } from "./audit.mjs";

const args = process.argv.slice(2);
const dryRun = args.includes("--dry-run");
const [tokenId, file, ...badges] = args.filter((x) => x !== "--dry-run");
const BADGE = /^[1-9A-HJ-NP-Za-km-z]{12,40}$/;
if (!/^\d+$/.test(tokenId || "") || !file || !badges.length || !badges.every((b) => BADGE.test(b))) {
  console.error("usage: schedule.mjs <own token id> <audit.jsonl> <seller badge>... [--dry-run]"); process.exit(2);
}
const until = process.env.GG_SCHEDULE_UNTIL ? Date.parse(process.env.GG_SCHEDULE_UNTIL) : NaN;
if (Number.isFinite(until) && Date.now() > until) { console.log(JSON.stringify({ at: new Date().toISOString(), action: "off", reason: "after GG_SCHEDULE_UNTIL" })); process.exit(0); }

const key = anchorKey();
const out = { at: new Date().toISOString(), network: NETWORK, key, dry_run: dryRun };
let log = file;
if (dryRun) { log = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "gg-sched-")), "audit.jsonl"); if (fs.existsSync(file)) fs.copyFileSync(file, log); }

// 1. Never build on a rewritten log.
const current = await readAnchor(tokenId, key).catch(() => undefined);
if (current === undefined) { console.log(JSON.stringify({ ...out, action: "refuse", reason: "registry unreachable: could not read the anchored head (fail closed)" })); process.exit(12); }
const before = planAnchor(log, current);
if (before.action === "refuse") { console.log(JSON.stringify({ ...out, previous: current, action: "refuse", reason: before.reason })); process.exit(11); }

// 2. Re-check each seller, read-only, and log it.
out.rechecks = [];
for (const badge of badges) {
  const row = { seller_badge: badge };
  try {
    const b = await mcpCall("check_badge", { id: badge, network: NETWORK });
    const c = b?.checks || {};
    Object.assign(row, { found: !!c.on_chain_agent_found, registry_status: String(b?.on_chain?.status || "unknown").replace(/[^\w]/g, "").slice(0, 20), card_matches: !!c.hash_matches_on_chain });
    const owner = b?.on_chain?.owner_account;
    const id = owner ? await checkOwnerIdentity(owner) : { ok: false };
    Object.assign(row, { seller_owner: owner || null, owner_verified: id.ok === true, owner_idp: id.ok ? id.idpName : null });
  } catch { row.registry_error = "unreachable or malformed (fail closed)"; }
  row.verdict = row.found && row.registry_status === "Active" && row.card_matches && row.owner_verified ? "still accountable" : "would be refused";
  record("decision", { gate: "recheck", ...row }, { file: log });
  out.rechecks.push({ badge, verdict: row.verdict, status: row.registry_status ?? null });
}

// 3. Re-anchor (reads the head again, so a change between steps 1 and 3 is caught too).
const r = await anchorIfSafe(tokenId, log, dryRun ? null : (await import("./rail.mjs")).loadAccount(), { key, dryRun });
console.log(JSON.stringify({ ...out, ...r }));
process.exit(r.action === "refuse" ? 11 : r.action === "anchor" && !dryRun && !r.ok ? 1 : 0);
