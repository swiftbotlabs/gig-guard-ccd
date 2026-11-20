// Accountability record in the spirit of EU AI Act Art. 12 (record keeping): every decision and payment the
// agent makes is appended as one JSON line, chained by SHA-256 so any edit or deletion breaks the chain.
// Each entry names the accountable parties: the agent's own registry badge and its owner account.
import fs from "node:fs";
import crypto from "node:crypto";
import { dataFile, ensureDir } from "../paths.mjs";

export const AUDIT_FILE = process.env.GG_AUDIT || dataFile("audit.jsonl");
export const SELLER_AUDIT_FILE = dataFile("seller-audit.jsonl");
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const canon = (o) => JSON.stringify(sortDeep(o));
function sortDeep(v) { return Array.isArray(v) ? v.map(sortDeep) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])])) : v; }

function lastHash(file) {
  if (!fs.existsSync(file)) return "0".repeat(64);
  const lines = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
  return lines.length ? JSON.parse(lines[lines.length - 1]).hash : "0".repeat(64);
}

// kind: decision | payment | refusal | approval | kill
export function record(kind, data, { file = AUDIT_FILE, agent = process.env.GG_CCD_BADGE || null, owner = process.env.GG_CCD_OWNER || null } = {}) {
  const body = { seq: undefined, ts: new Date().toISOString(), kind, agent_badge: agent, owner_account: owner, ...data, prev: lastHash(file) };
  body.seq = fs.existsSync(file) ? fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean).length : 0;
  const hash = sha(canon(body));
  ensureDir(file);
  fs.appendFileSync(file, JSON.stringify({ ...body, hash }) + "\n");
  return hash;
}

// Recomputes the chain. Returns {ok, entries, brokenAt, reason}.
export function verifyAudit(file = AUDIT_FILE) {
  if (!fs.existsSync(file)) return { ok: true, entries: 0 };
  const lines = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
  let prev = "0".repeat(64);
  for (let i = 0; i < lines.length; i++) {
    const { hash, ...body } = JSON.parse(lines[i]);
    if (body.prev !== prev) return { ok: false, entries: lines.length, brokenAt: i, reason: "prev hash does not match the line before (entry removed or reordered)" };
    if (body.seq !== i) return { ok: false, entries: lines.length, brokenAt: i, reason: "sequence gap" };
    if (sha(canon(body)) !== hash) return { ok: false, entries: lines.length, brokenAt: i, reason: "entry edited after it was written" };
    prev = hash;
  }
  return { ok: true, entries: lines.length, head: prev };
}

// Checks the log against an anchored head "N:hash" (as written by `setup.mjs anchor`): the first N entries
// must still verify and entry N-1 must still carry that hash. Later entries may follow; earlier ones can't change.
export function verifyAnchor(file = AUDIT_FILE, anchored) {
  const m = /^(\d+):([0-9a-f]{64})$/.exec(String(anchored || "").trim());
  if (!m) return { ok: false, reason: "no valid anchor (expected entries:hash)" };
  const n = Number(m[1]), head = m[2];
  const v = verifyAudit(file);
  if (!v.ok && v.brokenAt < n) return { ok: false, reason: `log broken at entry ${v.brokenAt}, inside the anchored part: ${v.reason}` };
  const lines = fs.existsSync(file) ? fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean) : [];
  if (lines.length < n) return { ok: false, reason: `log has ${lines.length} entries, the anchor covers ${n}: entries were removed` };
  if (n && JSON.parse(lines[n - 1]).hash !== head) return { ok: false, reason: `entry ${n - 1} no longer has the anchored hash` };
  return { ok: true, anchored_entries: n, total_entries: lines.length, after_anchor: lines.length - n, tail_ok: v.ok };
}
