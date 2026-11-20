// Public output never carries real client names, receiving wallets, tx hashes or link targets.
// The private ledger.jsonl keeps them (the agent needs them); the page and `export` go through here.
// A queue item may set `label` ("Payment A"); otherwise clients become "Client A", "Client B", ... by first appearance.
import { readLedger } from "./ledger.mjs";

const PAYER = (process.env.GG_PAYER_PUBLIC || "").toLowerCase(); // our own payer address may stay visible
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const short = (h) => `${h.slice(0, 6)}…${h.slice(-4)}`;
// Already-neutral names ("Payment B", "Client A") are kept; generic words never count as a client's name.
const NEUTRAL = /^(payment|client|lead)( [a-z0-9])?$/i;
const GENERIC = new Set(["payment", "payments", "lead", "client", "clients", "team", "labs", "protocol", "network", "foundation", "chain", "finance"]);

export function makeRedactor(entries = readLedger()) {
  const labels = new Map();
  // Explicit labels first (a queue item's "label"), then automatic ones by first appearance.
  for (const e of entries) {
    const s = e.kind === "decision" && e.input?.client;
    if (s && e.input.label && !NEUTRAL.test(s.trim()) && !labels.has(s.toLowerCase())) labels.set(s.toLowerCase(), e.input.label);
  }
  for (const e of entries) {
    const s = e.kind === "decision" && e.input?.client;
    if (s && !NEUTRAL.test(s.trim()) && s.trim().length >= 2 && !labels.has(s.toLowerCase())) labels.set(s.toLowerCase(), e.input.label || `Client ${String.fromCharCode(65 + labels.size)}`);
  }
  // Full names first, then distinctive single words (>= 4 letters) of each name.
  const rules = [];
  for (const [name, lab] of labels) {
    rules.push([new RegExp(`\\b${reEsc(name)}\\b`, "gi"), lab]);
    for (const w of name.split(/\s+/).filter((w) => w.length >= 4 && !GENERIC.has(w))) rules.push([new RegExp(`\\b${reEsc(w)}\\w*`, "gi"), lab]);
  }
  const text = (s) => {
    let t = String(s);
    t = t.replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>)]+/gi, "[link]"); // any scheme://... (no client or platform hosts in public output)
    t = t.replace(/0x[0-9a-fA-F]{64}\b/g, (h) => short(h));            // tx hashes in inputs/reasons
    t = t.replace(/0x[0-9a-fA-F]{40}\b/g, (a) => (a.toLowerCase() === PAYER ? a : short(a)));
    t = t.replace(/[\w.+-]+@[\w-]+(\.[\w-]+)+/g, "[email]");                       // e-mail addresses, by value
    t = t.replace(/(?<![0-9A-Za-z])[1-9A-HJ-NP-Za-km-z]{32,60}(?![0-9A-Za-z])/g, (a) => (/^[0-9a-fA-F]+$/.test(a) ? a : short(a)));   // base58 addresses (Solana, Concordium, Tron...)
    for (const [re, lab] of rules) t = t.replace(re, lab);
    return t;
  };
  const deep = (v) => (typeof v === "string" ? text(v) : Array.isArray(v) ? v.map(deep) : v && typeof v === "object" ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, deep(x)])) : v);
  const label = (client) => labels.get(String(client || "").toLowerCase());
  return { text, deep, label };
}

/** Public copy of the ledger. Every field is on an allow-list and typed: free text from miners, sellers, nodes or registries never
 *  reaches it except through reasons/uncertainty (built from fixed templates in the gates) and the redactor. */
const HEX = /^0x[0-9a-fA-F]{64}$/;
const WORD = (v, re = /^[A-Za-z0-9_.:|-]{1,64}$/) => (typeof v === "string" && re.test(v) ? v : undefined);
const NUM = (v) => (typeof v === "number" && Number.isFinite(v) ? v : undefined);
const MINER = /^(0x)?[0-9a-fA-F]{1,64}$/;
// one tight pattern per field: no field accepts general text
const INTENT = /^[A-Z0-9_|]{1,200}( \(free\))?$/, KIND = /^[a-z_]{1,20}$/, PURPOSE = /^[a-z-]{1,20}$/, RAIL = /^(escrow|x402|api-key)$/,
  NETWORK = /^[a-z0-9]{2,12}:[A-Za-z0-9]{1,64}$/, POLICY = /^v\d{1,3}$/, GATE = /^[a-z]{1,10}$/, CHAIN = /^[a-z ]{1,30}$/, TOKEN = /^([A-Za-z0-9.$_-]{1,16}|0x[0-9a-fA-F]{40})$/;   // miner ids are numbers/hex; anything else from the node is dropped
const VERDICTS = new Set(["GO", "CAUTION", "SKIP", "PAID", "CLAIM", "PENDING", "SHIP", "FIX", "HOLD"]);
const KNOWN_ERRORS = new Set(["empty answer", "no supplier delivered"]);
const pubReceipt = (r) => (r && typeof r === "object" ? { receipt_hash: HEX.test(r.receipt_hash) ? r.receipt_hash : undefined, epoch_id: Number.isInteger(r.epoch_id) ? r.epoch_id : undefined,
  tx_hash: HEX.test(r.tx_hash) ? r.tx_hash : undefined, amount_uusdc: NUM(r.amount_uusdc) } : undefined);
const pubError = (x) => (x == null ? undefined : KNOWN_ERRORS.has(x) ? x : /^stale answer/.test(String(x)) ? "stale answer" : "failed");
export function publicLedger(entries = readLedger()) {
  const R = makeRedactor(entries);
  return entries.map((e) => {
    const base = { ts: WORD(e.ts, /^[0-9T:.Z-]{10,30}$/), kind: WORD(e.kind, KIND) };
    if (e.kind === "purchase") {
      return { ...base, intent: WORD(e.intent, INTENT), purpose: WORD(e.purpose, PURPOSE), rail: WORD(e.rail, RAIL), network: WORD(e.network, NETWORK), miner_id: WORD(String(e.miner_id ?? ""), MINER),
        cost_usd: NUM(e.cost_usd), amount_uusdc: NUM(e.amount_uusdc), ms: NUM(e.ms), receipt: pubReceipt(e.receipt),
        payer: PAYER && String(e.payer || "").toLowerCase() === PAYER ? e.payer : undefined };
    }
    if (e.kind === "decision") {
      const inp = e.input || {};
      return { ...base, policy: WORD(e.policy, POLICY), gate: WORD(e.gate, GATE), verdict: VERDICTS.has(e.verdict) ? e.verdict : undefined, action: e.action ? R.text(String(e.action)) : undefined,
        input: R.deep({ client: inp.client ? R.label(inp.client) : undefined, url: inp.url, wallet: inp.wallet, chain: WORD(inp.chain, CHAIN), token: WORD(inp.token, TOKEN), txHash: inp.txHash,
          amountUsd: NUM(inp.amountUsd), dueDate: WORD(inp.dueDate, /^\d{4}-\d{2}-\d{2}$/), name: inp.name, bytes: NUM(inp.bytes), solidity: inp.solidity === true || undefined }),
        reasons: (e.reasons || []).map((x) => R.text(String(x))), uncertainty: (e.uncertainty || []).map((x) => R.text(String(x))),
        receipts: (e.receipts || []).filter((h) => HEX.test(h) || /^ccd:[0-9a-f]{64}$/.test(h)),
        wasted_receipts: (e.wasted_receipts || []).filter((h) => HEX.test(h)),
        cost_usd: NUM(e.cost_usd), cost_ccd: NUM(e.cost_ccd), ms: NUM(e.ms), paid_receipts: NUM(e.paid_receipts),
        evidence: (e.evidence || []).map((x) => ({ intent: WORD(x.intent, INTENT), ok: x.ok === true, miner_id: WORD(String(x.miner_id ?? ""), MINER), cost_usd: NUM(x.cost_usd), reused: HEX.test(x.reused) ? x.reused : x.reused === true || undefined, error: pubError(x.error) })),
        claim_drafted: !!e.claim };
    }
    if (e.kind === "reuse") return { ...base, intent: WORD(e.intent, INTENT), of: HEX.test(e.of) ? e.of : undefined, age_s: NUM(e.age_s) };
    return { ...base, intent: WORD(e.intent, INTENT), error: e.error == null && e.status == null ? undefined : `failed${Number.isInteger(e.status) ? ` (HTTP ${e.status})` : ""}` };
  });
}
