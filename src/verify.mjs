// Third-party receipt check. Escrow receipts settle in the epoch's ledger block:
//   GET {node}/v1/blocks/{epoch_id}/deliveries/{receipt_hash}
// SETTLED  = the block lists this delivery with our payer, intent and amount.
// PENDING  = the epoch's block isn't recorded yet (testnet: up to ~1 h after the 3 h epoch window closes).
// MISMATCH = the node returned a delivery that doesn't match the receipt we were given.
import { config } from "./config.mjs";
import { readLedger } from "./ledger.mjs";

export async function verifyReceipt(rc, node = config.node) {
  // only a well-formed hash and an integer epoch are looked up or copied out (both come from the node's receipt header)
  const h = /^0x[0-9a-fA-F]{64}$/.test(String(rc?.receipt_hash)) ? rc.receipt_hash : null;
  const e = Number.isInteger(rc?.epoch_id) && rc.epoch_id >= 0 ? rc.epoch_id : null;
  if (!h) return { receipt_hash: null, status: "INVALID", note: "receipt hash is not 0x + 64 hex" };
  if (e === null) return { receipt_hash: h, status: "NO_EPOCH", note: "receipt has no epoch (x402 exact receipts settle by tx instead)" };
  let r, j;
  try { r = await fetch(`${node}/v1/blocks/${e}/deliveries/${h}`, { signal: AbortSignal.timeout(15000) }); j = await r.json(); }
  catch { return { receipt_hash: h, epoch_id: e, status: "UNREACHABLE", note: "node unreachable" }; }
  // node text is never copied out: a fixed note per status, and miner ids only when numeric/hex
  if (!r.ok) return { receipt_hash: h, epoch_id: e, status: /no block recorded/.test(j?.error || "") ? "PENDING" : "NOT_FOUND", note: `HTTP ${r.status}` };
  const d = j.delivery || {};
  const bad = [];
  if (rc.payer && d.payer?.toLowerCase() !== rc.payer.toLowerCase()) bad.push("payer");
  if (rc.intent && d.intent !== rc.intent) bad.push("intent");
  if (rc.amount_uusdc && Number(d.usdc) !== Number(rc.amount_uusdc)) bad.push("amount");
  return { receipt_hash: h, epoch_id: e, status: bad.length ? "MISMATCH" : "SETTLED", mismatch: bad, miner_id: /^(0x)?[0-9a-fA-F]{1,64}$/.test(String(d.miner_id ?? "")) ? String(d.miner_id) : undefined, usdc: Number.isFinite(Number(d.usdc)) ? Number(d.usdc) : undefined,
    deliveries_root: /^0x[0-9a-fA-F]{1,64}$/.test(String(j.deliveries_root)) ? j.deliveries_root : undefined, block_data_root: /^0x[0-9a-fA-F]{1,64}$/.test(String(j.block_data_root)) ? j.block_data_root : undefined, proof_len: Array.isArray(j.proof) ? j.proof.length : 0 };
}
export async function verifyLedger(entries = readLedger()) {
  const out = [];
  for (const b of entries.filter((x) => x.kind === "purchase" && x.receipt?.receipt_hash)) out.push({ intent: b.intent, ...(await verifyReceipt(b.receipt)) });
  const n = (s) => out.filter((x) => x.status === s).length;
  return { total: out.length, settled: n("SETTLED"), pending: n("PENDING"), mismatch: n("MISMATCH"), other: out.length - n("SETTLED") - n("PENDING") - n("MISMATCH"), receipts: out };
}
