// Minimal Telegraph client: one paid ask over x402 with hard spending limits.
import { wrapFetchWithPayment } from "@x402/fetch";
import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm";
import { privateKeyToAccount } from "viem/accounts";
import { config } from "./config.mjs";
import { append, spentToday } from "./ledger.mjs";

let paidFetch, payer, lastSigned = null;
// The x402 refusal check, exported for tests. Fixed text only: the node's own field values are never echoed (errors land in the ledger,
// whose error lines are public).
export function x402Refusal(r) {
  const bad = r?.scheme !== "exact" ? "scheme" : r.network !== config.network ? "network"
    : String(r.asset).toLowerCase() !== String(config.assets[config.network]).toLowerCase() ? "asset"
    : !AMOUNT.test(String(r.amount)) ? "amount" : Number(r.amount) > config.maxPerCall ? `amount over the per-call cap ${config.maxPerCall}` : null;
  return bad ? `refused before signing: ${bad}` : null;
}
export class BudgetError extends Error { name = "BudgetError"; }
export class PaymentRefused extends Error { name = "PaymentRefused"; }
const AMOUNT = /^[1-9][0-9]{0,15}$/;   // micro-USDC, positive integer, nothing else

// Counts a payment against the daily cap before it is signed. Synchronous: no other call can slip in between.
function reserve(amount, info) {
  if (spentToday() + amount > config.maxPerDay) throw new BudgetError(`daily cap ${config.maxPerDay} uUSDC reached`);
  append({ kind: "signed", amount_uusdc: amount, ...info });
  lastSigned = amount;
}

// x402 exact rail: the network, asset and amount are checked by us before the library signs anything.
function client() {
  if (paidFetch) return paidFetch;
  const key = process.env.TELEGRAPH_PAYER_KEY;
  if (!key) throw new Error("TELEGRAPH_PAYER_KEY is not set (use a testnet-only key)");
  const account = privateKeyToAccount(key);
  payer = account.address;
  const c = x402Client.fromConfig({
    schemes: [{ network: config.network, client: new ExactEvmScheme(account) }],
    spendControls: { allowedAssets: [{ network: config.network, asset: config.assets[config.network], maxAmountPerPayment: String(config.maxPerCall) }] },
  });
  c.onBeforePaymentCreation(async ({ selectedRequirements: r }) => {
    const reason = x402Refusal(r);
    if (reason) return { abort: true, reason };
    try { reserve(Number(r.amount), { rail: "x402", network: r.network, asset: r.asset, payTo: r.payTo }); }
    catch (e) { return { abort: true, reason: e.message }; }
  });
  paidFetch = wrapFetchWithPayment(fetch, c);
  return paidFetch;
}

// Escrow rail (Ethereum Sepolia): prepaid balance on the Telegraph Diamond, one EIP-191 signature
// per request, no facilitator in the path. Enabled with GG_RAIL=escrow.
// The message to sign is built here from checked fields; the node's quoted message must equal it exactly,
// so a node can't slip a different amount, payee or extra text into what we sign.
export const ESCROW_NETWORK = "eip155:11155111";
export const ESCROW_PAYTO = (process.env.TELEGRAPH_ESCROW_PAYTO || "0x72a70e949362670bf8bcead24efc5b8f950aa08b").toLowerCase();
const ESCROW_RESOURCE = "/v1/ask";
export function escrowMessage({ from, payTo, network, amount, resource, nonce, validAfter, validBefore }) {
  return `Telegraph Escrow Payment\n\nWallet: ${from}\nPay To: ${payTo}\nNetwork: ${network}\nAmount: ${amount} uUSDC\nResource: ${resource}\nNonce: ${nonce}\nValid After: ${validAfter}\nValid Before: ${validBefore}`;
}
let escrowAccount;
function escrowFetch(maxPerCall) {
  if (!escrowAccount) {
    const key = process.env.TELEGRAPH_PAYER_KEY;
    if (!key) throw new Error("TELEGRAPH_PAYER_KEY is not set (use a testnet-only key)");
    escrowAccount = privateKeyToAccount(key);
    payer = escrowAccount.address;
  }
  return async (url, init) => {
    const first = await fetch(url, init);
    if (first.status !== 402) return first;
    const h = first.headers.get("payment-required");
    const ch = h ? JSON.parse(Buffer.from(h, "base64").toString("utf8")) : await first.json();
    const opt = (ch.accepts || []).find((a) => a.scheme === "escrow" && a.network === ESCROW_NETWORK);
    if (!opt) throw new PaymentRefused(`node offered no escrow option on ${ESCROW_NETWORK}`);
    const amount = String(opt.amount ?? "");
    if (!AMOUNT.test(amount)) throw new PaymentRefused("escrow amount is not a positive integer");
    if (String(opt.payTo).toLowerCase() !== ESCROW_PAYTO) throw new PaymentRefused(`escrow payTo is not the escrow contract ${ESCROW_PAYTO}`);
    if (Number(amount) > maxPerCall) throw new BudgetError(`escrow quote ${amount} exceeds per-call cap ${maxPerCall}`);
    const now = Math.floor(Date.now() / 1000);
    const authorization = { from: escrowAccount.address.toLowerCase(), to: ESCROW_PAYTO, value: amount,
      validAfter: String(now - 5), validBefore: String(now + 90), nonce: `gg-${now}-${Math.random().toString(36).slice(2, 10)}` };
    const message = escrowMessage({ from: authorization.from, payTo: ESCROW_PAYTO, network: ESCROW_NETWORK, amount, resource: ESCROW_RESOURCE,
      nonce: authorization.nonce, validAfter: authorization.validAfter, validBefore: authorization.validBefore });
    const quoted = String(opt.extra?.message ?? "").replace("{from}", authorization.from).replace("{nonce}", authorization.nonce)
      .replace("{validAfter}", authorization.validAfter).replace("{validBefore}", authorization.validBefore);
    if (quoted !== message) throw new PaymentRefused("the node's escrow message differs from the one built locally: not signed");
    reserve(Number(amount), { rail: "escrow", network: ESCROW_NETWORK, payTo: ESCROW_PAYTO, nonce: authorization.nonce });
    const signature = await escrowAccount.signMessage({ message });
    const xp = Buffer.from(JSON.stringify({ x402Version: 2, scheme: "escrow", network: ESCROW_NETWORK, payload: { signature, authorization } })).toString("base64");
    return fetch(url, { ...init, headers: { ...init.headers, "X-PAYMENT": xp } });
  };
}

/** Buy one answer for `intent`. Returns { result, receipt, cost_usd, miner_id, ms }. Throws on failure. */
export async function ask(intent, params, { budget = config.maxPerCall, purpose = "" } = {}) {
  if (budget > config.maxPerCall) throw new BudgetError(`budget ${budget} exceeds per-call cap ${config.maxPerCall}`);
  if (spentToday() + budget > config.maxPerDay) throw new BudgetError(`daily cap ${config.maxPerDay} uUSDC reached`);
  const f = config.rail === "escrow" ? escrowFetch(config.maxPerCall) : client();
  const t0 = Date.now();
  const ctrl = AbortSignal.timeout(config.timeoutMs);
  lastSigned = null;
  let res;
  try {
    res = await f(`${config.node}/engine/v1/ask`, {
      method: "POST", signal: ctrl,
      headers: { "Content-Type": "application/json" },
      // A multi-miner budget needs a refundable rail (Sepolia escrow/diamond); on Base Sepolia the node
      // rejects it, so there we buy a single routed answer at the base price.
      body: JSON.stringify(config.rail === "escrow" || config.network === "eip155:11155111" ? { intent, params, max_budget_usdc: budget } : { intent, params }),
    });
  } catch (e) {
    append({ kind: "error", intent, params, purpose, error: String(e.message || e), signed_uusdc: lastSigned });
    throw e;
  }
  const ms = Date.now() - t0;
  const text = await res.text();
  let body; try { body = JSON.parse(text); } catch { body = { raw: text.slice(0, 500) }; }
  const rh = res.headers.get("x-telegraph-receipt") || res.headers.get("x-payment-response");
  const receipt = rh ? JSON.parse(Buffer.from(rh, "base64").toString("utf8")) : null;
  if (res.status !== 200 || !receipt) {
    append({ kind: "error", intent, params, purpose, status: res.status, body, ms, signed_uusdc: lastSigned });
    throw new Error(`Telegraph ${intent} failed: HTTP ${res.status} ${JSON.stringify(body).slice(0, 200)}`);
  }
  append({ kind: "purchase", intent, params, purpose, payer, network: config.rail === "escrow" ? "eip155:11155111" : config.network, rail: config.rail, miner_id: body.miner_id,
    // what we signed is what counts; the receipt's own figure is kept beside it
    cost_usd: body.cost_usd, amount_uusdc: lastSigned ?? 0, signed: lastSigned != null, receipt_amount_uusdc: Number(receipt.amount_uusdc || 0), receipt, result: body.result,
    field_status: body.field_status, ms });
  return { result: body.result || {}, receipt, cost_usd: body.cost_usd, miner_id: body.miner_id, field_status: body.field_status, ms };
}
