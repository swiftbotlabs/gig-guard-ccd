// The three gates of an autonomous freelance agent. Each buys intelligence through Telegraph,
// applies a written policy, and returns a decision with the receipts attached.
//   scout: should the agent loop spend effort on this job lead (is its payer real and paying)?
//   claim: a promised payment is overdue: prove it and draft the claim.
//   ship:  is this contract/code deliverable safe to hand over?
import { ask } from "./telegraph.mjs";
import { append, readLedger } from "./ledger.mjs";
import { chainBalance } from "./chain.mjs";
import { balanceQueries, normChain } from "./tokens.mjs";

// Fresh answers are reused instead of paying twice for the same fact (cost per useful outcome).
// TTL per Intent, in minutes; GG_REUSE=0 turns reuse off.
const TTL_MIN = { WALLET_BALANCE_CHECK_GENERAL: 10, ONCHAIN_TX_LOOKUP_GENERAL: 10, CRYPTO_TRANSFER_VERIFY_GENERAL: 10,
  URL_SCAN_VERDICT: 1440, URL_SAFE_GENERAL: 1440, WEB_SEARCH_GENERAL: 360, NEWS_SEARCH_GENERAL: 360,
  SECURITY_REVIEW_GENERAL: 10080, CODE_REVIEW_GENERAL: 10080, CONTRACT_OBLIGATION_AUDIT_GENERAL: 10080 };
const STALE_MIN = 60; // a balance reading older than this is not evidence of "now"
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function reusable(intent, p, need) {
  if (process.env.GG_REUSE === "0" || !TTL_MIN[intent]) return null;
  const cutoff = Date.now() - TTL_MIN[intent] * 60000;
  const hit = readLedger().reverse().find((e) => e.kind === "purchase" && e.intent === intent && same(e.params, p) && Date.parse(e.ts) >= cutoff
    && e.result && (!need || (e.result[need] !== null && e.result[need] !== undefined && e.result[need] !== "")));
  return hit || null;
}
// an answer with no readable as_of counts as stale (fail closed): only a parseable, recent time is fresh
const stale = (r) => { const t = Date.parse(r?.as_of ?? ""); return !Number.isFinite(t) || Date.now() - t > STALE_MIN * 60000; };
const safeSym = (s) => (typeof s === "string" && /^[A-Za-z0-9.$_-]{1,16}$/.test(s) ? s : "");
const safeTime = (s) => { const t = Date.parse(s ?? ""); return Number.isFinite(t) ? new Date(t).toISOString() : "now"; };

// Buy from the first intent in the list that delivers (some intents have thin supply on testnet).
// `need` names the answer field that must be filled for the answer to count (e.g. "balance").
async function buy(intents, params, purpose, need) {
  const tried = [];
  for (const [intent, p] of intents.map((i) => (Array.isArray(i) ? i : [i, params]))) {
    const hit = reusable(intent, p, need);
    if (hit) {
      append({ kind: "reuse", intent, purpose, of: hit.receipt?.receipt_hash, age_s: Math.round((Date.now() - Date.parse(hit.ts)) / 1000) });
      return { ok: true, intent, result: hit.result, receipt: hit.receipt, miner_id: hit.miner_id, cost_usd: 0, ms: 0, reused: hit.receipt?.receipt_hash, tried };
    }
    try {
      const r = await ask(intent, p, { purpose });
      // A paid answer whose fields are all empty is no answer: note it and try the next supplier.
      const vals = Object.entries(r.result || {}).filter(([k]) => !Object.values(p).includes(r.result[k])).map(([, v]) => v);
      const filled = (v) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && !v.length);
      if (need ? !filled(r.result?.[need]) : !vals.some(filled)) { tried.push({ intent, error: "empty answer", receipt: r.receipt?.receipt_hash, cost_usd: r.cost_usd }); continue; }
      if (need && stale(r.result)) { tried.push({ intent, error: `stale answer (as_of ${Number.isFinite(Date.parse(r.result?.as_of ?? "")) ? safeTime(r.result.as_of) : "unreadable"})`, receipt: r.receipt?.receipt_hash, cost_usd: r.cost_usd }); continue; }
      return { ok: true, intent, ...r, tried };
    }
    catch (e) { if (e.name === "BudgetError") throw e; tried.push({ intent, error: String(e.message || e).slice(0, 200) }); }
  }
  return { ok: false, intent: intents.map((i) => (Array.isArray(i) ? i[0] : i)).join("|"), error: "no supplier delivered", tried };
}
function decide(gate, input, verdict, reasons, evidence, extra = {}) {
  const d = { kind: "decision", policy: POLICY, gate, input, verdict, reasons,
    // Telegraph escrow receipt hashes, plus the Concordium transaction of every paid agent call (prefixed ccd:)
    receipts: evidence.filter((e) => e.ok).map((e) => e.receipt?.receipt_hash || (e.tx ? `ccd:${e.tx}` : null)).filter(Boolean),
    // Paid-but-unusable answers cost money too: they count toward the decision cost (honest cost per outcome).
    cost_usd: evidence.reduce((s, e) => s + (e.ok ? Number(e.cost_usd || 0) : 0) + (e.tried || []).reduce((t, x) => t + Number(x.cost_usd || 0), 0), 0),
    wasted_receipts: evidence.flatMap((e) => (e.tried || []).map((x) => x.receipt).filter(Boolean)),
    cost_ccd: evidence.reduce((s, e) => s + Number(e.cost_ccd || 0), 0),   // agent calls paid in CCD (not in cost_usd)
    ms: evidence.reduce((s, e) => s + (e.ms || 0), 0),
    evidence: evidence.map((e) => ({ intent: e.intent, ok: e.ok, result: e.result, error: e.error, tried: e.tried, miner_id: e.miner_id, cost_usd: e.cost_usd, cost_ccd: e.cost_ccd, tx: e.tx, explorer: e.explorer, reused: e.reused, source: e.source })),
    ...extra };
  append(d);
  return d;
}
const lc = (s) => String(s ?? "").toLowerCase();
export const POLICY = "v5"; // decisions record the policy version that made them

/** Triage a job lead found by the agent loop. */
export async function scoutLead({ url, client, amountUsd, label }) {
  const u = new URL(url); // invalid input costs nothing
  if (!client) throw new Error("client name required");
  const q = `${client} payment paid unpaid late payment reviews`; // keyword queries work far better than questions
  const ev = [
    await buy(["URL_SCAN_VERDICT", "URL_SAFE_GENERAL"], { url: u.href }, "scout"),
    await buy([["WEB_SEARCH_GENERAL", { query: q }], ["NEWS_SEARCH_GENERAL", { query: q }]], {}, "scout"),
  ];
  const [link, rep] = ev; const reasons = [], notes = [];   // notes: raw answer text, private (never in public output)
  let verdict = "GO";
  const lv = lc(link.result?.verdict ?? link.result?.safe ?? link.result?.answer);
  if (!link.ok) { verdict = "CAUTION"; reasons.push("link reputation unavailable"); }
  else if (/malicious|phish|unsafe|false/.test(lv)) { verdict = "SKIP"; reasons.push("link flagged by the reputation check"); notes.push(`link: ${lv.slice(0, 200)}`); }
  else if (/suspicious|unknown/.test(lv)) { verdict = "CAUTION"; reasons.push(/suspicious/.test(lv) ? "link reputation: suspicious" : "link reputation: unknown"); notes.push(`link: ${lv.slice(0, 200)}`); }
  const text = lc(`${rep.result?.brief ?? ""} ${rep.result?.answer ?? ""}`);
  if (!rep.ok) { if (verdict === "GO") verdict = "CAUTION"; reasons.push("client payment history unavailable"); }
  else {
    const srcs = (rep.result?.sources || []).map(String);
    const key = lc(client).split(/\s+/)[0];
    const relevant = srcs.filter((s) => lc(s).includes(key)).length + (text.includes(key) ? 1 : 0);
    if (/(unpaid|never paid|not (been |yet )?paid|not (yet )?(received|been received)|still waiting|didn'?t pay|did not pay|no payment|scam|rug ?pull|withheld)/.test(text)) { if (verdict === "GO") verdict = "CAUTION"; reasons.push(`payment red flag${srcs.length ? "" : " (unsourced)"}`); notes.push(`search: ${(rep.result?.brief || text).slice(0, 160)}`); }
    else if (!relevant) { if (verdict === "GO") verdict = "CAUTION"; reasons.push(`no independent record of ${client} paying what it owes (${srcs.length} sources, none mention it)`); }
    else reasons.push(`${relevant} of ${srcs.length} sources mention ${client}; no unpaid-payment reports`); notes.push(`search: ${(rep.result?.brief || text).slice(0, 140)}`);
  }
  if (u.protocol !== "https:") { if (verdict === "GO") verdict = "CAUTION"; reasons.push("not HTTPS"); }
  return decide("scout", { url: u.href, client, amountUsd, label }, verdict, reasons, ev, { notes });
}

/** A promised payment has not arrived. Verify on-chain, read the terms, and draft the claim. */
export async function claimPayment({ wallet, chain, token, txHash, client, amountUsd, termsText, dueDate, contact, label, approved }, { ccd = {} } = {}) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(wallet || "")) throw new Error("wallet must be a 0x address");
  if (txHash && !/^0x[0-9a-fA-F]{64}$/.test(txHash)) throw new Error("tx hash must be 0x + 64 hex chars");
  const ev = [];
  const chk = txHash
    ? await buy([["ONCHAIN_TX_LOOKUP_GENERAL", { tx_hash: txHash, chain }], ["CRYPTO_TRANSFER_VERIFY_GENERAL", { tx_hash: txHash, chain }]], {}, "claim")
    : await buy(balanceQueries(wallet, chain, token || "").map((q) => ["WALLET_BALANCE_CHECK_GENERAL", q]), {}, "claim", "balance");
  ev.push(chk);
  if (termsText) ev.push(await buy([["CONTRACT_OBLIGATION_AUDIT_GENERAL", { contract: termsText.slice(0, 8000) }]], {}, "claim"));
  const reasons = [], uncertainty = [], notes = []; let verdict;   // notes: raw answer text, private (never in public output)
  const r = chk.result || {};
  // Free, deterministic second source for balances: the chain itself.
  let onchain = txHash ? null : await chainBalance(wallet, chain, token);
  if (onchain) ev.push({ ok: true, intent: "CHAIN_READ (free)", result: onchain, source: onchain.source, cost_usd: 0, ms: 0 });
  // Concordium: hire an accountable agent (registry-verified before paying, x402 over Concordium) for a
  // second reading. A seller that can't prove an accountable owner is never paid.
  if (!txHash && process.env.GG_CCD_SELLER_URL) {
    const { buyCcd } = await import("./ccd/rail.mjs");
    const su = new URL(process.env.GG_CCD_SELLER_URL);
    if (su.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(su.hostname)) throw new Error("GG_CCD_SELLER_URL must be https (or a local address)");
    const c = await buyCcd(su.href.replace(/\/$/, "") + "/v1/balance", { body: { address: wallet, chain: normChain(chain), token }, purpose: "claim", ...ccd });
    const sellerBal = c.ok && c.body && c.body.balance !== null && c.body.balance !== undefined && c.body.balance !== "" ? Number(c.body.balance) : NaN;
    if (c.ok && !Number.isFinite(sellerBal)) {   // paid, but no number: the cost still counts, the answer is not evidence
      uncertainty.push("Concordium agent reading unreadable: not used");
      ev.push({ ok: false, intent: "CCD_AGENT_BALANCE", error: "empty answer", tx: c.tx, cost_usd: 0, cost_ccd: c.amount_ccd, ms: c.ms });
    }
    else if (c.ok) {
      // name the badge our registry check verified, never the one the seller writes into its own answer
      ev.push({ ok: true, intent: "CCD_AGENT_BALANCE", result: c.body, source: `Concordium agent ${c.seller_badge}`, tx: c.tx, explorer: c.explorer, cost_usd: 0, cost_ccd: c.amount_ccd, ms: c.ms });
      if (onchain && Math.abs(sellerBal - onchain.balance) > Math.max(0.01, onchain.balance * 0.01)) uncertainty.push(`Concordium agent reading ${sellerBal} disagrees with our chain read (${onchain.balance})`);
      if (!onchain) onchain = { balance: sellerBal, source: `Concordium agent ${c.seller_badge}` };
    } else if (c.refused) uncertainty.push(`Concordium seller not paid: ${c.reason}`);   // our own policy text: rail.mjs and registry.mjs build it from fixed templates
    else { uncertainty.push(`Concordium seller failed${Number.isInteger(c.status) ? ` (HTTP ${c.status})` : ""}`); if (c.reason) notes.push(`ccd seller: ${String(c.reason).slice(0, 200)}`); }
  }
  const agentRead = ev.some((e) => e.ok && e.intent === "CCD_AGENT_BALANCE");
  if (!chk.ok && onchain) uncertainty.push(agentRead ? "Telegraph balance check unavailable: decided on the free chain read and the paid Concordium agent reading" : "paid balance check unavailable: decided on the free chain read alone");
  if (!chk.ok && !onchain) {
    verdict = "PENDING";
    const empty = chk.tried.filter((t) => t.error === "empty answer").length;
    reasons.push(empty
      ? `no miner returned a ${token || "native"} balance on ${normChain(chain)} (${empty} paid answer${empty > 1 ? "s" : ""} came back empty): chain or token likely unsupported, not claiming without proof`
      : `on-chain check unavailable on ${normChain(chain)}: not claiming without proof`);
  }
  else if (txHash) {
    const st = lc(r.status ?? r.answer);
    const stWord = /revert|fail/.test(st) ? "reverted" : /confirm|success/.test(st) ? "confirmed" : /pending/.test(st) ? "pending" : "unverified";
    if (st) notes.push(`tx lookup: ${st.slice(0, 200)}`);
    const mentionsUs = JSON.stringify(r).toLowerCase().includes(wallet.toLowerCase().slice(2));
    if (/confirm|success/.test(st) && mentionsUs) { verdict = "PAID"; reasons.push(`transfer ${txHash.slice(0, 10)}… confirmed to our wallet`); }
    else { verdict = "CLAIM"; reasons.push(`claimed tx ${txHash.slice(0, 10)}… is ${stWord}${mentionsUs ? "" : " and does not pay our wallet"}`); }
  } else {
    const minerBal = !chk.ok || r.balance === null || r.balance === undefined || r.balance === "" ? NaN : Number(r.balance);
    let bal = minerBal;
    if (onchain) {
      if (Number.isFinite(minerBal) && Math.abs(minerBal - onchain.balance) > Math.max(0.01, onchain.balance * 0.01)) {
        uncertainty.push(`miner answer ${minerBal} disagrees with the chain (${onchain.balance}): using the chain value`);
      } else if (Number.isFinite(minerBal)) reasons.push(`chain read agrees (${onchain.balance})`);
      bal = onchain.balance;
    } else if (chk.ok) uncertainty.push("single source: no free chain read for this chain/token");
    if (Number.isFinite(bal) && amountUsd && bal >= amountUsd) { verdict = "PAID"; reasons.push(`wallet holds ${bal} ${safeSym(token) || safeSym(r.token_symbol)}, covers the payment`); }
    else { verdict = "CLAIM"; reasons.push(`wallet holds ${Number.isFinite(bal) ? bal : "?"} ${safeSym(token) || safeSym(r.token_symbol)} on ${normChain(chain)} as of ${safeTime(r.as_of)}: payment of $${amountUsd} not received`); }
  }
  const terms = ev.find((e) => e.intent === "CONTRACT_OBLIGATION_AUDIT_GENERAL");
  if (verdict === "CLAIM" && /\? /.test(reasons.join(" "))) uncertainty.push("balance unknown");
  if (terms?.ok) { reasons.push("terms read (summary in notes)"); notes.push(`terms: ${terms.result?.summary || (terms.result?.obligations || []).slice(0, 2).join("; ")}`); }
  let claim;
  if (verdict === "CLAIM") {
    const H = /^0x[0-9a-fA-F]{64}$/;   // the letter goes to the client after approval: only well-formed hashes from the node
    const rc = ev.filter((e) => e.ok && H.test(String(e.receipt?.receipt_hash))).map((e) => `- ${e.intent}: receipt ${e.receipt.receipt_hash}${H.test(String(e.receipt?.tx_hash)) ? ` (settlement tx ${e.receipt.tx_hash})` : ""}`).join("\n") + (onchain ? `\n- independent chain read: ${onchain.balance} via ${onchain.source}` : "");
    claim = `To: ${contact || client + " payments team"}\nSubject: Unpaid payment: $${amountUsd}${dueDate ? `, due ${dueDate}` : ""}\n\nHello ${client} team,\n\nWe are owed $${amountUsd}${dueDate ? ` with payment due ${dueDate}` : ""}. As of ${new Date().toISOString().slice(0, 10)} it has not arrived at ${wallet} on ${chain}.\n\n${[...reasons, ...notes.filter((n) => n.startsWith("terms: ")).map((n) => n.replace(/^terms: /, "terms, as summarised by a paid reviewer (check before sending): "))].map((x) => "- " + x).join("\n")}\n\nIndependent evidence, bought from the Telegraph network (verifiable receipts):\n${rc}\n\nPlease send the payment or tell us what is still needed from our side.\n\nThank you.`;
  }
  // Consent: Gig Guard never sends anything. A claim is an action on the user's behalf, so it waits for a yes.
  const action = verdict !== "CLAIM" ? "none" : approved === true ? "approved: hand the letter to the mailer" : approved === false ? "declined by user: not sent" : "awaiting user approval";
  const rc = ev.filter((e) => e.ok && e.receipt).length;
  return decide("claim", { wallet, chain, token, txHash, client, amountUsd, dueDate, label }, verdict, reasons, ev,
    { ...(claim && approved !== false ? { claim } : {}), action, uncertainty, notes, paid_receipts: rc });
}

// Deterministic local rules. A miner's finding is corroborated when one of these fires on the same code;
// otherwise it is marked "miner-only" so a human knows how much weight it carries.
const RULES = [
  [/tx\.origin/, "tx.origin used for auth (SWC-115)"],
  [/\.delegatecall\s*\(/, "delegatecall (SWC-112)"],
  [/selfdestruct\s*\(|suicide\s*\(/, "selfdestruct (SWC-106)"],
  [/^\s*(?!\(bool)[^\n=]*\.call(\{[^}]*\})?\([^\n]*\);/m, "low-level call result not checked (SWC-104)"],
  [/\.call\{value:[^}]*\}\([^)]*\);[\s\S]{0,200}?\b\w+\[[^\]]+\]\s*(=|-=)/, "state written after external call (SWC-107 reentrancy)"],
  [/block\.timestamp\s*%|blockhash\s*\(/, "weak randomness (SWC-120)"],
];
const localFindings = (code) => RULES.filter(([re]) => re.test(code)).map(([, m]) => m);

/** May this contract/code deliverable be handed over? */
export async function shipCheck(code, { name = "deliverable" } = {}) {
  if (!code || !code.trim()) throw new Error("empty deliverable");
  const src = code.length > 12000 ? code.slice(0, 12000) + "\n/* truncated */" : code;
  const isSol = /pragma solidity|contract\s+\w+\s*\{/.test(code);
  const ev = [await buy([["SECURITY_REVIEW_GENERAL", { target: src }]], {}, "ship")];
  // SMART_CONTRACT_AUDIT_GENERAL has no published schema yet (answers come back as free text, no receipt),
  // so contracts get the typed CODE_REVIEW Intent as the second opinion.
  ev.push(await buy([["CODE_REVIEW_GENERAL", { code: src }]], {}, "ship"));
  const [sr, cr] = ev; const reasons = [], notes = [];   // notes: reviewer free text, private (never in public output)
  let verdict = "SHIP";
  if (!sr.ok && !cr.ok) { verdict = "HOLD"; reasons.push("no review could be bought: fail closed"); }
  const sv = lc(sr.result?.verdict), cv = lc(cr.result?.verdict);
  const vc = Number(sr.result?.vulnerability_count);
  const nIssues = (Number.isFinite(vc) && vc > 0 ? vc : 0) + (Array.isArray(sr.result?.issues) && !(Number.isFinite(vc) && vc > 0) ? sr.result.issues.length : 0);
  if (sr.ok && (/insecure|needs changes/.test(sv) || (!sv && nIssues > 0))) { verdict = "FIX"; const cwes = [...new Set(JSON.stringify(sr.result.issues || []).match(/CWE-\d{1,4}/g) || [])].slice(0, 5); reasons.push(`security review: ${nIssues || "?"} issue${nIssues === 1 ? "" : "s"}${cwes.length ? " (" + cwes.join(", ") + ")" : ""}`); notes.push(`security: ${String(sr.result.verdict)} ${JSON.stringify((sr.result.issues || []).slice(0, 5)).slice(0, 400)}`); }
  const cf = lc(JSON.stringify(cr.result?.findings || []));
  if (cr.ok && (/request changes/.test(cv) || /not correct or safe|reentran|critical|vulnerab/.test(cf))) { verdict = "FIX"; reasons.push(`${cr.intent}: changes requested`); notes.push(`${cr.intent}: ${String(cr.result.verdict)}. ${String(cr.result.summary || "").slice(0, 400)}`); }
  if (!reasons.length) { reasons.push(`security review: ${sr.ok ? (nIssues ? `passed with ${nIssues} note${nIssues === 1 ? "" : "s"}` : "no issues") : "n/a"}; ${cr.intent}: ${cr.ok ? "no changes requested" : "n/a"}`); notes.push(`security: ${sr.ok ? String(sr.result.verdict) : "n/a"}; ${cr.intent}: ${cr.ok ? String(cr.result.verdict) : "n/a"}`); }
  const local = isSol ? localFindings(code) : [];
  const uncertainty = [];
  if (verdict === "FIX" && local.length) reasons.push(`confirmed by local rules: ${local.join("; ")}`);
  else if (verdict === "FIX") uncertainty.push("miner-only finding: no local rule fired; a human should confirm before rework");
  else if (verdict === "SHIP" && local.length) { verdict = "FIX"; reasons.push(`miners passed it, but local rules fired: ${local.join("; ")}`); uncertainty.push("miners and local rules disagree"); }
  if (verdict === "SHIP" && (!sr.ok || !cr.ok)) uncertainty.push("only one review could be bought");
  return decide("ship", { name, bytes: code.length, solidity: isSol }, verdict, reasons, ev, { uncertainty, notes, local_findings: local });
}
