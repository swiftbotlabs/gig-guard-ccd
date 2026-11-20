#!/usr/bin/env node
// Offline walkthrough of the Concordium accountability layer: no accounts, no network, no funds.
//
//   npm run demo:offline
//
// What is real: the HTTP 402 flow (@x402/express seller, @x402/fetch buyer), Gig Guard's payment policy
// (registry check, payTo binding, caps), and the hash-chained audit log.
// What is faked: the Agent Registry answers, the transaction signature, the facilitator's settlement and the node's
// account-key lookup (each demo account gets a real ed25519 key, so the seller's key proof is signed and checked for real).
// The live testnet run (docs/LIVE.md) swaps those three fakes for the real registry, wallet and facilitator.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buyCcd, makePayingFetch, CAIP2 } from "../src/ccd/rail.mjs";
import { buildSeller } from "../src/ccd/seller.mjs";
import { verifyAudit, record } from "../src/ccd/audit.mjs";
import { checkCounterparty, verifyAccountProof } from "../src/ccd/registry.mjs";
import { keyFor, fakeAccountInfo } from "./fakekeys.mjs";

const SELLER = "4n3P1UDZA2usiVTS95mteZRnMB7pizRb9LcsmqrQMstnCgcE9K"; // Ledger Check's registered wallet (example)
const OTHER = "32MAVPXN9z4s6XmkXLy4vsNpaimLcEEs95Lfna7BjBbfQ4gn8p";  // some other account
const BUYER = "4SV3Q1ejRmi3DVNPaZGS8QRRNikquFeMpNXjnLnoNFkRYnL62R";  // Gig Guard (example)
const GOOD = "MockVerifiedAgent11111", REVOKED = "MockRevokedAgent22222", TAMPERED = "MockTamperedCard33333";

// Agent Cards in the registry's shape; their SHA-256 is the on-chain hash the fake registry reports, and each
// seller serves its card, so the buyer can bind the badge to the endpoint it pays.
import crypto from "node:crypto";
const card = (badge, wallet) => JSON.stringify({ name: badge, capabilities: { extensions: [{ uri: "https://docs.concordium.com/a2a-extensions/concordium-badge/v1",
  params: { tokenAddress: `${CAIP2}/cis-2:${badge}`, owner: { account: `${CAIP2}:${wallet}` }, agentWallet: `${CAIP2}:${wallet}` } }] } });
const sha = (s) => crypto.createHash("sha256").update(s).digest("hex");
const registry = {
  [GOOD]: { checks: { on_chain_agent_found: true, status_active: true, hash_matches_on_chain: true }, on_chain: { owner_account: SELLER, status: "Active", metadata_hash_hex: sha(card(GOOD, SELLER)) }, token_id: 7 },
  [REVOKED]: { checks: { on_chain_agent_found: true, status_active: false, hash_matches_on_chain: true }, on_chain: { owner_account: SELLER, status: "Revoked", metadata_hash_hex: sha(card(REVOKED, SELLER)) }, token_id: 8 },
  [TAMPERED]: { checks: { on_chain_agent_found: true, status_active: true, hash_matches_on_chain: false }, on_chain: { owner_account: SELLER, status: "Active", metadata_hash_hex: sha("the card as registered, before the edit") }, token_id: 9 },
};
const call = async (name, args) => name === "check_badge" ? registry[args.id] || { checks: { on_chain_agent_found: false } } : SELLER;
const verifyProof = (m, sig, a) => verifyAccountProof(m, sig, a, { getAccountInfo: fakeAccountInfo });   // a node would answer this
const check = (badge, o) => checkCounterparty(badge, { ...o, call, verifyProof });

let n = 0;
const scheme = { scheme: "exact", async createPaymentPayload(v, req) { return { x402Version: v, payload: { signedTransaction: { amount: req.amount, to: req.payTo }, sender: BUYER } }; } };
const facilitatorClient = {
  async verify(p, r) { return { isValid: p.payload.signedTransaction.to === r.payTo, payer: BUYER }; },
  async settle(p, r) { n++; return { success: true, transaction: n.toString(16).padStart(64, "d"), network: r.network, payer: BUYER }; },
  async getSupported() { return { kinds: [{ x402Version: 2, scheme: "exact", network: CAIP2, extra: { feePayer: SELLER } }], extensions: [], signers: {} }; },
};

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ggccd-demo-"));
process.on("exit", () => { if (!process.env.GG_KEEP_DEMO) fs.rmSync(dir, { recursive: true, force: true }); });   // GG_KEEP_DEMO=1 keeps the logs
process.on("SIGINT", () => process.exit(130));   // Ctrl-C still runs the cleanup above
const audit = path.join(dir, "audit.jsonl");
process.env.GG_CCD_BADGE = "GigGuardDemoBadge777"; process.env.GG_CCD_OWNER = BUYER;
const say = (s = "") => console.log(s);
const step = (s) => say(`\n\x1b[1m${s}\x1b[0m`);
const query = { address: "0x000000000000000000000000000000000000dEaD", chain: "ethereum", token: "USDT" };

async function sellerRun(label, { badge, payTo = SELLER }) {
  let origin = null;
  const app = buildSeller({ seller: { address: payTo, signer: keyFor(payTo).signer }, origin: () => origin, facilitatorClient, read: async () => ({ balance: 0 }), auditFile: path.join(dir, "seller.jsonl"), badge, card: badge ? card(badge, SELLER) : null });
  const srv = app.listen(0); await new Promise((r) => srv.once("listening", r));
  origin = `http://127.0.0.1:${srv.address().port}`;
  try {
    const payingFetch = makePayingFetch({ account: { address: BUYER, signer: null }, scheme, check, auditFile: audit, purpose: "claim" });
    const r = await buyCcd(`http://127.0.0.1:${srv.address().port}/v1/balance`, { body: query, purpose: "claim", auditFile: audit, payingFetch });
    say(`  seller: ${label}`);
    if (r.ok) say(`  \x1b[32mPAID\x1b[0m 0.1 CCD, fee sponsored by the seller's facilitator. tx ${r.tx.slice(0, 12)}…  balance read: ${r.body.balance} USDT`);
    else say(`  \x1b[31mREFUSED before signing\x1b[0m: ${r.reason}`);
    return r;
  } finally { srv.close(); }
}

say("Gig Guard on Concordium: offline walkthrough (fake registry, fake signature, fake settlement; real 402 flow and policy)");
step("1. The claim gate needs a second, independent balance reading. It hires the Ledger Check agent.");
say("  Before paying, Gig Guard looks the seller up in the Agent Registry: registered? Active? Agent Card hash matches the chain? payTo = its registered wallet?");
say("  It also binds the badge to the endpoint: the seller must serve that exact on-chain-hashed card, naming this badge and this payTo.");
const ok = await sellerRun("Ledger Check, registered + Active + card verified, payTo = registered wallet", { badge: GOOD });
record("decision", { gate: "claim", verdict: "CLAIM", reasons: ["wallet holds 0 USDT: payment of $400 not received", "second reading bought from an accountable agent agrees (0)"], action: "awaiting user approval", payment_tx: ok.tx }, { file: audit });
say("  verdict: CLAIM, letter drafted, waiting for the user's yes (nothing is sent without it)");

step("2. The same request to sellers that are not accountable:");
await sellerRun("registry status Revoked", { badge: REVOKED });
await sellerRun("Agent Card edited after registration (hash mismatch)", { badge: TAMPERED });
await sellerRun("valid badge, but payTo switched to another account", { badge: GOOD, payTo: OTHER });
await sellerRun("no badge at all", { badge: undefined });

step("3. Every payment, refusal and decision is in a hash-chained log naming the accountable parties:");
for (const l of fs.readFileSync(audit, "utf8").trim().split("\n").map((x) => JSON.parse(x)))
  say(`  #${l.seq} ${l.kind.padEnd(10)} agent=${l.agent_badge} ${l.kind === "refusal" ? l.reason.slice(0, 70) : l.kind === "authorized" ? `may sign ${l.amount} to ${l.payTo.slice(0, 8)}… (counted now)` : l.kind === "payment" ? `paid ${l.amount} to ${l.payTo.slice(0, 8)}…` : l.verdict}  hash ${l.hash.slice(0, 10)}…`);
const v = verifyAudit(audit);
say(`  gig-guard audit: \x1b[32mOK\x1b[0m, ${v.entries} entries, head ${v.head.slice(0, 16)}…`);
say(`  live run: \`setup.mjs anchor\` writes "${v.entries}:${v.head.slice(0, 16)}…" into Gig Guard's registry metadata (key gigguard.audit.head), so the head is public and dated.`);

step("4. Someone quietly edits the log afterwards:");
const lines = fs.readFileSync(audit, "utf8").trim().split("\n");
const forged = lines.map((l, i) => (i === 0 ? l.replace(/"amount":"\d+"/, '"amount":"1"') : l));
fs.writeFileSync(audit, forged.join("\n") + "\n");
const bad = verifyAudit(audit);
say(`  gig-guard audit: \x1b[31mFAIL\x1b[0m at entry #${bad.brokenAt}: ${bad.reason}`);
say(`\nPayments settled: ${n} of 5 attempts. Refused before signing: 4. Audit log: ${audit}${process.env.GG_KEEP_DEMO ? "" : " (removed on exit; GG_KEEP_DEMO=1 keeps it)"}`);
