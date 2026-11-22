// One-time setup on Concordium testnet, run on a machine that can reach the node (gRPC :20000):
//
//   node src/ccd/setup.mjs card   <name> <public card url>   write the Agent Card JSON (hash goes on chain)
//   node src/ccd/setup.mjs register <public card url> <card file>   mint the agent in the Agent Registry
//   node src/ccd/setup.mjs badge <token id> <public card url> [card file]   add the badge to the card, re-anchor its hash
//   node src/ccd/setup.mjs anchor <token id> [audit.jsonl]    write the decision log's chain head on chain (refuses a log that
//                                                              no longer reaches the head already there; skips if nothing is new)
//   node src/ccd/setup.mjs show <token address>               badge check (same lookup buyers use)
//   node src/ccd/setup.mjs revoke <token id> [reason]          mark an agent Revoked (used for the refusal demo)
//   node src/ccd/setup.mjs check-anchor <token id> [audit.jsonl] [--at N:hash]  read the anchored head back and check the log
//   (both use registry metadata key gigguard.audit.head, or GG_CCD_ANCHOR_KEY=gigguard.audit.<name>)
//
// Every chain write is also appended to GG_LIVE_LOG (default docs/LIVE.md) with its explorer link.
//
// Key: GG_CCD_KEYFILE (Concordium wallet export). The card file must be served byte-for-byte at the URL.
import fs from "node:fs";
import crypto from "node:crypto";
import { loadAccount } from "./rail.mjs";
import { submitBuilt, build } from "./chaintx.mjs";
import { verifyAnchor, AUDIT_FILE } from "./audit.mjs";
import { anchorKey, readAnchor, anchorIfSafe, live } from "./anchor.mjs";
import { mcpCall, NETWORK } from "./registry.mjs";

const [cmd, ...a] = process.argv.slice(2);
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const acct = () => loadAccount();
let ANCHOR_KEY;
try { ANCHOR_KEY = anchorKey(); } catch (e) { console.error(e.message); process.exit(2); }
if (cmd === "card") {
  const [name, url, out = "agent-card.json"] = a;
  const me = acct();
  const card = await build("build_agent_card", {
    name, agent_uri: url, owner_account: me.address, agent_wallet: me.address, version: "0.1.0",
    description: process.env.GG_CARD_DESC || "Gig Guard: an autonomous freelance agent that buys verified checks before it acts, pays only accountable agents over x402, and keeps a tamper-evident decision log.",
    documentation_url: process.env.GG_CARD_DOCS || undefined,
  });
  const json = card.agent_card_json ?? JSON.stringify(card.card ?? card, null, 2) + "\n";
  fs.writeFileSync(out, json);
  console.log(JSON.stringify({ file: out, sha256: sha(json) }));
} else if (cmd === "register") {
  const [url, file = "agent-card.json"] = a;
  const me = acct();
  const built = await build("build_register", { agent_uri: url, metadata_hash_hex: sha(fs.readFileSync(file)), sender: me.address });
  const r = await submitBuilt(built, me);
  live(`register ${url}`, r);
  const agents = await mcpCall("agents_by_owner", { owner_account: me.address, network: NETWORK }).catch(() => null);
  console.log(JSON.stringify({ ok: r.ok, tx: r.tx, explorer: r.explorer, agents: agents?.agents?.map((x) => ({ token_id: x.token_id, token_address: x.token_address, agent_uri: x.agent_uri })) }, null, 2));
} else if (cmd === "badge") {
  // After registering: put the badge (token address) into the card, then point the registry at the new hash.
  const [tokenId, url, file = "agent-card.json"] = a;
  const me = acct();
  const b = await build("build_agent_badge", { card_json: fs.readFileSync(file, "utf8"), token_id: Number(tokenId), owner_account: me.address, agent_wallet: me.address });
  const json = b.agent_card_json ?? JSON.stringify(b.card ?? b, null, 2) + "\n";
  fs.writeFileSync(file, json);
  const built = await build("build_set_agent_uri", { token_id: Number(tokenId), agent_uri: url, metadata_hash_hex: sha(json), sender: me.address });
  const r = await submitBuilt(built, me);
  live(`badge + card hash, token ${tokenId}`, r, `card sha256 ${sha(json).slice(0, 12)}…`);
  console.log(JSON.stringify({ ok: r.ok, file, sha256: sha(json), tx: r.tx, explorer: r.explorer, next: "publish the card file byte-for-byte at " + url }));
} else if (cmd === "anchor") {
  // Reads the head already on chain first: a log that no longer reaches it (edited, cut, or re-hashed) is never anchored.
  const [tokenId, file = AUDIT_FILE] = a;
  const r = await anchorIfSafe(tokenId, file, acct(), { key: ANCHOR_KEY });
  console.log(JSON.stringify(r));
  if (r.action === "refuse") { console.error("NOT anchoring:", r.reason); process.exit(11); }
  if (r.action === "anchor" && !r.ok) process.exit(1);
} else if (cmd === "show") {
  console.log(JSON.stringify(await mcpCall("check_badge", { id: a[0], network: NETWORK }), null, 2));
} else if (cmd === "revoke") {
  const [tokenId, reason = "demo: revoked agent must be refused"] = a;
  const me = acct();
  const built = await build("build_revoke", { token_id: Number(tokenId), reason, sender: me.address });
  const r = await submitBuilt(built, me);
  live(`revoke token ${tokenId}`, r);
  console.log(JSON.stringify({ ok: r.ok, tx: r.tx, explorer: r.explorer }));
} else if (cmd === "check-anchor") {
  // Free and read-only: works from any machine that can reach the registry MCP (no node access needed).
  // --at <entries:hash> checks against an earlier anchor instead (its value is in that anchor transaction on CCDExplorer).
  const at = a.indexOf("--at"), given = at >= 0 ? a.splice(at, 2)[1] : null;
  const [tokenId, file = AUDIT_FILE] = a;
  const anchored = given || await readAnchor(tokenId, ANCHOR_KEY);
  const v = verifyAnchor(file, anchored);
  console.log(JSON.stringify({ anchored, ...(given ? { source: "--at" } : {}), ...v }));
  process.exit(v.ok ? 0 : 10);
} else {
  console.log("usage: setup.mjs card|register|badge|anchor|show|revoke|check-anchor ...");
  process.exit(2);
}
