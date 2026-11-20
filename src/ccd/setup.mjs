// One-time setup on Concordium testnet, run on a machine that can reach the node (gRPC :20000):
//
//   node src/ccd/setup.mjs card   <name> <public card url>   write the Agent Card JSON (hash goes on chain)
//   node src/ccd/setup.mjs register <public card url> <card file>   mint the agent in the Agent Registry
//   node src/ccd/setup.mjs badge <token id> <public card url> [card file]   add the badge to the card, re-anchor its hash
//   node src/ccd/setup.mjs anchor <token id> [audit.jsonl]    write the decision log's chain head on chain
//   node src/ccd/setup.mjs show <token address>               badge check (same lookup buyers use)
//   node src/ccd/setup.mjs revoke <token id> [reason]          mark an agent Revoked (used for the refusal demo)
//   node src/ccd/setup.mjs check-anchor <token id> [audit.jsonl]  read the anchored head back and check the log
//   (both use registry metadata key gigguard.audit.head, or GG_CCD_ANCHOR_KEY=gigguard.audit.<name>)
//
// Every chain write is also appended to GG_LIVE_LOG (default docs/LIVE.md) with its explorer link.
//
// Key: GG_CCD_KEYFILE (Concordium wallet export). The card file must be served byte-for-byte at the URL.
import fs from "node:fs";
import crypto from "node:crypto";
import { loadAccount } from "./rail.mjs";
import { submitBuilt, build } from "./chaintx.mjs";
import { verifyAudit, verifyAnchor, AUDIT_FILE } from "./audit.mjs";
import { mcpCall, NETWORK } from "./registry.mjs";

const [cmd, ...a] = process.argv.slice(2);
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const acct = () => loadAccount();
// Live record: one line per chain write, so docs/LIVE.md fills itself during the run.
function live(what, r, extra = "") {
  const f = process.env.GG_LIVE_LOG || "docs/LIVE.md";
  if (!fs.existsSync(f)) fs.writeFileSync(f, "# Live testnet run\n\n| Time (UTC) | Step | Result | Transaction |\n|---|---|---|---|\n");
  fs.appendFileSync(f, `| ${new Date().toISOString().slice(0, 19).replace("T", " ")} | ${what} | ${r.ok ? "ok" : "FAILED"}${extra ? ", " + extra : ""} | ${r.explorer ? `[${r.tx.slice(0, 10)}…](${r.explorer})` : "n/a"} |\n`);
}

// Registry metadata key for the audit head. GG_CCD_ANCHOR_KEY lets a separate, publishable log (e.g. a public demo run) be
// anchored next to the operator's private one (default key) without replacing it.
const ANCHOR_KEY = process.env.GG_CCD_ANCHOR_KEY || "gigguard.audit.head";
if (!/^gigguard\.audit\.[a-z0-9.]{1,40}$/.test(ANCHOR_KEY)) { console.error("GG_CCD_ANCHOR_KEY must look like gigguard.audit.<name>"); process.exit(2); }
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
  const [tokenId, file = AUDIT_FILE] = a;
  const v = verifyAudit(file);
  if (!v.ok) { console.error("audit chain broken, not anchoring:", v.reason); process.exit(10); }
  const value = `${v.entries}:${v.head}`;
  const me = acct();
  const built = await build("build_set_metadata", { token_id: Number(tokenId), key: ANCHOR_KEY, value_hex: Buffer.from(value).toString("hex"), sender: me.address });
  const r = await submitBuilt(built, me);
  live(`anchor audit head, token ${tokenId}`, r, value.slice(0, 24) + "…");
  console.log(JSON.stringify({ ok: r.ok, anchored: value, tx: r.tx, explorer: r.explorer }));
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
  const [tokenId, file = AUDIT_FILE] = a;
  const m = await mcpCall("get_metadata", { token_id: Number(tokenId), key: ANCHOR_KEY, network: NETWORK });
  // The tool returns the value as hex and, when it is UTF-8, as text; field names may vary, so search both forms.
  const hexes = JSON.stringify(m ?? null).match(/[0-9a-f]{132,}/gi) || [];
  const anchored = [JSON.stringify(m ?? null), ...hexes.map((h) => Buffer.from(h, "hex").toString())].map((s) => /\d+:[0-9a-f]{64}/.exec(s)?.[0]).find(Boolean) || null;
  const v = verifyAnchor(file, anchored);
  console.log(JSON.stringify({ anchored, ...v }));
  process.exit(v.ok ? 0 : 10);
} else {
  console.log("usage: setup.mjs card|register|badge|anchor|show|revoke|check-anchor ...");
  process.exit(2);
}
