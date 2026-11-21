// Read-only: run Gig Guard's registry-side checks against agents OTHER people registered on testnet, through Concordium's hosted
// Agent Registry MCP and a node. Nothing is signed or paid. For each agent: found, Active, the card at its agent_uri hashes to the
// on-chain value (check_badge), and a verified human behind the owner account (checkOwnerIdentity). The endpoint key proof and payTo
// binding need a live x402 seller, so they are not part of this survey; Gig Guard would refuse to pay without them anyway.
//   node src/ccd/survey.mjs [active=8] [revoked=3]      -> one JSON line per agent, then a summary line
import { mcpCall, NETWORK, checkOwnerIdentity } from "./registry.mjs";

const OURS = new Set((process.env.GG_SURVEY_EXCLUDE || "3whFmR7A1j55fAHfaMdkDckhH21Fr5ybfWm5oNVRGNsqJpeehk,3dVtNczd1YM3GFuNkUSVhVaqXbEUv4ykwPhVoNcqADBDG1uxeD").split(","));
const [nActive, nRevoked] = [Number(process.argv[2] || 8), Number(process.argv[3] || 3)];
const short = (s, n = 10) => (typeof s === "string" ? s.replace(/[^\w.:/-]/g, "").slice(0, n) : null);

async function pick(status, n) {
  const first = await mcpCall("list_agents", { network: NETWORK, status, limit: 1 });
  const total = Number(first?.total) || 0, out = [];
  for (let off = Math.max(0, total - 50); out.length < n && off >= 0; off -= 50) {   // newest first, other people's only
    const page = await mcpCall("list_agents", { network: NETWORK, status, limit: 50, offset: off });
    for (const a of (page?.agents || []).reverse()) if (!OURS.has(a.owner_account) && out.length < n && !out.some((x) => x.owner_account === a.owner_account)) out.push(a);
    if (!total) break;
  }
  return out;
}

const rows = [];
for (const a of [...await pick("Active", nActive), ...await pick("Revoked", nRevoked)]) {
  const row = { token_id: Number(a.token_id), owner: short(a.owner_account), status: a.status === "Active" || a.status === "Revoked" ? a.status : "unknown" };
  try {
    const info = await mcpCall("agent_of", { network: NETWORK, token_id: Number(a.token_id) });
    const b = await mcpCall("check_badge", { id: info.token_address, network: NETWORK });
    const c = b?.checks || {};
    Object.assign(row, { badge: short(info.token_address, 24), found: !!c.on_chain_agent_found, active: !!c.status_active, card_fetched: !!c.card_fetched, card_matches: !!c.hash_matches_on_chain });
  } catch (e) { row.registry_error = "unreachable or malformed (fail closed)"; }
  const id = await checkOwnerIdentity(a.owner_account);
  Object.assign(row, { owner_verified: id.ok, idp: id.ok ? id.idpName : null });
  row.registry_checks = row.found && row.active && row.card_matches && row.owner_verified ? "pass" : "refuse";
  row.why = row.registry_checks === "pass" ? null : [!row.active && `status ${row.status}`, row.found && !row.card_matches && (row.card_fetched ? "card does not match its on-chain hash" : "card not served at its agent_uri"), !row.owner_verified && "no verified human behind the owner"].filter(Boolean).join("; ") || "not found";
  rows.push(row); console.log(JSON.stringify(row));
}
console.log(JSON.stringify({ at: new Date().toISOString(), network: NETWORK, checked: rows.length, pass: rows.filter((r) => r.registry_checks === "pass").length,
  refused: rows.filter((r) => r.registry_checks !== "pass").length, revoked_refused: rows.filter((r) => r.status === "Revoked" && r.registry_checks !== "pass").length }));
