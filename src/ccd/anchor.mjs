// Reading and writing the audit log's anchored head in Gig Guard's registry metadata (CIS-8004 set_metadata / get_metadata).
// Shared by setup.mjs (anchor, check-anchor) and schedule.mjs (the scheduled re-anchor).
import fs from "node:fs";
import { mcpCall, NETWORK } from "./registry.mjs";
import { build, submitBuilt } from "./chaintx.mjs";
import { planAnchor } from "./audit.mjs";

// Registry metadata key for the audit head. GG_CCD_ANCHOR_KEY lets a separate, publishable log (e.g. a public demo run) be
// anchored next to the operator's private one (default key) without replacing it.
export function anchorKey(key = process.env.GG_CCD_ANCHOR_KEY || "gigguard.audit.head") {
  if (!/^gigguard\.audit\.[a-z0-9.]{1,40}$/.test(key)) throw new Error("GG_CCD_ANCHOR_KEY must look like gigguard.audit.<name>");
  return key;
}

// Free and read-only: the head currently anchored under `key`, as "entries:hash", or null if none.
export async function readAnchor(tokenId, key = anchorKey(), call = mcpCall) {
  const m = await call("get_metadata", { token_id: Number(tokenId), key, network: NETWORK });
  // The tool returns the value as hex and, when it is UTF-8, as text; field names may vary, so search both forms.
  const hexes = JSON.stringify(m ?? null).match(/[0-9a-f]{132,}/gi) || [];
  return [JSON.stringify(m ?? null), ...hexes.map((h) => Buffer.from(h, "hex").toString())].map((s) => /\d+:[0-9a-f]{64}/.exec(s)?.[0]).find(Boolean) || null;
}

// Live record: one line per chain write, so docs/LIVE.md (or GG_LIVE_LOG) fills itself during a run.
export function live(what, r, extra = "") {
  const f = process.env.GG_LIVE_LOG || "docs/LIVE.md";
  if (!fs.existsSync(f)) fs.writeFileSync(f, "# Live testnet run\n\n| Time (UTC) | Step | Result | Transaction |\n|---|---|---|---|\n");
  fs.appendFileSync(f, `| ${new Date().toISOString().slice(0, 19).replace("T", " ")} | ${what} | ${r.ok ? "ok" : "FAILED"}${extra ? ", " + extra : ""} | ${r.explorer ? `[${r.tx.slice(0, 10)}…](${r.explorer})` : "n/a"} |\n`);
}

// Re-anchor only when it is safe: reads the head on chain first and never overwrites it with a log that no longer reaches it.
// Returns the plan, plus {tx, explorer, ok} when it wrote. dryRun: decide only, sign nothing.
export async function anchorIfSafe(tokenId, file, account, { key = anchorKey(), dryRun = false } = {}) {
  const current = await readAnchor(tokenId, key);
  const plan = { previous: current, ...planAnchor(file, current) };
  if (plan.action !== "anchor" || dryRun) return plan;
  const built = await build("build_set_metadata", { token_id: Number(tokenId), key, value_hex: Buffer.from(plan.value).toString("hex"), sender: account.address });
  const r = await submitBuilt(built, account);
  live(`anchor audit head (${key.replace(/^gigguard\.audit\./, "")}), token ${tokenId}`, r, plan.value.slice(0, 24) + "…");
  return { ...plan, ok: r.ok, tx: r.tx, explorer: r.explorer };
}
