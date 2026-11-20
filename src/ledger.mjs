import fs from "node:fs";
import { config } from "./config.mjs";
import { ensureDir } from "./paths.mjs";
export function readLedger() {
  if (!fs.existsSync(config.ledgerPath)) return [];
  return fs.readFileSync(config.ledgerPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
}
export function append(entry) {
  ensureDir(config.ledgerPath);
  fs.appendFileSync(config.ledgerPath, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n");
}
// Day spend in micro-USDC: every payment counts the moment we sign it ("signed"), whatever the node answers
// or its receipt says afterwards. Older ledgers have only "purchase" lines; those count unless already signed-counted.
export function spentToday() {
  const day = new Date().toISOString().slice(0, 10);
  return readLedger().filter((e) => e.ts?.startsWith(day) && (e.kind === "signed" || (e.kind === "purchase" && !e.signed)))
    .reduce((s, e) => s + (Number.isSafeInteger(e.amount_uusdc) && e.amount_uusdc > 0 ? e.amount_uusdc : 0), 0);
}
