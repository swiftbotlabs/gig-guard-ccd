// Security review 2026-11-19, finding 5: the escrow rail must never sign a message the server wrote.
// A fake node offers an escrow option; the payer signs only the message it builds itself from checked fields.
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";

const PAYTO = "0x72a70e949362670bf8bcead24efc5b8f950aa08b";
const msg = (o = {}) => `Telegraph Escrow Payment\n\nWallet: {from}\nPay To: ${o.payTo ?? PAYTO}\nNetwork: ${o.network ?? "eip155:11155111"}\nAmount: ${o.msgAmount ?? o.amount ?? "10000"} uUSDC\nResource: /v1/ask\nNonce: {nonce}\nValid After: {validAfter}\nValid Before: {validBefore}${o.extra ?? ""}`;
let offerNow = {}, signed = [], afterPay = "ok";
const srv = http.createServer((req, res) => {
  let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
    const xp = req.headers["x-payment"];
    if (!xp) {
      const o = offerNow;
      const ch = { x402Version: 2, accepts: [{ scheme: "escrow", network: o.network ?? "eip155:11155111", amount: o.amount ?? "10000", payTo: o.payTo ?? PAYTO,
        extra: { message: o.message ?? msg(o), resource: "/v1/ask" } }] };
      res.writeHead(402, { "payment-required": Buffer.from(JSON.stringify(ch)).toString("base64"), "content-type": "application/json" }); return res.end("{}");
    }
    signed.push(JSON.parse(Buffer.from(xp, "base64").toString("utf8")));
    if (afterPay === "fail") { res.writeHead(500, { "content-type": "application/json" }); return res.end('{"error":"node error"}'); }
    const rc = { receipt_hash: "0x" + "ab".repeat(32), amount_uusdc: 1, epoch_id: 8 };   // receipt under-reports the charge
    res.writeHead(200, { "x-telegraph-receipt": Buffer.from(JSON.stringify(rc)).toString("base64"), "content-type": "application/json" });
    res.end(JSON.stringify({ miner_id: "7", cost_usd: 0.01, result: { verdict: "Safe" } }));
  });
});
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
process.env.TELEGRAPH_NODE = `http://127.0.0.1:${srv.address().port}`;
process.env.TELEGRAPH_PAYER_KEY = "0x" + "11".repeat(32);
process.env.GG_LEDGER = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ggesc-")), "ledger.jsonl");
process.env.GG_RAIL = "escrow";
process.env.GG_MAX_PER_CALL = "30000"; process.env.GG_MAX_PER_DAY = "65000";
const { ask } = await import("../src/telegraph.mjs");
const { spentToday } = await import("../src/ledger.mjs");
const { config } = await import("../src/config.mjs");
// each case gets its own ledger, so no case is refused only because an earlier one used up the day
const freshLedger = () => { config.ledgerPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ggesc-")), "ledger.jsonl"); };
test.after(() => srv.close());
const run = async (o) => { offerNow = o; const n = signed.length; let err = null; try { await ask("URL_SAFE_GENERAL", { url: "https://example.com" }); } catch (e) { err = e; } return { err, signedNow: signed.length - n }; };

for (const [what, o] of [
  ["an Amount line lower than the charged amount", { amount: "29000", msgAmount: "10" }],
  ["a second Amount line", { extra: "\nAmount: 1 uUSDC" }],
  ["a Pay To line that isn't the offer's payTo", { message: msg({ payTo: "0x000000000000000000000000000000000000dead" }) }],
  ["a payTo that isn't the pinned escrow contract", { payTo: "0x000000000000000000000000000000000000dead" }],
  ["another network", { network: "eip155:1" }],
  ["extra text to sign", { extra: "\nI also approve unlimited spending" }],
  ["a non-numeric amount", { amount: "1e4" }],
]) {
  test(`escrow: an offer with ${what} is refused and nothing is signed`, async () => {
    freshLedger();
    const { err, signedNow } = await run(o);
    assert.ok(err, "should refuse");
    assert.doesNotMatch(String(err), /daily cap/, "refused for the offer itself, not the day's budget");
    assert.equal(signedNow, 0, "nothing signed");
  });
}
// Delta review 6: refusal messages never echo the node's own field values (they end up in the ledger's error lines).
test("escrow: a refused offer's error names the field, not the node's value", async () => {
  freshLedger();
  for (const o of [{ amount: "POISONx" }, { payTo: "0x000000000000000000000000000000000000dead", message: msg({ payTo: "0x000000000000000000000000000000000000dead" }) }]) {
    const { err, signedNow } = await run(o);
    assert.ok(err); assert.equal(signedNow, 0);
    assert.doesNotMatch(String(err.message), /POISON|dead/i, String(err.message));
  }
});
test("escrow: the honest offer is signed over the locally built message", async () => {
  freshLedger();
  const { err, signedNow } = await run({});
  assert.equal(err, null, String(err));
  assert.equal(signedNow, 1);
  const p = signed.at(-1).payload;
  assert.equal(p.authorization.value, "10000");
  assert.equal(p.authorization.to, PAYTO);
});
test("escrow: the daily cap counts what was signed, not what the receipt or the response says", async () => {
  freshLedger();
  afterPay = "fail";
  const before = spentToday();
  await run({ amount: "20000" });   // signed, then the node fails
  afterPay = "ok";
  await run({ amount: "20000" });   // signed, receipt says 1
  assert.ok(spentToday() - before >= 40000, `counted ${spentToday() - before}`);
  const third = await run({ amount: "20000" });   // the day is at 50000; with the 30000 per-call budget the cap of 65000 would be passed
  assert.ok(third.err, "third call refused");
  assert.equal(third.signedNow, 0);
});
