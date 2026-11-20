// Free deterministic cross-check: read the token balance straight from a public RPC and compare it with
// the miner's paid answer. A miner can be wrong (or invent a number); the chain can't. Same idea as checking
// a paid answer against an independent free source before acting on it.
import { normChain, TOKENS } from "./tokens.mjs";

const RPC = {
  ethereum: "https://ethereum-rpc.publicnode.com",
  bsc: "https://bsc-rpc.publicnode.com",
  polygon: "https://polygon-bor-rpc.publicnode.com",
  arbitrum: "https://arbitrum-one-rpc.publicnode.com",
  base: "https://base-rpc.publicnode.com",
  optimism: "https://optimism-rpc.publicnode.com",
};
async function call(url, to, data) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: to ? "eth_call" : "eth_getBalance", params: to ? [{ to, data }, "latest"] : [data, "latest"] }),
    signal: AbortSignal.timeout(Number(process.env.GG_RPC_TIMEOUT_MS || 10000)) });
  const j = await r.json();
  if (j.error || !j.result) throw new Error(j.error?.message || "no result");
  return BigInt(j.result === "0x" ? 0 : j.result);
}
/** Returns { balance, source } in whole token units, or null when the chain/token isn't covered or the RPC fails. */
export async function chainBalance(address, chain, token) {
  if (process.env.GG_NO_RPC === "1") return null;
  const c = normChain(chain), url = (process.env[`GG_RPC_${c.toUpperCase()}`] || RPC[c]);
  if (!url) return null;
  const t = String(token || "").trim();
  const ca = /^0x[0-9a-fA-F]{40}$/.test(t) ? t : TOKENS[c]?.[t.toUpperCase()];
  try {
    if (!t) return { balance: Number(await call(url, null, address)) / 1e18, source: `${c} RPC eth_getBalance` };
    if (!ca) return null;
    const pad = address.toLowerCase().replace(/^0x/, "").padStart(64, "0");
    const [raw, dec] = await Promise.all([call(url, ca, "0x70a08231" + pad), call(url, ca, "0x313ce567")]);
    return { balance: Number(raw) / 10 ** Number(dec), source: `${c} RPC balanceOf(${ca.slice(0, 6)}…${ca.slice(-4)})` };
  } catch { return null; }
}
