// Chain names and stablecoin contracts. Live finding (2026-11-18): WALLET_BALANCE_CHECK miners answer
// "bsc" + token SYMBOL with an all-null result, but "bsc" + token CONTRACT with a real balance.
// So the claim gate asks by contract first and by symbol second.
const ALIASES = {
  ethereum: ["ethereum", "eth", "mainnet", "1", "erc20", "erc-20"],
  bsc: ["bsc", "bnb", "bnb smart chain", "bnb chain", "binance smart chain", "binance", "56", "bep20", "bep-20"],
  polygon: ["polygon", "matic", "pos", "137"],
  arbitrum: ["arbitrum", "arbitrum one", "arb", "42161"],
  base: ["base", "8453"],
  optimism: ["optimism", "op", "10"],
};
export function normChain(c) {
  const k = String(c ?? "").trim().toLowerCase();
  for (const [name, al] of Object.entries(ALIASES)) if (al.includes(k)) return name;
  return k;
}
export const TOKENS = {
  ethereum: { USDT: "0xdAC17F958D2ee523a2206206994597C13D831ec7", USDC: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" },
  bsc: { USDT: "0x55d398326f99059fF775485246999027B3197955", USDC: "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d" },
  polygon: { USDT: "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", USDC: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359" },
  arbitrum: { USDT: "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", USDC: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831" },
  base: { USDC: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" },
  optimism: { USDT: "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", USDC: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85" },
};
/** Ordered parameter sets to try for a balance check: contract address first, then the symbol. */
export function balanceQueries(address, chain, token) {
  const c = normChain(chain), t = String(token ?? "").trim();
  const sym = t.toUpperCase(), ca = /^0x[0-9a-fA-F]{40}$/.test(t) ? t : TOKENS[c]?.[sym];
  const qs = [];
  if (ca) qs.push({ address, chain: c, token: ca });
  if (!ca || ca !== t) qs.push({ address, chain: c, token: t });
  return qs;
}
