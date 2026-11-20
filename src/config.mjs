import { dataFile } from "./paths.mjs";
// All limits in micro-USDC (6 decimals). 10000 = $0.01.
export const config = {
  rail: process.env.GG_RAIL || "escrow", // "escrow" (prepaid Diamond balance, works today) or "x402" (exact, needs a facilitator signer)
  node: process.env.TELEGRAPH_NODE || "https://devnode.telegraphprotocol.com",
  network: process.env.TELEGRAPH_NETWORK || "eip155:84532", // Base Sepolia (testnet)
  assets: {
    "eip155:84532": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",   // Circle test USDC, Base Sepolia
    "eip155:11155111": "0xcc194e1a843B658526D0D5C431f670028582Ae17", // Telegraph test USDC, Ethereum Sepolia
  },
  maxPerCall: Number(process.env.GG_MAX_PER_CALL || 30000),   // $0.03 hard cap per request
  maxPerDay: Number(process.env.GG_MAX_PER_DAY || 1000000),   // $1.00 hard cap per UTC day
  timeoutMs: Number(process.env.GG_TIMEOUT_MS || 120000),
  ledgerPath: process.env.GG_LEDGER || dataFile("ledger.jsonl"),   // private: outside the repository
};
export const explorers = {
  "eip155:84532": "https://sepolia.basescan.org/tx/",
  "eip155:11155111": "https://sepolia.etherscan.io/tx/",
};
