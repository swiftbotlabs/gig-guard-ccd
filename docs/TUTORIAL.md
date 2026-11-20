# Tutorial: pay for verified intelligence from an agent loop in 10 minutes (Telegraph testnet)

This walks through what Gig Guard does: an agent pays the Telegraph network for each answer it needs, then acts on the answer. Everything runs on testnet, with nothing real at stake.

## 1. Make a testnet-only key

```bash
node -e 'const {generatePrivateKey,privateKeyToAccount}=require("viem/accounts");const k=generatePrivateKey();console.log(k, privateKeyToAccount(k).address)'
```

Never reuse a key that has ever held real funds.

## 2. Fund an escrow balance (Ethereum Sepolia)

You need a little Sepolia ETH for gas, from any public faucet. Then:

```bash
RPC=https://ethereum-sepolia-rpc.publicnode.com
USDC=0xcc194e1a843B658526D0D5C431f670028582Ae17     # Telegraph test USDC (public mint)
DIAMOND=0x72a70e949362670Bf8bceAd24eFC5b8f950aa08b  # Telegraph devnode Diamond
cast send $USDC "mint(address,uint256)" $ME 10000000 --rpc-url $RPC --private-key $KEY
cast send $USDC "approve(address,uint256)" $DIAMOND 10000000 --rpc-url $RPC --private-key $KEY
cast send $DIAMOND "depositUSDC(uint256)" 5000000 --rpc-url $RPC --private-key $KEY
```

Why escrow and not x402 `exact`? On 2026-11-18 the public facilitator listed no EVM testnet signer, and every settlement timed out. Escrow needs only one EIP-191 signature per request, with no facilitator involved.

## 3. Ask a question and pay for it

```bash
git clone <repo> && cd gig-guard-ccd && npm install
export TELEGRAPH_PAYER_KEY=$KEY   # escrow is the default rail
node src/cli.mjs ship samples/Vault.sol
```

What happens under the hood (`src/telegraph.mjs`):
1. A POST to `/engine/v1/ask` returns `402` with an `escrow` option.
2. The client fills `{from}`, `{nonce}`, `{validAfter}` and `{validBefore}` into the quoted message, then signs it with `personal_sign`.
3. It retries with `X-PAYMENT: base64({x402Version:2, scheme:"escrow", payload:{signature, authorization}})`.
4. The `200` response carries the miner's answer, plus `X-PAYMENT-RESPONSE`, a receipt with `receipt_hash` and `epoch_id`.

## 4. Act on the answer

The policy lives in `src/guards.mjs`. A contract that `SECURITY_REVIEW` flags (CWE-863 for tx.origin auth) gets FIX, and the agent doesn't hand it over. Exit code 10 means stop. That makes it a one-line guard in any shell loop:

```bash
node src/cli.mjs ship out/Contract.sol && hand_over || echo "held by Gig Guard"
```

## 5. Put it in the loop

```bash
node src/cli.mjs run queue.json results.json
```

`queue.json` is a list of `{id, gate, ...}` items. Pending items are run, marked done, and logged to the private ledger (`~/.gig-guard/ledger.jsonl`, or `GG_DATA_DIR`) with their receipts. `node src/cli.mjs ledger ledger.html` renders the public page.

## 6. Check the receipts

```bash
node src/cli.mjs verify verify.json
node src/cli.mjs ledger ledger.html verify.json
```

Each receipt is looked up at `GET /v1/blocks/{epoch_id}/deliveries/{receipt_hash}` on the node. SETTLED means the epoch block lists the delivery with the same intent and amount; PENDING means the epoch is still open (blocks are recorded about an hour after each 3-hour window). The page's **Check receipts live** button does the same lookup from any browser.

## 7. Keep the private ledger private

The private ledger (`~/.gig-guard/ledger.jsonl`) holds client names, wallets, claim letters and raw answer text. Publish only `ledger.html` or `node src/cli.mjs export ledger.public.jsonl`; both use neutral labels.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `402 ... insufficient escrow for delivery` | Your signature is fine but the balance is 0 | Deposit (step 2) |
| `402 ... settle request failed ... context deadline exceeded` | The x402 facilitator can't settle | Use `GG_RAIL=escrow` |
| `400 max_budget_usdc needs escrow` | Multi-miner budget on Base Sepolia x402 | Gig Guard drops the budget on that rail automatically |
| `PENDING ... likely unsupported` on a balance | Miners return null for that chain/token | Pass the token contract address in `token` |
| Receipt stays PENDING | Its epoch block isn't recorded yet | Re-run `verify` an hour after the epoch closes |
| `answer: null` from WEB_SEARCH | The query was phrased as a question | Use keywords |
| Free-text answer with no receipt | The Intent has no published schema (for example SMART_CONTRACT_AUDIT_GENERAL) | Pick a typed Intent; Gig Guard uses CODE_REVIEW |

## Costs

Each answer costs $0.01, and a gate buys two answers, so about $0.02 per gate. Hard caps are $0.03 per request and $1 per day, set by `GG_MAX_PER_CALL` and `GG_MAX_PER_DAY`.
