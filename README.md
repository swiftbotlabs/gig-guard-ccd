# Gig Guard, made accountable on Concordium

**An agent that pays other agents, now accountable both ways.** Gig Guard is an autonomous agent for freelance crypto work. Before it takes on a job lead, hands over a contract or chases an overdue payment, it buys checks from other agents and decides by a written policy, keeping a receipt for every purchase (the three gates: [docs/GIG-GUARD-BASE.md](docs/GIG-GUARD-BASE.md)).

On Concordium testnet it gets three things it didn't have:

1. **It proves who it is.** Gig Guard has its own Agent Registry entry (CIS-8004) and an Agent Card whose SHA-256 is committed on chain, owned by an account that can be ID-verified.
2. **It pays only accountable agents.** Payments go over x402 (`exact` scheme, sponsored V1 transactions, so the buyer needs no CCD for fees). Before anything is signed, the seller must be in the registry, **Active**, with an Agent Card that matches its on-chain hash, the endpoint being paid must serve that same card at `/.well-known/agent-card.json` **and prove it holds the registered wallet's key**: it signs a fresh challenge naming the exact origin being paid, checked against the account's keys on chain. A copied badge or a copied card is not enough, and a proof relayed from the real seller names the real seller's origin, so it fails too. The x402 `payTo` must be that agent's registered wallet. Only the configured network and assets (`GG_CCD_ASSETS`, default CCD) are paid, and every authorised payment counts against the daily cap at once, whether or not the seller reports settlement. Anything else is refused and logged. If the registry can't be reached, nothing is paid.
3. **It keeps a record.** Every decision, payment and refusal goes into an append-only, SHA-256 hash-chained log naming the agent's badge and owner (in the spirit of EU AI Act Art. 12 record keeping). The chain head is anchored in Gig Guard's own registry metadata, so the log can't be quietly rewritten afterwards.

Testnet only. Claim letters are drafts that wait for the user's yes. Paid checks are bought automatically, inside the per-call and per-day caps, including the second balance reading from Ledger Check when `GG_CCD_SELLER_URL` is set.

## Try it in one minute (no accounts, no network, no funds)

```bash
npm install
npm run demo:offline     # the whole flow with a fake registry, fake signature and fake settlement
npm test                 # 93 tests (+1 that needs a maintainer word list, skipped without it)
```

The offline walkthrough uses the real HTTP 402 flow (`@x402/express` seller, `@x402/fetch` buyer), the real payment policy and the real audit log. Only the registry answers, the signature and the settlement are faked. It shows:

- one paid request to a verified agent;
- four refusals before signing: revoked, tampered card, `payTo` switched, no badge;
- the audit log verifying OK;
- the same log failing after one edited byte.

## How it fits together

| Piece | File | What it does |
|---|---|---|
| Counterparty check | `src/ccd/registry.mjs` | `check_badge` and `get_agent_wallet` through Concordium's hosted Agent Registry MCP. Registered, Active, card hash, payTo binding, and the endpoint's key proof (`/.well-known/agent-proof`, verified against the account's on-chain keys). Fails closed. |
| Payment rail | `src/ccd/rail.mjs` | x402 client on `@x402/concordium`. Per-call and per-day caps checked before signing. The policy runs in `onBeforePaymentCreation` and aborts a payment it doesn't allow. |
| A seller to hire | `src/ccd/seller.mjs` | "Ledger Check", a small paid agent selling an on-chain balance reading. It advertises its badge in every offer (`extra.agentBadge`) and runs its own facilitator with a sponsor account. |
| Decision log | `src/ccd/audit.mjs` | Hash-chained JSONL; `gig-guard audit` recomputes the chain (exit 10 if edited). **Private**: it holds client names and full reasons, so it stays with the operator (default `~/.gig-guard/`); only its anchored head is public. Show it to an auditor, who can check it against the anchor. |
| On-chain setup | `src/ccd/setup.mjs`, `src/ccd/chaintx.mjs` | `card`, `register`, `badge`, `anchor`, `revoke` and `show`. The registry MCP builds the contract call; we sign it with our own key. Every write is appended to `docs/LIVE.md` with its CCDExplorer link. |
| Anchor check | `setup.mjs check-anchor` | Reads the anchored head back from the registry (free, no node access) and checks the log against it. Appending is fine; rewriting anything anchored fails. |
| Where it's used | `src/guards.mjs` | The claim gate buys a second balance reading from Ledger Check when `GG_CCD_SELLER_URL` is set. Disagreement or a refusal lands in the decision's `uncertainty`. |

## Live testnet run

The on-chain steps are the `src/ccd/setup.mjs` commands (`card`, `register`, `badge`, `anchor`, `show`, `revoke`, `check-anchor`). The run needs three different testnet accounts, because the facilitator refuses a sponsor that is also the sender or the recipient:

- the buyer (Gig Guard);
- the seller (Ledger Check);
- the sponsor (fee payer).

Results, with CCDExplorer links, go in `docs/LIVE.md`.

## Path to mainnet

- Same code. Set `GG_CCD_NETWORK=mainnet`; the registry moves to `<10082,0>` and the CAIP-2 id changes.
- The owner verifies once with Concordium ID, which makes the badge "Verified".
- Caps already exist (`GG_CCD_MAX_PER_CALL`, `GG_CCD_MAX_PER_DAY`).

## Limits

- Badge checks rely on the hosted registry MCP. If it is down, Gig Guard pays nobody (by design), and the run stalls.
- "Verified" here means the card hash matches and the agent is Active. Whether the owner has passed Concordium ID depends on the owner, and the live run reports exactly what `show` returns.
- The anchor proves the log's head at a time. It does not prove nothing was logged before the first entry.
- One seller so far, and it is ours. No independent users yet.

## License

MIT
