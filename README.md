# Gig Guard, made accountable on Concordium

**An agent that pays other agents, now accountable both ways.** Gig Guard is an autonomous agent for freelance crypto work. Before it takes on a job lead, hands over a contract or chases an overdue payment, it buys checks from other agents and decides by a written policy, keeping a receipt for every purchase (the three gates: [docs/GIG-GUARD-BASE.md](docs/GIG-GUARD-BASE.md)).

On Concordium testnet it gets three things it didn't have:

1. **It proves who it is.** Gig Guard has its own Agent Registry entry (CIS-8004) and an Agent Card whose SHA-256 is committed on chain, owned by an account whose identity credential was issued by a Concordium identity provider (read from the chain: provider "Concordium testnet IP", valid to 2027-11). **On testnet that provider issues test identities without any document check**, so here the check shows the mechanism working, not that a real person was checked; on mainnet `GG_CCD_IDP_ALLOW=1,2,3` accepts only providers that check ID documents ([docs/MAINNET.md](docs/MAINNET.md)).
2. **It pays only accountable agents.** Payments go over x402 (`exact` scheme, sponsored V1 transactions, so the buyer needs no CCD for fees). Before anything is signed, the seller must be in the registry, **Active**, with an Agent Card that matches its on-chain hash, the endpoint being paid must serve that same card at `/.well-known/agent-card.json` **and prove it holds the registered wallet's key**: it signs a fresh challenge naming the exact origin being paid, checked against the account's keys on chain. A copied badge or a copied card is not enough, and a proof relayed from the real seller names the real seller's origin, so it fails too. The x402 `payTo` must be that agent's registered wallet. **And a verified human must stand behind it:** the owner account must hold a live identity credential issued by one of the chain's Concordium identity providers (read from a node; only the provider id and the validity month, no personal data; `GG_CCD_IDP_ALLOW` narrows the accepted providers). The provider is written into the payment's audit record. Only the configured network and assets (`GG_CCD_ASSETS`, default CCD) are paid, and every authorised payment counts against the daily cap at once, whether or not the seller reports settlement. Anything else is refused and logged. If the registry can't be reached, nothing is paid.
3. **It keeps a record.** Every decision, payment and refusal goes into an append-only, SHA-256 hash-chained log naming the agent's badge and owner (in the spirit of EU AI Act Art. 12 record keeping). The chain head is anchored in Gig Guard's own registry metadata, on a schedule, so the log can't be quietly rewritten afterwards: a rewrite that recomputes every hash still fails against the anchor, and the scheduled re-anchor refuses to anchor it.

Testnet only. Claim letters are drafts that wait for the user's yes. Paid checks are bought automatically, inside the per-call and per-day caps, including the second balance reading from Ledger Check when `GG_CCD_SELLER_URL` is set.

## Try it in one minute (no accounts, no network, no funds)

```bash
npm install
npm run demo:offline     # the whole flow with a fake registry, fake signature and fake settlement
npm run demo:rewrite     # the published public-run log vs the head anchored on chain: an edit, a full rewrite, an append
npm test                 # 115 tests (+1 that needs a maintainer word list, skipped without it)
```

The offline walkthrough uses the real HTTP 402 flow (`@x402/express` seller, `@x402/fetch` buyer), the real payment policy and the real audit log. Only the registry answers, the signature and the settlement are faked. It shows:

- one paid request to a verified agent;
- five refusals before signing: revoked, tampered card, `payTo` switched, no badge, and a seller that passes every registry check but has no verified human behind its owner account;
- the audit log verifying OK;
- the same log failing after one edited byte.

## How it fits together

| Piece | File | What it does |
|---|---|---|
| Counterparty check | `src/ccd/registry.mjs` | `check_badge` and `get_agent_wallet` through Concordium's hosted Agent Registry MCP. Registered, Active, card hash, payTo binding, the endpoint's key proof (`/.well-known/agent-proof`, verified against the account's on-chain keys), and the owner's identity credential (`checkOwnerIdentity`: issued by a known Concordium identity provider, not expired). Fails closed. |
| Payment rail | `src/ccd/rail.mjs` | x402 client on `@x402/concordium`. Per-call and per-day caps checked before signing. The policy runs in `onBeforePaymentCreation` and aborts a payment it doesn't allow. |
| A seller to hire | `src/ccd/seller.mjs` | "Ledger Check", a small paid agent selling an on-chain balance reading. It advertises its badge in every offer (`extra.agentBadge`) and runs its own facilitator with a sponsor account. With `GG_CCD_SELLER_BUYER_ID=1` it is accountable the other way too: it serves only buyers whose paying account holds a live identity credential from an accepted Concordium identity provider, and a refused buyer is never charged (the check runs after the payment is verified and before it settles). Every Concordium account comes from an identity provider, so on mainnet also set `GG_CCD_IDP_ALLOW`; without it the gate refuses only expired or unknown-provider credentials. Verdicts are cached per account for 5 minutes, so a credential that lapses or is removed is noticed within 5 minutes. With `GG_CCD_SELLER_ID_PROOF=1` it also asks for a zero-knowledge identity attribute proof (default 18 or older) made for the paying account: `GET /v1/id-challenge?account=<payer>` returns the request, the buyer sends the presentation in `X-ID-Presentation` with the paid call, and a missing, replayed, weaker or borrowed proof is refused before settlement (not charged); the body is validated first, so a bad request never uses up a proof. It needs `GG_CCD_IDP_ALLOW` set explicitly (testnet's provider 0 issues self-service test identities). |
| Identity attribute proof | `src/ccd/idproof.mjs` | Zero-knowledge proof of an identity attribute (default: the holder is 18 or older) as a Concordium Verifiable Presentation (`VerifiablePresentationV1`), from an **account** credential. `challenge(account)` issues a single-use 32-byte nonce (10-minute expiry, at most 3 open per account, so other clients cannot evict a buyer's challenge) and the statement; `check(presentation)` verifies the proofs, the credentials' on-chain metadata and validity window with the SDK's `verifyWithNode`, then checks itself that the presentation names our nonce, account and resource (no replay), that the credential's registration id resolves on chain to the challenged account (an anonymous identity-based proof, or one borrowed from another account, is refused), that the proven date-of-birth bound is at least as strong as asked, and that the provider is accepted (`GG_CCD_IDP_ALLOW`). Any error refuses. Nothing personal is stored. |
| Decision log | `src/ccd/audit.mjs` | Hash-chained JSONL; `gig-guard audit` recomputes the chain (exit 10 if edited). **Private**: it holds client names and full reasons, so it stays with the operator (default `~/.gig-guard/`); only its anchored head is public. Show it to an auditor, who can check it against the anchor. |
| On-chain setup | `src/ccd/setup.mjs`, `src/ccd/chaintx.mjs` | `card`, `register`, `badge`, `anchor`, `revoke` and `show`. The registry MCP builds the contract call; we sign it with our own key. Every write is appended to `docs/LIVE.md` with its CCDExplorer link. |
| Anchor check | `setup.mjs check-anchor` | Reads the anchored head back from the registry (free, no node access) and checks the log against it. Appending is fine; rewriting anything anchored fails, even a rewrite that recomputes every later hash (`npm run demo:rewrite`). `--at N:hash` checks against an earlier anchor, whose value is in that anchor transaction. |
| Scheduled re-check + re-anchor | `src/ccd/schedule.mjs`, `deploy/gigguard-schedule.{service,timer}` | Every 3 hours: reads the head on chain and stops (exit 11) if the log no longer reaches it; re-checks each paid seller in the registry and its owner's credential, logging one `recheck` decision per seller; then anchors the grown log. `setup.mjs anchor` uses the same rule: it never anchors a log that no longer reaches the head already on chain. |
| Published log | `docs/public-run/audit-public.jsonl` | The public testnet run's log (no client data), anchored under `gigguard.audit.public.head`, so anyone can run `check-anchor` on it. |
| Survey of other agents | `src/ccd/survey.mjs` | Read-only: runs the registry-side checks (found, Active, card hash, a live IdP credential behind the owner) on agents other people registered. Results in `docs/LIVE.md`. |
| Where it's used | `src/guards.mjs` | The claim gate buys a second balance reading from Ledger Check when `GG_CCD_SELLER_URL` is set. Disagreement or a refusal lands in the decision's `uncertainty`. |

## Live testnet run

The on-chain steps are the `src/ccd/setup.mjs` commands (`card`, `register`, `badge`, `anchor`, `show`, `revoke`, `check-anchor`). The run needs three different testnet accounts, because the facilitator refuses a sponsor that is also the sender or the recipient:

- the buyer (Gig Guard);
- the seller (Ledger Check);
- the sponsor (fee payer).

Results, with CCDExplorer links, go in `docs/LIVE.md`.

## Path to mainnet

One page with the identity providers, the measured costs and the steps: [docs/MAINNET.md](docs/MAINNET.md).

- Same code. Set `GG_CCD_NETWORK=mainnet`; the registry moves to `<10082,0>` and the CAIP-2 id changes.
- The owner verifies once with Concordium ID, which makes the badge "Verified". `GG_CCD_IDP_ALLOW=1,2,3` (Notabene, Digital Trust Solutions, Global FinReg on mainnet).
- Caps already exist (`GG_CCD_MAX_PER_CALL`, `GG_CCD_MAX_PER_DAY`).

## Limits

- Badge checks rely on the hosted registry MCP. If it is down, Gig Guard pays nobody (by design), and the run stalls.
- The owner check proves that a Concordium identity provider issued the identity behind the owner account. It reveals nothing about who that is. On testnet the provider is the test one, which checks no documents, so every testnet "verified human" (ours and the surveyed agents') is a test identity. On mainnet set `GG_CCD_IDP_ALLOW` to the providers you accept.
- The anchor proves the log's head at each anchor time. It does not prove nothing was logged before the first entry, and between two scheduled anchors (3 hours) the newest entries are covered only by the chain itself.
- The identity attribute proof (`idproof.mjs`) is tested offline: the SDK's proof verification is stubbed with the result shape `verifyWithNode` returns, and our own checks (challenge, replay, account binding, statement strength, validity, provider) run for real, each with a test that fails when the check is removed. A presentation from a real wallet-held identity has not been verified yet; that needs a Concordium wallet holding a testnet identity. The presentation travels in a request header, so it must fit Node's 16 KB header limit (not yet measured on a real one). The SDK reports a credential's validity window, not a revocation.
- One seller so far, and it is ours. No independent users yet.

## License

MIT
