# Gig Guard: the three gates

Gig Guard is a paid safety gate for an autonomous freelance agent. An agent that takes paid work loses money in three places:
it spends effort on job leads from payers who never pay, it hands over code with holes in it, and it lets payments it is owed
go unclaimed. Gig Guard puts a paid, checkable step in front of each of those moves. It buys answers from other agents (the
Telegraph network for the checks below, accountable agents on Concordium for the balance reading), pays for them itself,
checks them against a free independent source where one exists, and a written policy decides. Every decision keeps its receipts.

Testnet only. No real money moves.

| Gate | What it buys | Free cross-check | Decisions |
|---|---|---|---|
| `scout`: a new job lead | `URL_SCAN_VERDICT` (fallback `URL_SAFE_GENERAL`) on the link, `WEB_SEARCH_GENERAL` (fallback `NEWS_SEARCH_GENERAL`) on the payer's payment record | sources must actually mention the payer | GO / CAUTION / SKIP |
| `ship`: a contract or code deliverable is about to be handed over | `SECURITY_REVIEW_GENERAL`, `CODE_REVIEW_GENERAL` | local Solidity rules (SWC-104/106/107/112/115/120) | SHIP / FIX / HOLD |
| `claim`: a promised payment is overdue | `WALLET_BALANCE_CHECK_GENERAL` (or `ONCHAIN_TX_LOOKUP_GENERAL` for a tx), `CONTRACT_OBLIGATION_AUDIT_GENERAL` on the terms; on Concordium, a second reading from Ledger Check | public RPC `balanceOf` | PAID / CLAIM (letter drafted, waits for the user's yes) / PENDING |

## Why a verdict can be trusted

- **Receipts anyone can check.** `gig-guard verify` looks each escrow receipt up in the node's settled epoch block.
- **A paid answer is not the last word.** Balances are re-read from a public RPC; if the answer disagrees with the chain, the chain
  wins and the disagreement is shown. Security findings are marked "confirmed by local rules" or "reviewer-only".
- **Uncertainty is visible.** Every decision carries an `uncertainty` list: single source, disagreement, stale reading.
- **Consent before acting.** A claim letter is a draft: without `"approved": true` it waits; with `"approved": false` it is dropped.
- **Fail closed.** No proof means PENDING or HOLD. Bad input, and any file outside the workspace (`GG_WORKSPACE`), is refused
  before any payment. A paid answer that comes back empty or stale is logged, counted in the cost, and not used as evidence.
- **Caps before signing.** Per call and per day; the escrow message is built locally and signed only if the node quotes the same text.

## Run it

```bash
npm install
npm test
node src/cli.mjs ship samples/Vault.sol        # FIX
node src/cli.mjs ship samples/SafeVault.sol    # SHIP
node src/cli.mjs run queue.json results.json   # every pending item of a queue (an agent loop)
```

Exit codes: 0 = go (GO/PAID/SHIP), 10 = stop and look, 1 = error, so each gate is a one-line guard in a shell loop:
`node src/cli.mjs ship out/C.sol && hand_over || echo held`.

## Privacy

The decision ledger and the audit log live outside the repository (`GG_DATA_DIR`, default `~/.gig-guard`) because they hold client
names, wallets, claim letters and raw answer text (terms summaries, search snippets, kept as private `notes`). The public page
and `export` drop raw answers, notes and claim letters, replace the client's name with a neutral label, shorten EVM, base58 and
hash values, replace links with `[link]` and e-mail addresses with `[email]`. Receipt hashes stay, so every decision remains
checkable. The redaction is by pattern and by the names the ledger knows: a name it has never seen, written inside a reason, can
still show, so reasons hold only fixed verdict text (counts, CWE ids, verdict words); every reviewer's or scanner's free text goes to the
private notes, which are never exported.

## Limits

- The payer check reads web sources: it flags risk, it doesn't prove fraud.
- A balance can't tell one deposit from another; pass the payer's announced tx hash when there is one.
- Reviews read the first 12 KB of a deliverable. The local rules are a short list, not an auditor.
