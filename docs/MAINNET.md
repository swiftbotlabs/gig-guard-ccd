# Gig Guard on mainnet: the plan on one page

## What changes, what stays
- **Same code.** `GG_CCD_NETWORK=mainnet` points the registry checks at the mainnet Agent Registry `<10082,0>`, the node at `grpc.mainnet.concordium.software:20000` and x402 at the mainnet CAIP-2 id. Nothing else in the payment path changes.
- **Identity providers.** On testnet, Gig Guard's and Ledger Check's owner credentials come from the *Concordium testnet IP*, which issues test identities **without any document check**. On testnet the "verified human" check therefore proves the mechanism, not that a real person was checked. On mainnet we start with `GG_CCD_IDP_ALLOW=1,2,3`. Read from a mainnet node on 22 Nov 2026, those ids are Notabene, Digital Trust Solutions and Global FinReg, the identity providers that verify a person's ID document before they issue an identity. Id 0 ("Identity Provider 0") stays out until we know what it checks. The provider that vouched for each seller is written into every payment record.
- **Keys.** The owner account verifies once with Concordium ID in the Concordium wallet. Gig Guard's agent wallet is a separate account with a small float, and the per-call and per-day caps (`GG_CCD_MAX_PER_CALL`, `GG_CCD_MAX_PER_DAY`) are checked before anything is signed.

## What it costs (mainnet chain parameters read 22 Nov 2026: €0.00002 per energy unit, about 389 CCD per €)
| Step | Energy (measured on testnet) | Mainnet fee | How often |
|---|---|---|---|
| Register the agent | 2,455 | about €0.05 | once |
| Badge + card hash | 1,910 | about €0.04 | once per card change |
| Anchor the log head | 2,142 | about €0.04 | per scheduled run (every 3 h: about €0.35 a day) |
| Protected x402 payment | 635 (transfer) | about €0.013, paid by the seller's facilitator (sponsored) | per call |
| Registry and identity reads | none | free | before every payment |

So one agent costs under €0.10 to set up, and about €10 a month to keep its log anchored every 3 hours. Every check before a payment is a free read.

## How it makes money (planned, not live)
- **Who pays:** the freelancer or small agency running Gig Guard, since a mistaken payment costs them more than the check does. Pricing is a flat fee per protected payment on top of the seller's own x402 price, and the caps stay with the user.
- **Sellers:** Gig Guard already buys balance readings and code reviews from agents on another escrow network. Each of those agents gets a Concordium badge so Gig Guard can pay it through the same checks.

## Steps, in order
1. Register Gig Guard on mainnet (the same `setup.mjs card / register / badge` steps), with the owner verified at one of providers 1-3.
2. Register Ledger Check on mainnet the same way, and run one paid call with the buyer gate on.
3. Turn on the scheduled re-check and re-anchor (`deploy/gigguard-schedule.*`, every 3 h), and publish the log's anchor history.
4. Invite the first outside seller. We have none yet, and we won't name one we don't have.

## Risks we know about
- The hosted registry service is a dependency. If it is down, Gig Guard pays nobody, by design. The fix is to read the registry contract directly from our own node.
- The anchor proves the log's head at each anchor time. It doesn't prove what happened before the first entry or between two anchors, which is why the scheduled anchor keeps that gap at 3 hours.
