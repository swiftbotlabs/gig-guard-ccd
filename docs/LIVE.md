# Live testnet run

Testnet, 2026-11-19. Setup (register, badge, revoke) and the first paid check ran at 06:50-09:58 UTC with the code before that day's security fixes. **The current code was re-run at 19:56-19:58 UTC**: see "Re-run with the current code" below; those transactions are the ones to check. The register URLs are the Agent Card URIs written on chain.

| Time (UTC) | Step | Result | Transaction |
|---|---|---|---|
| 2026-11-19 06:50:04 | register https://apps.swiftbotlab.workers.dev/concordium/agents/gig-guard.json | ok | [87cb810cdb…](https://ccdexplorer.io/testnet/transaction/87cb810cdba97a9fd6d1e58c61294ce60a6379ff61b8d0a64c3e30e533b8a327) |
| 2026-11-19 06:52:11 | badge + card hash, token 1272 | ok, card sha256 1cbe6d734a9a… | [a4b80e941e…](https://ccdexplorer.io/testnet/transaction/a4b80e941efbeff2be1a648ae6736cabc190d2ded4aecf81086c6430bed5d388) |
| 2026-11-19 07:09:49 | register https://apps.swiftbotlab.workers.dev/concordium/agents/ledger-check.json | ok | [e7d9f1f691…](https://ccdexplorer.io/testnet/transaction/e7d9f1f6916af0f0907d7a8d8df7eca13ea43fcd57b985c63674bdbc82bb48e6) |
| 2026-11-19 07:11:55 | badge + card hash, token 1273 | ok, card sha256 19e419c3e575… | [38c17767b4…](https://ccdexplorer.io/testnet/transaction/38c17767b430bf1c400492fd76e3a3cafbbea3049b20c5d46395d5eb1ad11871) |
| 2026-11-19 07:13:57 | register https://apps.swiftbotlab.workers.dev/concordium/agents/throwaway.json | ok | [404719722b…](https://ccdexplorer.io/testnet/transaction/404719722b8798205368ac106a44f5b09413cf5ebf24bee37b9c926077538741) |
| 2026-11-19 07:16:07 | badge + card hash, token 1274 | ok, card sha256 b87ddba2ef63… | [12c58014b8…](https://ccdexplorer.io/testnet/transaction/12c58014b8e27c5701194e16ef649e613b448a1fc3a7e7a5f5d36635924722b0) |
| 2026-11-19 09:53:37 | anchor audit head, token 1272 | ok, 8:4be9a71341da0996ab3ece… | [c7b8670711…](https://ccdexplorer.io/testnet/transaction/c7b8670711ba1710c919d21ca003faa6afc75cc2f960e566f49f0d084d7b3867) |
| 2026-11-19 09:56:25 | revoke token 1274 | ok | [00d6e023ba…](https://ccdexplorer.io/testnet/transaction/00d6e023baca8cdd1a835d50a23f8c20c023c267a95819f806192e527d383efc) |
| 2026-11-19 09:58:45 | anchor audit head, token 1272 | ok, 10:db2e4fc7a526bd2d3a340… | [cc1053b53e…](https://ccdexplorer.io/testnet/transaction/cc1053b53ea5ff8e66955ca320fcad7a713347c8aad3dc85315757b16a702612) |

## Paid checks and refusals (buyer Gig Guard, token 1272; its audit log is the one anchored below)

| Time (UTC) | Case | Result | Transaction |
|---|---|---|---|
| 2026-11-19 09:52:28 | Ledger Check (token 1273, Active, card hash matches, payTo = its registered wallet) | paid 0.1 CCD over x402, sponsored | [9f369eca22…](https://ccdexplorer.io/testnet/transaction/9f369eca2298ea2a6a781c4b9fb2e7451c4864a86c711458ee550779aa549fa1) |
| 2026-11-19 09:52:42 | seller presents Ledger Check's badge but asks to be paid to another account | REFUSED before signing: "x402 payTo is not this agent's registered wallet" | none |
| 2026-11-19 09:58:38 | Throwaway agent (token 1274) after its revoke | REFUSED before signing: "registry status Revoked" | none |
| 2026-11-19 09:58:45 | audit log (10 entries) head anchored on chain; `check-anchor` OK | | [cc1053b53e…](https://ccdexplorer.io/testnet/transaction/cc1053b53ea5ff8e66955ca320fcad7a713347c8aad3dc85315757b16a702612) |
| 2026-11-19 19:45:13 | anchor audit head, token 1272 | ok, 21:ed3faecc1d8357bfad883… | [853cbb50fb…](https://ccdexplorer.io/testnet/transaction/853cbb50fb25a933907e3906ed89ba691d87eb926d8ec7ea73a67139e7825e7b) |
| 2026-11-19 19:57:41 | anchor audit head, token 1272 | ok, 34:286fe3e494fcb1009509d… | [35905beb95…](https://ccdexplorer.io/testnet/transaction/35905beb95fea8d5c3e9a15c71ebd30e0f65bc31b3179972965de9124b00fed2) |

## Re-run with the current code (2026-11-19 19:56-19:58 UTC; buyer Gig Guard, token 1272)

Current checks before signing: registry status, card hash, the card served by the paid endpoint, a fresh key proof from the endpoint for the
paid origin (checked against the account's keys on chain), payTo = registered wallet, network and asset allow-list, caps counted at signing.

| Time (UTC) | Case | Result | Transaction |
|---|---|---|---|
| 2026-11-19 19:56:18 | Ledger Check (token 1273): Active, card hash matches, serves its card, valid key proof for the paid origin, payTo = its wallet | paid 0.1 CCD over x402, sponsored; the claim decision lists receipt `ccd:<tx>` and cost 0.1 CCD | [b282101127…](https://ccdexplorer.io/testnet/transaction/b28210112709d90e6ab1a07fb052569ecb0ad222e4e3cec00b62c76a635da17d) |
| 2026-11-19 19:56:34 | seller shows Ledger Check's badge but asks to be paid to another account | REFUSED before signing: "x402 payTo is not this agent's registered wallet or owner; the seller endpoint's Agent Card does not name the payTo account" | none |
| 2026-11-19 19:56:50 | seller serves a one-byte-edited copy of the card | REFUSED before signing: "the Agent Card served by the seller endpoint does not match the on-chain hash" | none |
| 2026-11-19 19:57:06 | Throwaway agent (token 1274), revoked earlier | REFUSED before signing: "registry status Revoked" | none |
| 2026-11-19 19:57:18 | seller shows Ledger Check's badge and wallet but serves another agent's (valid) card | REFUSED before signing: "the Agent Card served by the seller endpoint does not match the on-chain hash" | none |
| 2026-11-19 19:57:31 | the real Ledger Check, but its key proof names another origin (what a relaying impostor would hand over) | REFUSED before signing: "the seller endpoint's key proof names another origin, badge or account" | none |
| 2026-11-19 19:57:41 | audit log (34 entries) head anchored on chain; `check-anchor` OK (34 of 34 anchored, tail OK) | | [35905beb95…](https://ccdexplorer.io/testnet/transaction/35905beb95fea8d5c3e9a15c71ebd30e0f65bc31b3179972965de9124b00fed2) |

## Owner identity check (read-only, 2026-11-20 15:47 UTC, testnet node)

`checkOwnerIdentity` read both owner accounts from `grpc.testnet.concordium.com` (no transaction; nothing signed):

| Agent | Owner account | Identity credential |
|---|---|---|
| Gig Guard (token 1272) | 3whFmR7A… | issued by identity provider 0, "Concordium testnet IP", valid to 2027-11: **verified human** |
| Ledger Check (token 1273) | 3dVtNczd… | issued by identity provider 0, "Concordium testnet IP", valid to 2027-11: **verified human** |

From this version on, a seller whose owner has no such credential is refused before signing (offline demo case 6, `test/security.test.mjs`).
| 2026-11-20 22:00:57 | anchor audit head, token 1272 | ok, 16:26b461288441861481482… | [c74cd34f5a…](https://ccdexplorer.io/testnet/transaction/c74cd34f5a7b70c5a065acd6439df298cdef5b0b903852114edac37280182260) |

## Other people's agents, checked live (read-only, 2026-11-21 06:41, `node src/ccd/survey.mjs 8 3`)

Gig Guard's registry-side checks run against agents registered by 11 other owners on testnet (the newest Active ones and recently revoked ones; one per owner; ours excluded). Nothing was signed or paid. The endpoint key proof and payTo binding need a live x402 seller, so they are not part of this survey, and without them Gig Guard would still refuse to pay.

| Token | Status | Card matches on-chain hash | Owner has a live IdP credential | Registry-side verdict |
|---|---|---|---|---|
| 1369 | Active | yes | yes (Concordium testnet IP) | pass |
| 1368 | Active | yes | yes (Concordium testnet IP) | pass |
| 1367 | Active | yes | yes (Concordium testnet IP) | pass |
| 1362 | Active | yes | yes (Concordium testnet IP) | pass |
| 1361 | Active | yes | yes (Concordium testnet IP) | pass |
| 1350 | Active | yes | yes (Concordium testnet IP) | pass |
| 1346 | Active | yes | yes (Concordium testnet IP) | pass |
| 1345 | Active | yes | yes (Concordium testnet IP) | pass |
| 1357 | Revoked | not served | yes (Concordium testnet IP) | refuse: status Revoked; card not served at its agent_uri |
| 1299 | Revoked | yes | yes (Concordium testnet IP) | refuse: status Revoked |
| 1277 | Revoked | not served | yes (Concordium testnet IP) | refuse: status Revoked; card not served at its agent_uri |

8 of 11 would pass these checks; all 3 revoked agents are refused.

## The anchor, over time

The log head has been anchored five times, so a judge can see the log checked as it grows, not at one point:

| When (UTC) | Log | Anchored head | Transaction |
|---|---|---|---|
| 2026-11-19 09:53:37 | private live log | 8 entries | c7b8670711… |
| 2026-11-19 09:58:45 | private live log | 10 entries | cc1053b53e… |
| 2026-11-19 19:45:13 | private live log | 21 entries | 853cbb50fb… |
| 2026-11-19 19:57:41 | private live log | 34 entries | 35905beb95… |
| 2026-11-20 22:00:57 | public run log (`gigguard.audit.public.head`) | 16 entries | c74cd34f5a… |

Each later anchor of the same log covers its earlier entries: `check-anchor` passes on the grown log and fails if anything already anchored is edited.
