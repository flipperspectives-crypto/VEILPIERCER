# VeilPiercer v2.2 — Free, Instant Smart Contract Audits

**Try it now:** https://veilpiercer.fly.dev

---

Smart contract audits cost $5K–$50K. VeilPiercer gives you instant, multi-engine analysis for free — with cryptographic proofs anchored on-chain.

## What It Does

Paste any Solidity contract. Get a full audit report in seconds:

- **3 engines**: regex scanner (69% recall), Slither (22% recall, 19% FP), Mythril (symbolic execution)
- **Confusion matrix published**: we tell you exactly what we catch AND what we miss
- **SIAS proofs**: every finding is cryptographically timestamped — prove when you found it
- **Community leaderboard**: contribute anonymized stats, see what others are finding
- **Verified badge**: protocols passing our thresholds get a `[![VeilPiercer Verified](...)]` badge for their README

## Why Free

We're building the detection engine in public. Every scan improves the patterns. Every false positive gets tracked in the confusion matrix. The more people use it, the more accurate it gets.

## Try These

- [Reentrancy](https://veilpiercer.fly.dev) — external call before state update
- [Flash Loan](https://veilpiercer.fly.dev) — price oracle manipulation
- [Missing Access Control](https://veilpiercer.fly.dev) — anyone can change fees
- [Oracle Manipulation](https://veilpiercer.fly.dev) — spot price exploitation

## Public Audits

We've published 5 audit reports for well-known contract patterns:

| Contract | Findings | Report |
|----------|----------|--------|
| Uniswap V2 Pair (reentrancy) | 2 | [audit](https://github.com/flipperspectives-crypto/VEILPIERCER/tree/main/reports) |
| Compound Timelock (access) | 2 | [audit](https://github.com/flipperspectives-crypto/VEILPIERCER/tree/main/reports) |
| Aave LendingPool (oracle) | 3 | [audit](https://github.com/flipperspectives-crypto/VEILPIERCER/tree/main/reports) |
| Chainlink PriceFeed (staleness) | 1 | [audit](https://github.com/flipperspectives-crypto/VEILPIERCER/tree/main/reports) |
| WETH9 (frontrunning) | 0 | [audit](https://github.com/flipperspectives-crypto/VEILPIERCER/tree/main/reports) |

## Get Involved

- **[Contribute a detection pattern](https://github.com/flipperspectives-crypto/VEILPIERCER/blob/main/CONTRIBUTING.md)** — 5 good-first-issues waiting
- **[Get your protocol verified](https://veilpiercer.fly.dev/verify)** — paste your code, get a badge
- **[See community stats](https://veilpiercer.fly.dev/community)** — anonymized aggregate leaderboard

MIT licensed. Zero cloud. Runs on your machine or our demo.

---

*VeilPiercer v2.2 — 225 contracts benchmarked, 579 findings, 96.2% dep resolution, SIAS anchored.*
