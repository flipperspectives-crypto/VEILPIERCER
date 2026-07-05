# VeilPiercer Audit Report — UniswapV2Pair_Reentrancy
**Hash:** 911d646364a52771 | **Date:** 2026-07-05 14:21 UTC

## Summary
| Metric | Value |
|--------|-------|
| Contract | UniswapV2Pair_Reentrancy |
| SHA-256 | 911d646364a52771 |
| Total findings | 2 |
| Critical | 0 |
| High | 2 |
| Medium | 0 |
| Low | 0 |
| Informational | 0 |

## Findings

### 1. reentrancy — HIGH
**Lines:** 15
**Exploit chain:** external call before state update - attacker re-enters - drains funds

### 2. signature_replay — HIGH
**Lines:** 15
**Exploit chain:** missing nonce/chainId in signature - replay attack - unauthorized actions

---
*Audited by VeilPiercer v2.2 — [Verify](https://veilpiercer.fly.dev/verify) · [Dashboard](https://veilpiercer.fly.dev/dashboard)*
