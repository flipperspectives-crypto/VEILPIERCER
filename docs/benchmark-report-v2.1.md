# VeilPiercer v2.1 — Public Benchmark Report

**Date:** 2026-07-05  
**Pipeline:** `train_pipeline.py --full`  
**Corpus:** 39 contracts (1 per contest) from 225 available in Web3Bugs  
**Test environment:** Android/Termux, Python 3.14, no GPU  

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Contracts scanned | 39 (across 39 contests) |
| Total imports analyzed | 158 |
| Dependency resolution | **100%** (npm 100% · relative 100%) |
| Total findings | **110** |
| Critical / High / Medium / Info | 0 / 41 / 34 / 35 |
| Avg scan time | 0.02s per contract |
| Total pipeline time | 0.9s |
| Privacy violations | **0** |
| Regression drifts | **0** |
| CI gates | ✅ ALL PASSED |

---

## Per-Pattern Hit Rates

| Pattern | Severity | Contracts Hit | Hit Rate | Assessment |
|---------|----------|---------------|----------|------------|
| `access_control` | informational | 35 / 39 | **90%** | ⚠️ Noisy — fires on nearly every contract |
| `rounding_error` | medium | 19 / 39 | 49% | ⚠️ Noisy — matches benign division |
| `frontrunning` | medium | 15 / 39 | 38% | ⚠️ Matches legitimate block.* usage |
| `arithmetic` | high | 14 / 39 | 36% | ⚠️ SafeMath + unchecked flagged indiscriminately |
| `reentrancy` | high | 12 / 39 | 31% | ⚠️ `.transfer(` flagged despite 2300 gas limit |
| `storage_collision` | high | 8 / 39 | 21% | Mixed — proxy patterns, needs refinement |
| `signature_replay` | high | 4 / 39 | 10% | Targeted — mostly accurate |
| `flash_loan` | high | 2 / 39 | 5% | ❌ Under-detects — 0% recall on flash loan tests |
| `tx_origin_auth` | high | 1 / 39 | 3% | ✅ Targeted — low noise, high precision (added v2.1) |

### Confusion Matrix (from 34-contract labeled set)

| Category | TP | FP | FN | TN | Recall |
|----------|----|----|----|----|--------|
| Regex scanner (combined) | 9 | 29 | 4 | 307 | **69%** |
| Slither (comparison) | — | — | — | — | 22% |

**Key tradeoff:** Regex scanner has 3x higher recall than Slither (69% vs 22%) but **15x higher contract-level FP rate** (94% vs 19%). The scanner finds surface area fast; Slither provides precision.

---

## Top 5 Concrete Improvements for v2.2

These are grounded in the benchmark data above. Each includes the metric it targets and the expected impact.

### 1. Split `access_control` into Detection + Hygiene

**Problem:** `access_control` fires on 90% of contracts (35/39), accounting for 32% of all findings. The pattern matches legitimate `onlyOwner` / `Ownable` usage — not missing access control. This single detector produces 11/29 false positives (38% of all noise).

**Fix:** Split into two patterns:
- `uses_access_control` (informational) — contract implements access control patterns (normal, not a bug)
- `missing_access_control` (high) — privileged state-changing function lacks `onlyOwner` or equivalent modifier

**Expected impact:** Drops contract-level FP rate from 94% to ~60%, increases high-signal findings.

### 2. Flash Loan Vulnerability Detection

**Problem:** 0% recall on flash loan vulnerabilities. The scanner finds contracts mentioning "flashLoan" (2 hits) but misses actual price manipulation / borrow-attack-repay patterns. Three confirmed flash loan bugs (S03, S04, S06) go completely undetected.

**Fix:** Add patterns for:
- Price oracle reads inside unprotected functions (`getReserves()` + external call)
- Borrow → state change → repay within same transaction
- Missing slippage/deadline on swap functions called by flash loan receivers

**Expected impact:** +3 TP, recall from 0% to 75% on flash loan category.

### 3. Slither Integration as Second-Pass Filter

**Problem:** Regex scanner has 94% FP rate at contract level. Every contract gets flagged. Users can't distinguish real bugs from noise without manual triage.

**Fix:** Run Slither as a confirmation pass on regex-positive contracts:
- Regex finds candidate patterns → Slither confirms with data-flow analysis
- Findings confirmed by BOTH scanners get elevated severity
- Regex-only findings (no Slither confirmation) drop to informational

**Expected impact:** Combined precision improves significantly — Slither's 19% FP filters out regex noise without losing Slither's recall.

### 4. Severity Recalibration with Context Awareness

**Problem:** Severity is assigned per-pattern, not per-instance. `reentrancy` is always HIGH, even when the pattern matches `.transfer(` (2300 gas, not reentrant). `access_control` is informational but still clutters output.

**Fix:** Context-aware severity:
- `.transfer(` / `.send(` → downgrade to informational (2300 gas limit)
- `.call{value:` without checks-effects-interactions → keep HIGH
- `onlyOwner` present on all state-changing functions → informational (good pattern, not a bug)
- `onlyOwner` missing from a function that changes `owner` → HIGH

**Expected impact:** Fewer false-HIGH findings, more actionable HIGH findings.

### 5. Full-Corpus Benchmarking (225 Contracts)

**Problem:** Only 39 contracts are scanned (1 per contest) out of 225 available. Statistical power is limited. Per-contest trends (which vulnerability types appear in which contest categories) are invisible.

**Fix:** Remove the `1-per-contest` limit in `benchmark_contracts()`. Scan all 225 contracts. Add per-contest breakdown to the report (contest 105: 3 reentrancy + 1 access_control, contest 17: 1 tx_origin + 1 flash_loan, etc.).

**Expected impact:** 5.7x more data points, better FP rate estimates, contest-type trend analysis for targeted pattern improvements.

---

## CI Gate Status

| Gate | Threshold | Actual | Status |
|------|-----------|--------|--------|
| Dep resolution | ≥ 92% | **100%** | ✅ |
| Privacy violations | 0 | **0** | ✅ |
| Regression drifts | 0 | **0** | ✅ |

---

## Limitations

- **Single-contract analysis only.** Cross-contract vulnerabilities (proxy upgrades, multi-contract reentrancy) are not detected.
- **No Solidity version-specific checks.** Patterns don't account for compiler version changes (e.g., 0.8.0 auto-overflow checks).
- **Android environment constraints.** Slither and Mythril integration tested on Linux/Docker; Android Termux has limited binary compatibility.
- **94% FP rate** means manual triage is required for every scan. This tool is a triage scanner, not an audit replacement.

---

*Report generated by VeilPiercer Training Pipeline v1.0 · `train_pipeline.py --full`*  
*Dashboard: https://veilpiercer.fly.dev/dashboard*  
*API: https://veilpiercer.fly.dev/api/stats*
