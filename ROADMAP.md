# VeilPiercer Roadmap

Pick a task, open an issue, and submit a PR. Every task below includes the expected impact and files to touch.

## How to Contribute

1. Pick a task below
2. Comment on the linked issue (or create one if none exists)
3. Follow the [CONTRIBUTING.md](CONTRIBUTING.md) pattern-authoring guide
4. Submit a PR with confusion matrix data

---

## P0 — High Impact, Low Effort (good first issues)

### Add detection pattern for `delegatecall` to untrusted addresses
- **Impact:** Catches proxy upgrade vulnerabilities (SWC-112)
- **Files:** `training/cli/bounty_hunter_elite.py` → `VULN_PATTERNS`
- **Guide:** See [example PR](docs/example-pr-tx-origin-auth.md)
- **Labels:** `good first issue`, `pattern`

### Add detection pattern for unbounded loops over arrays
- **Impact:** Catches DoS via gas exhaustion (SWC-128)
- **Files:** `training/cli/bounty_hunter_elite.py` → `VULN_PATTERNS`
- **Labels:** `good first issue`, `pattern`

### Add detection pattern for `block.timestamp` manipulation
- **Impact:** Improves frontrunning detection precision (separate from legitimate `block.*` usage)
- **Files:** `training/cli/bounty_hunter_elite.py` → `VULN_PATTERNS`
- **Labels:** `good first issue`, `pattern`

### Improve `rounding_error` precision
- **Problem:** 49% hit rate — fires on benign division. Split into `safe_division` (uses SafeMath) vs `unsafe_division` (raw `/` operator).
- **Impact:** Reduces FP rate by ~20%
- **Files:** `training/cli/bounty_hunter_elite.py` → split `rounding_error` pattern
- **Labels:** `good first issue`, `cleanup`

### Reduce `frontrunning` false positives
- **Problem:** 38% hit rate — `block.timestamp` and `block.number` used in many legitimate patterns
- **Impact:** Drops FP rate below 20%
- **Approach:** Only flag when `block.timestamp` is used in comparison operators (`>=`, `<=`, `==`) not just referenced
- **Files:** `training/cli/bounty_hunter_elite.py` → refine `frontrunning` patterns
- **Labels:** `good first issue`, `cleanup`

---

## P1 — Medium Effort, High Impact

### Multi-contract vulnerability detection
- **Problem:** Scanner analyzes one contract at a time. Proxy upgrades and cross-contract reentrancy are invisible.
- **Approach:** When scanning a project with multiple `.sol` files, track `delegatecall` targets and verify they're not selfdestruct-able
- **Impact:** Catches a class of bugs currently at 0% detection
- **Files:** New module `training/cli/cross_contract.py`, update `bounty_hunter_elite.py`
- **Labels:** `enhancement`, `architecture`

### Slither-Mythril consensus scoring
- **Problem:** Regex scanner has high recall (69%) but high FP rate. Slither has low recall (22%) but low FP rate (19%).
- **Approach:** Findings confirmed by ≥2 scanners get elevated confidence + severity
- **Impact:** Combined precision improves, fewer false alarms
- **Files:** `web/sias_server.py` → update scan handler, `training/cli/bounty_hunter_elite.py`
- **Labels:** `enhancement`, `accuracy`

### Solidity version-aware patterns
- **Problem:** Patterns don't account for compiler version. 0.8.0 auto-overflow checks make `arithmetic` patterns obsolete for newer contracts.
- **Approach:** Parse `pragma solidity ^X.Y.Z` and skip patterns that the compiler already prevents
- **Impact:** Reduces false positives on 0.8.x contracts
- **Files:** `training/cli/bounty_hunter_elite.py` → `scan_contract()`
- **Labels:** `enhancement`

---

## P2 — Infrastructure & Community

### Docker Compose one-command deployment
- **Problem:** Server requires manual Python setup
- **Approach:** Single `docker compose up` that starts the web server, persists stats volume, auto-restarts
- **Files:** `docker/Dockerfile`, `docker/docker-compose.yml` (already in progress)
- **Labels:** `infrastructure`, `deployment`

### Per-contest weekly trend analysis
- **Problem:** Weekly report shows aggregate numbers. No per-contest breakdown.
- **Approach:** Add contest-type classification to `train_pipeline.py --full` output
- **Impact:** Community can see which contest categories produce the most findings
- **Files:** `training/train_pipeline.py`
- **Labels:** `data`, `community`

### Community dashboard embed
- **Problem:** Community stats only visible on `/community` page
- **Approach:** Embeddable `<iframe>` widget that protocols can add to their docs showing their verification status
- **Files:** New `web/widget.html`, `web/sias_server.py` → `/widget/<hash>` route
- **Labels:** `community`, `ui`

---

## Roadmap Timeline

```
v2.2 (NOW)     → Persistence, Community Leaderboard, Verified Badge
v2.3 (Jul)     → P0 patterns (5 new + 2 cleanup), Docker deploy
v2.4 (Aug)     → Multi-contract detection, Slither-Mythril consensus
v2.5 (Sep)     → Per-contest trends, Community widgets, Solidity version awareness
```

---

*Labels reference: `good first issue` = ≤2 files changed, pattern guide covers it. `pattern` = new detection rule. `cleanup` = reduce false positives. `enhancement` = new feature.*
