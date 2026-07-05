# Contributing to VeilPiercer

VeilPiercer grows by adding detection patterns that catch real vulnerabilities found in audits and contests. This guide shows you how to add a new pattern, test it, and submit it.

## How to Add a New Detection Pattern

### Step 1: Find a real vulnerability

Every new pattern must be based on a **confirmed real-world bug**. Sources:
- [Code4rena](https://code4rena.com) findings (search for "high" or "medium" severity)
- [Sherlock](https://audits.sherlock.xyz) contest reports
- [Immunefi](https://immunefi.com) bug bounty disclosures
- [SWC Registry](https://swcregistry.io) (Smart Contract Weakness Classification)
- [Solodit](https://solodit.xyz) — aggregated audit findings

Pick a finding that had an **actual exploit path**, not just a theoretical concern.

### Step 2: Reduce to a minimal contract

Strip the finding down to the smallest possible Solidity snippet that still demonstrates the vulnerability. Example for a reentrancy pattern:

```solidity
// BEFORE: 200-line DeFi protocol
contract MinimalReentrancy {
    mapping(address => uint) balances;

    function withdraw() external {
        uint amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;  // state update AFTER external call
    }
}
```

Keep it under 30 lines. The smaller the contract, the easier it is to verify the pattern doesn't fire on unrelated code.

### Step 3: Write the regex pattern(s)

Open `cli/bounty_hunter_elite.py` and find `VULN_PATTERNS` (line ~163). Pick the best-matching category, or create a new one.

**Pattern rules:**
1. Use raw strings: `r'your pattern'`
2. Be specific — a pattern that fires on every contract is noise, not detection
3. Prefer 3-5 tight patterns over one loose one
4. Test your regex against the **negative set** (known bug-free contracts) — it must not fire there

**Example — adding a `tx.origin` pattern:**

```python
"tx_origin_auth": {
    "severity": "high",
    "patterns": [
        r'tx\.origin\s*==',
        r'require\s*\(\s*tx\.origin',
        r'msg\.sender\s*==\s*address\(uint160\(tx\.origin',
    ],
    "exploit_chain": "tx.origin used for auth — phishing contract can proxy calls — bypass access control",
},
```

**Anti-examples (do NOT use):**
- `r'require\('  — fires on every contract
- `r'function'`  — useless
- `r'address'`   — also useless

### Step 4: Validate — confusion matrix

Run the test suite against the full contract corpus:

```bash
cd ~/veilpiercer
python3 train_pipeline.py --full
```

Check the output for:
- **TP (true positives):** Did your pattern catch the intended vulnerability?
- **FP (false positives):** Did it fire on contracts that DON'T have that bug?

A good pattern has:
- Recall ≥ 80% on the target vulnerability class
- FP rate ≤ 5% across the full corpus (fires on < 1 in 20 bug-free contracts)

If your pattern fires on more than 5% of contracts in the negative set, tighten the regex or add a prerequisite pattern.

### Step 5: Update the confusion matrix

At the top of `bounty_hunter_elite.py` (line ~40-90), update the confusion matrix table with your new category. Include:

```
CATEGORY              TP  FP  FN  TN   RECALL
new_pattern_name       1   0   0  16   100%
```

Run `train_pipeline.py --full` to get the actual numbers — don't estimate.

### Step 6: Submit

Push to a branch and open a PR against `main`. Include in the PR description:

1. **Link to the original finding** (Code4rena / Sherlock / SWC)
2. **Minimal vulnerable contract** (the one you tested against)
3. **Confusion matrix row** for your pattern
4. **List of FPs** if any (which contracts it fired on, and why it's acceptable)

## Pattern Categories Reference

| Category | Severity | What it catches |
|----------|----------|-----------------|
| `reentrancy` | high | External calls before state updates |
| `access_control` | informational | Missing onlyOwner on privileged functions |
| `arithmetic` | high | Unchecked math, overflow, SafeMath gaps |
| `flash_loan` | high | Flash loan attack surfaces, price manipulation |
| `frontrunning` | medium | Block-dependent logic, predictable randomness |
| `signature_replay` | high | Missing nonce/chainId in signature verification |
| `storage_collision` | high | Proxy upgrade patterns, delegatecall risks |
| `rounding_error` | medium | Integer division truncation |

## Accuracy Standards

Our confusion matrix (69% recall, 94% FP rate on regex) is honest about limitations. Every pattern you add should improve one of these numbers:

- **Improve recall:** Add patterns that catch known bugs we miss (e.g., flash loan detection at 0% recall)
- **Reduce false positives:** Tighten existing patterns that fire too broadly, or remove patterns that can't be salvaged

A pattern that adds 1 TP at the cost of 10 FP is a regression. A pattern that adds 1 TP with 0 FP is a win.

## Testing Setup

```bash
# Clone contracts corpus
git clone https://github.com/ZhangZhuoSJTU/Web3Bugs ~/Web3Bugs

# Run full benchmark (all contracts)
cd ~/veilpiercer
export VP_CONTRACT_DIR=~/Web3Bugs/contracts
python3 train_pipeline.py --full

# Run CI gates (strict)
python3 train_pipeline.py --ci
```

## Pull Request Checklist

- [ ] Pattern based on a confirmed real-world finding (link provided)
- [ ] Minimal reproducible contract included in PR description
- [ ] Confusion matrix row computed from `--full` run (not estimated)
- [ ] Zero new false positives on the 39-contract corpus (or justified)
- [ ] `train_pipeline.py --ci` passes (dep resolution ≥ 92%, zero privacy violations)
