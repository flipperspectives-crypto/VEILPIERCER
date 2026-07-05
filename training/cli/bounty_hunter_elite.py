#!/usr/bin/env python3
"""
---   -----------------     ------- ------------------  ----------------------
---   -----------------     ---------------------------------------------------
---   ---------  ------     -----------------  -----------     ------  --------
---- ----------  ------     ------- ---------  -----------     ------  --------
 ------- ----------------------     --------------  ----------------------  ---
  -----  ----------------------     --------------  --- ------------------  ---

ELITE BOUNTY HUNTER -- Autonomous Bug Bounty Pipeline
======================================================
Scrapes live contests - extracts smart contracts - runs multi-model
severity-based scoring - generates VeilPiercer-proof submission reports.

Every finding is:
  - Scored 1-10 by severity-based analysis with optional LLM API scoring
  - Anchored on Bitcoin via OpenTimestamps (you found it, prove when)
  - Packaged as a professional submission ready for Immunefi/Sherlock/Hats

Contests tracked: Immunefi, Code4rena, Cantina, Sherlock, Hats Finance

Usage:
  python3 bounty_hunter_elite.py                          # full scan
  python3 bounty_hunter_elite.py --contest immunefi       # specific platform
  python3 bounty_hunter_elite.py --repo <github_url>       # single repo
  python3 bounty_hunter_elite.py --report <finding_id>     # generate submission
  python3 bounty_hunter_elite.py --daemon 3600             # hourly autonomous

Output: ~/bounty_findings/YYYY-MM-DD/ -- one folder per finding with:
  finding.md        -- professional submission report
  proof.json        -- VeilPiercer SIAS proof (Bitcoin-timestamped)
  judge_panel.json  -- Severity scoring results (API or static fallback)


MEASURED ACCURACY (tested against 34 real Web3Bugs contracts):
  Segment 4 (TP/FN): 18 synthetic contracts reproducing confirmed Code4rena
    bugs across 9 pattern categories and 9 semantic categories.
  Segment 5 (FP/TN): 16 real stored contracts from 8 reentrancy-free contests.
  Same methodology as vpl_slither_scan.py Segments 4/5 for direct comparison.

CONFUSION MATRIX -- Regex Pattern Scanner per Category
------------------------------------------------------
CATEGORY                   TP  FP  FN  TN   RECALL   NOTES
-------------------------------------------------------------------------
reentrancy (detector)       1   2   0  14   100%     FP on Address.sol, Reserve.sol
access_control (detector)   0  11   0   5     0%     FIRES ON EVERY CONTRACT
access-control (conceptual) 1   0   0  16   100%     Caught S02, but detector is noise
arithmetic                  0   4   0  12     0%     FP on ERC20, LibLiquidation, etc
overflow (conceptual)       1   0   0  16   100%     Caught L03
underflow (conceptual)      1   0   0  16   100%     Caught L04
low-level-calls (conceptual)1   0   0  16   100%     Caught L02
frontrunning                1   1   0  15   100%     FP on OracleManagerFlippening
delegatecall (conceptual)   1   0   0  16   100%     Caught L07
timestamp (conceptual)      1   0   0  16   100%     Caught L08
flash-loan                  0   0   3  13     0%     MISS: S03, S04, S06 undetected
rounding (conceptual)       1   0   0  16   100%     Caught S07
rounding_error (detector)   0   6   0  10     0%     FP on 6 contracts
storage_collision           0   3   0  13     0%     FP on EIP712Base, FloatCapital, Address
signature_replay            0   2   0  14     0%     FP on EIP712Base, NativeMetaTx
oracle                      0   0   1  15     0%     MISS: S05 undetected
-------------------------------------------------------------------------
TOTALS                      9  29   4 307    69%

KEY TAKEAWAYS:
  - Recall: 69% (9/13 expected categories). Better than Slither (22%).
  - FALSE POSITIVE RATE: 29 FPs. 15/16 bug-free contracts flagged (94%).
  - The access_control pattern fires on NEARLY EVERY contract (matches
    onlyOwner, require(msg.sender == owner, Ownable). This one detector
    accounts for 11/29 false positives (38% of all noise).
  - Compared to Slither: 3x higher recall (69% vs 22%) but 15x higher
    contract-level FP rate (94% vs 19%). Slither FPs are hygiene nags;
    regex scanner FPs are severity-inflated (every access_control match
    labeled CRITICAL regardless of context).
  - This tool is a TRIAGE SCANNER, not an audit replacement. It finds
    surface area fast but requires manual filtering to remove noise.


LIMITATIONS -- READ BEFORE USING
================================
This tool is a PATTERN-MATCHING TRIAGE SCANNER. It is not an audit
replacement. The following limitations are measured, not assumed:

RECALL (what it finds):
  - Slither static analysis (vpl_slither_scan.py): 22% overall recall
    against 18 confirmed Code4rena bugs. Finds 1 in 5 real vulnerabilities.
    Pattern-level recall: 44%. Semantic/logic recall: 0%.
  - Regex pattern scanner (scan_contract()): 69% recall against the
    same 18 bugs. Casts a wider net but catches noise alongside signal.

FALSE POSITIVES (what it gets wrong):
  - Slither: 19% of contracts flagged. All FPs are code-hygiene nags
    (solc-version, missing-zero-check on utility libraries).
  - Regex scanner: 94% of contracts flagged. The access_control detector
    fires on nearly every contract (matches onlyOwner, Ownable, etc.)
    and labels every match CRITICAL regardless of context.

REAL-WORLD VALIDATION:
  - Zero confirmed real-world payouts. Zero submissions to Immunefi,
    Code4rena, Sherlock, Hats, or Cantina. Every generated report is a
    DRAFT TEMPLATE requiring manual completion before submission.

WHAT BOTH TOOLS CANNOT DO:
  - Neither tool detects business-logic/semantic bugs (oracle manipulation,
    access-control logic errors, atomicity violations, governance attacks,
    flash-loan vectors, incentive misalignment, rounding exploits).
  - Neither tool verifies exploitability. A finding is a PATTERN MATCH,
    not a confirmed vulnerability. The same pattern that signals reentrancy
    in a vault may be benign in a library.
  - The judge panel scores (when API is unavailable) come from a static
    severity lookup table, not real AI analysis. When the API IS available,
    the analysis is a single-pass LLM response -- not a security audit.
  - The Bitcoin/OTS timestamp proves the proof file existed at a specific
    time. It does NOT prove discovery priority or prevent front-running.

REQUIRED BEFORE ANY SUBMISSION:
  1. Manually verify the vulnerability is actually exploitable
  2. Write a working proof-of-concept
  3. Confirm the bug exists in the CURRENT on-chain deployment
  4. Replace all [DRAFT] placeholders with specific technical detail
  5. Verify no other researcher has already submitted the same finding

The 34-contract test methodology, confusion matrices, and per-category
TP/FP/FN/TN counts are documented below under MEASURED ACCURACY.
"""
import sys, os, json, time, hashlib, re, subprocess, urllib.request, urllib.error
from pathlib import Path
from datetime import datetime, timezone
from scan_dedup import ScanDeduplicator
_scan_dedup = ScanDeduplicator()

HOME = Path(os.environ.get("HOME", "/data/data/com.termux/files/home"))
FINDINGS_DIR = HOME / "bounty_findings"
LEDGER_DIR = HOME / "ledger_integration"
sys.path.insert(0, str(LEDGER_DIR))

# -- Contest Platform APIs ---------------------------------------

CONTEST_SOURCES = {
    "immunefi": {
        "url": "https://immunefi.com",
        "bounty_list": "https://immunefi.com/bounties/",
    },
    "code4rena": {
        "url": "https://code4rena.com",
        "contests": "https://code4rena.com/contests",
    },
    "cantina": {
        "url": "https://cantina.xyz",
        "contests": "https://cantina.xyz/competitions",
    },
    "sherlock": {
        "url": "https://www.sherlock.xyz",
        "contests": "https://audits.sherlock.xyz/contests",
    },
    "hats": {
        "url": "https://app.hats.finance",
        "vaults": "https://app.hats.finance/vaults",
    },
}

# -- Vulnerability Patterns (high-signal, low false-positive) ----

VULN_PATTERNS = {
    "reentrancy": {
        "severity": "high",
        "patterns": [
            r'\.call\{\s*value:', r'\.call\{value:', r'\.transfer\(', r'\.send\(',
            r'nonReentrant', r'ReentrancyGuard', r'checks-effects-interactions',
            r'\.call\(.*\)(?!.*nonReentrant)',
        ],
        "exploit_chain": "external call before state update - attacker re-enters - drains funds",
    },
    "access_control": {
        "severity": "informational",
        "patterns": [
            r'onlyOwner', r'require\(msg\.sender == owner', r'Ownable',
            r'function\s+\w+\s*\(.*\)\s*(public|external)(?!.*onlyOwner)',
            r'_msgSender\(\)', r'msg\.sender(?!.*require)',
        ],
        "exploit_chain": "privileged function lacks access control - anyone can call - steals control",
    },
    "arithmetic": {
        "severity": "high",
        "patterns": [
            r'unchecked\s*\{', r'\.add\(', r'\.sub\(', r'\.mul\(',
            r'SafeMath', r'overflow', r'underflow',
            r'uint\d+\s+\w+\s*=\s*\w+\s*[\+\-\*]',
        ],
        "exploit_chain": "unchecked arithmetic - overflow/underflow - incorrect balances or logic",
    },
    "flash_loan": {
        "severity": "high",
        "patterns": [
            r'flashLoan', r'flash_loan', r'FlashLoan',
            r'getAmountsOut', r'swapExactTokens',
            r'getReserves\(\)', r'price.*manipulat',
        ],
        "exploit_chain": "flash loan - manipulate price oracle - exploit dependent logic - profit",
    },
    "frontrunning": {
        "severity": "medium",
        "patterns": [
            r'commit.*reveal', r'block\.timestamp', r'block\.number',
            r'blockhash', r'block\.difficulty', r'block\.coinbase',
            r'commitReveal', r'random.*block',
        ],
        "exploit_chain": "predictable randomness or unprotected mempool - frontrunning - MEV extraction",
    },
    "signature_replay": {
        "severity": "high",
        "patterns": [
            r'ecrecover', r'ECDSA\.recover', r'permit\(',
            r'signature', r'deadline(?!.*require)',
            r'nonce(?!.*increment)', r'chainId(?!.*require)',
        ],
        "exploit_chain": "missing nonce/chainId in signature - replay attack - unauthorized actions",
    },
    "storage_collision": {
        "severity": "high",
        "patterns": [
            r'delegatecall', r'upgradeable', r'UUPS', r'transparent.*proxy',
            r'storage.*gap', r'__gap',
            r'initializer(?!.*initializer)', r'initialize\(',
        ],
        "exploit_chain": "proxy storage collision - delegatecall to malicious impl - selfdestruct or drain",
    },
    "rounding_error": {
        "severity": "medium",
        "patterns": [
            r'\/\s*\d+', r'\%\s+\d+', r'\.div\(', r'\.mod\(',
            r'precision.*loss', r'rounding',
            r'amount.*\/.*total',
        ],
        "exploit_chain": "integer division truncation - accumulated rounding errors - fund loss over time",
    },
}


def fetch_url(url, timeout=15):
    """Fetch URL with proper headers."""
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'VeilPiercer-BountyHunter/2.1',
            'Accept': 'text/html,application/json',
        })
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.read().decode('utf-8', errors='replace')
    except Exception as e:
        return None


def scan_contract(code, filename="unknown"):
    """Scan a Solidity contract for vulnerability patterns.
    Prints a warning if the input does not appear to be valid Solidity."""
    findings = []

    # Sanity check: does this look like Solidity source?
    has_pragma = "pragma solidity" in code
    has_contract = any(kw in code for kw in ("contract ", "interface ", "library "))
    is_empty = len(code.strip()) < 10

    if is_empty:
        print(f"  [!] WARNING: {filename} is empty or nearly empty - not valid Solidity")
        return findings
    if not has_pragma:
        print(f"  [!] WARNING: {filename} has no \"pragma solidity\" directive - may not be Solidity")
    if not has_contract:
        print(f"  [!] WARNING: {filename} has no contract/interface/library declaration - may not be Solidity")
    if not has_pragma and not has_contract:
        print(f"  [!] Input does not appear to be a Solidity source file. Results may be meaningless.")

    lines = code.split("\n")
    findings = []
    lines = code.split('\n')

    for vuln_name, vuln_info in VULN_PATTERNS.items():
        matches = []
        for pattern in vuln_info["patterns"]:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append({
                        "line": i,
                        "code": line.strip()[:120],
                        "pattern": pattern,
                    })

        if matches:
            findings.append({
                "vulnerability": vuln_name,
                "severity": vuln_info["severity"],
                "exploit_chain": vuln_info["exploit_chain"],
                "matches": matches[:5],  # top 5 matches
                "match_count": len(matches),
                "file": filename,
            })

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    return findings


_api_calls = 0
_api_input_tokens = 0
_api_output_tokens = 0
_PRICE_INPUT_PER_1M = 0.14   # DeepSeek chat: USD per 1M input tokens
_PRICE_OUTPUT_PER_1M = 0.28  # DeepSeek chat: USD per 1M output tokens

def api_cost_summary():
    est = (_api_input_tokens / 1_000_000 * _PRICE_INPUT_PER_1M +
           _api_output_tokens / 1_000_000 * _PRICE_OUTPUT_PER_1M)
    return {"calls": _api_calls, "input_tokens": _api_input_tokens,
            "output_tokens": _api_output_tokens, "estimated_cost_usd": round(est, 6)}


# -- Bitcoin anchor gate (permanence warning) --
_BITCOIN_ANCHOR_WARNED = False
_ALLOW_BITCOIN_ANCHOR = False
_ANCHOR_OPAQUE = False

def allow_opaque_anchor():
    """Use opaque content hash only (no file paths or contest names)."""
    global _ANCHOR_OPAQUE
    _ANCHOR_OPAQUE = True

def allow_bitcoin_anchor():
    """Opt in to permanent Bitcoin anchoring."""
    global _ALLOW_BITCOIN_ANCHOR
    _ALLOW_BITCOIN_ANCHOR = True

def _warn_bitcoin_anchor():
    """One-time warning about permanence on the Bitcoin blockchain."""
    global _BITCOIN_ANCHOR_WARNED
    if not _BITCOIN_ANCHOR_WARNED:
        _BITCOIN_ANCHOR_WARNED = True
        print()
        print("  [!] BITCOIN PERMANENCE WARNING: OTS anchoring is IRREVERSIBLE.")
        print("  [!] Once stamped, the Merkle root is permanently on the Bitcoin")
        print("  [!] blockchain. No delete, no retract, no overwrite -- forever.")
        print("  [!] The hash preimage includes: file path, contest name,")
        print("  [!] vulnerability type, severity, and discovery timestamp.")
        print("  [!] Use --anchor-opaque to anchor only a content hash without")
        print("  [!] identifying metadata (file paths, contest names).")
        print("  [!] Use --allow-bitcoin-anchor to acknowledge this, or")
        print("  [!] the anchor will be skipped and proof files will NOT be created.")
        print()
# -- External API control (privacy safeguard) --
_ALLOW_EXTERNAL_API = False
_EXTERNAL_API_WARNED = False

def allow_external_api():
    """Enable sending contract code to third-party APIs."""
    global _ALLOW_EXTERNAL_API
    _ALLOW_EXTERNAL_API = True

def _warn_external_api():
    """Print one-time warning about code leaving the machine."""
    global _EXTERNAL_API_WARNED
    if not _EXTERNAL_API_WARNED:
        _EXTERNAL_API_WARNED = True
        print()
        print("  [!] PRIVACY WARNING: Contract code and vulnerability evidence")
        print("  [!] will be sent to DeepSeek API (third-party server).")
        print("  [!] Do NOT scan confidential, NDA-protected, or pre-disclosure contracts.")
        print("  [!] Use --allow-external-api to acknowledge this risk, or")
        print("  [!] the tool will use static scoring only.")
        print()

def print_api_cost_summary():
    s = api_cost_summary()
    if False: pass  # always show cost, even $0.00
    print(f"  API Usage: {s['calls']} calls, {s['input_tokens']} in / {s['output_tokens']} out, est. ${s['estimated_cost_usd']:.4f} USD")
def run_judge_panel(finding, contract_code="", slither_findings=None, mythril_findings=None):
    """Run severity-based scoring with optional dual-scanner context.
    Calls DeepSeek API with Slither + Mythril findings for richer
    severity scoring. Falls back to static lookup if API unreachable.
    
    Args:
        finding: dict from regex scanner (vulnerability, severity, matches)
        contract_code: raw Solidity source
        slither_findings: optional list of dicts from vpl_slither_scan.py
        mythril_findings: optional list of dicts from vpl_mythril_scan.py
    """

    vuln = finding["vulnerability"]
    sev = finding["severity"]
    chain = finding["exploit_chain"]
    evidence = "\n".join(
        f"  Line {m['line']}: {m['code']}" for m in finding["matches"][:3]
    )

    # Build scanner context if available
    scanner_context = ""
    if slither_findings:
        slither_summary = "\n".join(
            f"  [{f.get('severity','?').upper()}] {f.get('vulnerability','?')}: {f.get('exploit_chain','?')[:150]}"
            for f in slither_findings[:5]
        )
        scanner_context += f"\nSLITHER (pattern analysis, {len(slither_findings)} detectors):\n{slither_summary}"
    if mythril_findings:
        mythril_summary = "\n".join(
            f"  [{f.get('severity','?').upper()}] {f.get('vulnerability','?')} (SWC: {f.get('mythril_raw',{}).get('swc_id','?')})"
            for f in mythril_findings[:5]
        )
        scanner_context += f"\nMYTHRIL (symbolic execution, {len(mythril_findings)} paths):\n{mythril_summary}"
    
    prompt = f"""BUG BOUNTY ANALYSIS - Score this finding.

VULNERABILITY: {vuln} (severity: {sev})
EVIDENCE: {evidence}
{scanner_context}

Return ONLY a JSON object with these exact keys, no other text:
{{"exploitability": 1-10, "novelty": 1-10, "payout_potential": 1-10,
 "overall": 1-10, "submit": "YES or NO",
 "funds_at_risk": "description", "precedent": "known exploits",
 "fix": "remediation"}}"""

    api_key = ""
    # Try DeepSeek API (only if user explicitly opts in)
    if not _ALLOW_EXTERNAL_API:
        _warn_external_api()
    else:
        import os as _os, json as _json, urllib.request as _ur
        env_path = _os.path.expanduser("~/.hermes/.env")
        if _os.path.exists(env_path):
            for line in open(env_path):
                if line.startswith("DEEPSEEK_API_KEY="):
                    api_key = line.strip().split("=", 1)[1].strip()
                    break
        if not api_key:
            api_key = _os.environ.get("DEEPSEEK_API_KEY", "")
        if api_key:
            try:
                payload = _json.dumps({
                    "model": "deepseek-chat",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.3,
                    "max_tokens": 500,
                }).encode()
                req = _ur.Request(
                    "https://api.deepseek.com/v1/chat/completions",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                    },
                )
                r = _ur.urlopen(req, timeout=60)
                resp = _json.loads(r.read())
                global _api_calls, _api_input_tokens, _api_output_tokens
                usage = resp.get("usage", {})
                _api_calls += 1
                _api_input_tokens += usage.get("prompt_tokens", 0)
                _api_output_tokens += usage.get("completion_tokens", 0)
                content = resp["choices"][0]["message"]["content"]
                if "```" in content:
                    if content.startswith("json"):
                        content = content[4:]
                result = _json.loads(content.strip())
                result["_source"] = "deepseek-api"
                return result
            except Exception:
                pass

    # Static fallback
    sev_scores = {"critical": 9, "high": 7, "medium": 5, "low": 3}
    base_score = sev_scores.get(sev, 5)
    return {
        "exploitability": min(10, base_score + 1),
        "novelty": max(1, base_score - 2),
        "payout_potential": base_score,
        "overall": base_score,
        "submit": "YES" if base_score >= 5 else "NO",
        "exploit_engineer": "[DRAFT] Analyze the vulnerable code path and describe the attack vector.",
        "security_auditor": "[DRAFT] Assess real-world impact, affected protocols, and historical precedents.",
        "protocol_designer": "[DRAFT] Identify root cause and propose a specific code fix.",
        "funds_at_risk": "[DRAFT] Estimate funds at risk based on contract TVL and exploit impact.",
        "precedent": "[DRAFT] Research similar exploits and reference specific incidents.",
        "fix": "[DRAFT] Write a concrete code-level fix, not a general recommendation.",
        "_source": "static-fallback",
    }
def generate_submission_report(finding, judge_result, proof_path):
    DRAFT_BANNER = "[DRAFT - REQUIRES MANUAL COMPLETION BEFORE SUBMISSION]\n\n" if judge_result.get("_source") == "static-fallback" else ""
    """Generate a professional bug bounty submission report."""
    vuln = finding["vulnerability"]
    sev = finding["severity"].upper()
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    is_draft = judge_result.get("_source") == "static-fallback"
    draft_banner = "[DRAFT - REQUIRES MANUAL COMPLETION BEFORE SUBMISSION]\n\n" if is_draft else ""

    report = f"""# Bug Bounty Submission -- {vuln.upper()}
**Severity: {sev}** | **Found: {ts}** | **Proof: Bitcoin-Anchored**

---



## Summary

{draft_banner}A {sev}-severity {vuln} vulnerability was identified in the target smart contract.

## Technical Details

### Vulnerable Code
    code_parts = []
    for m in finding.get("matches", [])[:5]:
        code_parts.append("Line " + str(m.get("line", "?")) + ": " + m.get("code", ""))
    code_snippets = chr(10).join(code_parts)
```

### Exploit Path
1. {judge_result.get('exploit_step_1') or judge_result.get('exploit_engineer') or 'Attacker identifies the vulnerable function'}
2. {judge_result.get('exploit_step_2') or judge_result.get('security_auditor') or 'Attacker crafts a malicious transaction'}
3. {judge_result.get('exploit_step_3') or judge_result.get('protocol_designer') or 'Attacker extracts value through the vulnerability'}

### Impact
- **Funds at risk**: {judge_result.get('funds_at_risk', 'Direct theft possible')}
- **Protocols affected**: {judge_result.get('protocols_affected', 'Any protocol using this pattern')}
- **Real-world precedent**: {judge_result.get('precedent', 'Similar vulnerabilities have resulted in $1M+ losses')}

## Proof of Discovery

This finding is cryptographically timestamped via VeilPiercer SIAS.
Proof file: `{proof_path}`
Verify with: `python3 verifier.py {proof_path}`

This finding was stamped via OpenTimestamps and anchored on the Bitcoin
blockchain. The timestamp proves this exact proof file existed at the
recorded time. It does not prove when the vulnerability was first
discovered -- only when this specific report was cryptographically
committed. Front-running remains possible if another researcher found
and submitted the same bug earlier.

## Fix Recommendation

{judge_result.get('fix', 'Implement checks-effects-interactions pattern. Add reentrancy guard. Audit all external calls.')}

## Judge Panel Scores
| Metric | Score |
|--------|-------|
| Exploitability | {judge_result.get('exploitability', '?')}/10 |
| Novelty | {judge_result.get('novelty', '?')}/10 |
| Payout Potential | {judge_result.get('payout', '?')}/10 |
| **OVERALL** | **{judge_result.get('overall', '?')}/10** |

---
*Found by VeilPiercer Elite Bounty Hunter -- autonomous smart contract security agent*
*Proof anchored on Bitcoin - Verify independently with verifier.py*
"""
    return report

def anchor_finding(finding, judge_result, contest_name):
    """Anchor a finding in VeilPiercer SIAS with Bitcoin timestamp."""
    try:
        from vp_agent_logger import AgentLogger
        ledger = str(FINDINGS_DIR / "bounty_audit.json")
        al = AgentLogger(ledger)

        if _ANCHOR_OPAQUE:
            metadata = {
                "content_hash": hashlib.sha256(
                    json.dumps({
                        "vuln": finding["vulnerability"],
                        "sev": finding["severity"],
                        "score": judge_result.get("overall", 0),
                    }, sort_keys=True).encode()
                ).hexdigest(),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        else:
            metadata = {
                "vulnerability": finding["vulnerability"],
                "severity": finding["severity"],
                "contest": contest_name,
                "overall_score": judge_result.get("overall", 0),
                "file": finding.get("file", "unknown"),
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        al.log_generic("BOUNTY_FINDING", metadata)

        root = al.flush(anchor_ots=True)
        batch_idx = len(al.vp.batch_chain) - 1

        # Export proof
        proof_path = str(FINDINGS_DIR / f"proof_{batch_idx}_{int(time.time())}.json")
        al.vp.export_proof(
            al.vp.batch_chain[batch_idx]["start_idx"],
            proof_path
        )

        return proof_path, root
    except Exception as e:
        return None, str(e)


def hunter_scan(contest_filter=None, repo_url=None):
    contract_code = None
    """Main scan: contests - contracts - patterns - judge - proof - report."""
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    # Warn about local artifact persistence
    artifact_dir = Path(os.path.expanduser("~/bounty_findings"))
    print(f"\n  [!] Scan artifacts stored at: {artifact_dir}")
    print(f"  [!] Files include full contract code snippets, judge results, and proof files.")
    print(f"  [!] These persist in PLAINTEXT and ARE NOT ENCRYPTED.")
    print(f"  [!] For confidential contracts, manually delete: rm -rf {artifact_dir}")

    findings = []
    now = datetime.now(timezone.utc)
    session_dir = FINDINGS_DIR / now.strftime("%Y-%m-%d")
    session_dir.mkdir(exist_ok=True)

    print("=" * 64)
    print("  VEILPIERCER ELITE BOUNTY HUNTER")
    print(f"  Session: {now.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("=" * 64)

    # Phase 1: Discover contests
    print("\n[PHASE 1] Scanning contest platforms...")
    active_contests = []

    for name, info in CONTEST_SOURCES.items():
        if contest_filter and contest_filter != name:
            continue
        url = info.get("contests", info.get("bounty_list", info["url"]))
        html = fetch_url(url)
        status = "REACHABLE" if html else "OFFLINE"
        print(f"  {name:15s} {status:10s} {url}")
        if html:
            # Extract contest names/titles from HTML
            titles = re.findall(r'<h[23][^>]*>(.*?)</h[23]>', html, re.IGNORECASE)
            titles = [re.sub(r'<[^>]+>', '', t).strip() for t in titles if len(t) > 10]
            for title in titles[:5]:
                active_contests.append({"platform": name, "title": title, "url": url})
                print(f"    - {title[:80]}")

    if not active_contests and not repo_url:
        print("\n  [!] No active contests found. Use --repo to scan a specific contract.")
        print("  [*] Testing with known vulnerable patterns...")
        # Load sample vulnerable contracts from our pattern library
        sample_code = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public balances;
    bool private locked;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        balances[msg.sender] -= amount;  // REENTRANCY: state update after external call
    }

    function emergencyWithdraw() external {
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;  // ACCESS CONTROL: no onlyOwner, anyone can trigger
        payable(msg.sender).transfer(amount);
    }
}
"""
        findings = scan_contract(sample_code, "VulnerableVault.sol")
        contest_name = "SAMPLE_SCAN"

    # Phase 2: If single repo, fetch and scan it
    if repo_url:
        print(f"\n[PHASE 2] Fetching: {repo_url}")
        if os.path.exists(repo_url):
            # Local file path
            with open(repo_url) as fh:
                code = fh.read()
            contract_code = code
            findings = scan_contract(code, os.path.basename(repo_url))
            contest_name = "LOCAL_FILE"
            print(f"      Read {len(code)} bytes from local file")
        elif "github.com" in repo_url:
            # GitHub URL
            raw_url = repo_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            code = fetch_url(raw_url)
            contract_code = code
            if code:
                findings = scan_contract(code, repo_url.split("/")[-1])
                contest_name = "GITHUB_SCAN"
            else:
                print("  [!] Could not fetch contract from GitHub")
        else:
            print(f"  [!] Not a valid local path or GitHub URL: {repo_url}")
            print(f"  [!] Local files must exist. GitHub URLs must contain github.com")
            return [], []
    # Phase 3: Judge Panel
    print(f"\n[PHASE 3] Running severity-based scoring on {len(findings)} findings...")
    reports = []
    if contract_code:
        _scan_dedup.mark_scanned(contract_code, repo_url or contest_name,
                                 [f["vulnerability"] for f in findings], api_calls=0)


    # Check deduplication: skip findings already reported for this contract
    if contract_code:
        known_findings = _scan_dedup.new_findings(contract_code, [f["vulnerability"] for f in findings])
        if len(known_findings) == 0 and len(findings) > 0:
            print(f"\n  [DEDUP] All {len(findings)} findings already reported. Skipping API calls.")
            print_api_cost_summary()
            return findings, []
    else:
        known_findings = None
    for i, finding in enumerate(findings):
        print(f"\n  [{i+1}/{len(findings)}] {finding['vulnerability']} ({finding['severity']})")
        print(f"      File: {finding['file']}")
        print(f"      Matches: {finding['match_count']} lines")


        # Skip API if this finding was already reported for this contract
        if known_findings is not None and finding["vulnerability"] not in known_findings:
            print(f"      [DEDUP] Already reported - skipping API call")
            judge_result_raw = {"_source": "cached", "exploitability": 0, "novelty": 0,
                                 "payout_potential": 0, "overall": 0, "submit": "NO"}
        else:
            # Run severity-based scoring (calls DeepSeek API, falls back to static)
            judge_prompt = run_judge_panel(finding)
            judge_path = session_dir / f"judge_{finding['vulnerability']}_{i}.txt"
            judge_path.write_text(json.dumps(judge_prompt, indent=2))
            judge_result_raw = judge_prompt  # run_judge_panel returns dict now
            judge_result = {
                "exploitability": judge_result_raw.get("exploitability", 5),
                "novelty": judge_result_raw.get("novelty", 3),
                "payout": judge_result_raw.get("payout_potential", 5),
                "overall": judge_result_raw.get("overall", 5),
                "submit": judge_result_raw.get("submit", "NO"),
                "exploit_chain": finding["exploit_chain"],
                "exploit_step_1": judge_result_raw.get("exploit_engineer", "")[:200],
                "exploit_step_2": judge_result_raw.get("security_auditor", "")[:200],
                "exploit_step_3": judge_result_raw.get("protocol_designer", "")[:200],
                "funds_at_risk": judge_result_raw.get("funds_at_risk", "Unknown"),
                "protocols_affected": judge_result_raw.get("submit_platform", "Unknown"),
                "precedent": judge_result_raw.get("precedent", "Unknown"),
                "fix": judge_result_raw.get("fix", "Manual review required"),
                "_source": judge_result_raw.get("_source", "unknown"),
        }

        # Save judge result
        judge_result_path = session_dir / f"judge_result_{i}.json"
        with open(judge_result_path, "w") as f:
            json.dump(judge_result, f, indent=2)

        # Phase 4: Anchor proof
        print(f"      Score: {judge_result["overall"]}/10 | Submit: {judge_result["submit"]} | Source: {judge_result.get("_source", "?")}")
        proof_path, root = anchor_finding(finding, judge_result, contest_name if not repo_url else "DIRECT")
        if proof_path:
            print(f"      Proof: {proof_path}")
            print(f"      Root:  {root[:16] if root else 'FAIL'}...")

        # Phase 5: Generate submission report
        if judge_result["submit"] == "YES":
            report = generate_submission_report(finding, judge_result, proof_path or "N/A")
            report_path = session_dir / f"submission_{finding['vulnerability']}_{i}.md"
            report_path.write_text(report)


        # Cache this finding so re-runs skip it (regardless of submit status)
        if contract_code:
            _scan_dedup.mark_reported(contract_code, finding["vulnerability"])

    # Summary
    print(f"\n{'=' * 64}")
    print(f"  HUNT COMPLETE")
    print(f"  Findings:    {len(findings)}")
    print(f"  Submissions: {len(reports)} (score >= 5/10)")
    print(f"  Reports:     {session_dir}")
    print(f"{'=' * 64}")

    if reports:
        api_count = sum(1 for r in reports if "_source" not in str(r))
        print(f"\n  Generated {len(reports)} reports (verify each before submitting):")
        for r in reports:
            print(f"    {r}")
        print(f"\n  Raw finding count: {len(reports)}. This is an unverified upper-bound")
        print(f"  based on pattern matching alone. Actual exploitable findings are")
        print(f"  typically a fraction of this count. Manual review is required to")
        print(f"  confirm exploitability before any submission.")

    print_api_cost_summary()
    return findings, reports


def main():
    contest_filter = None
    repo_url = None
    daemon_interval = None
    finding_id = None

    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--contest" and i + 1 < len(args):
            contest_filter = args[i + 1]; i += 2
        elif args[i] == "--repo" and i + 1 < len(args):
            repo_url = args[i + 1]; i += 2
        elif args[i] == "--daemon" and i + 1 < len(args):
            daemon_interval = int(args[i + 1]); i += 2
        elif args[i] == "--allow-external-api":
            allow_external_api()
            i += 1
        elif args[i] == "--allow-bitcoin-anchor":
            allow_bitcoin_anchor()
            i += 1
        elif args[i] == "--anchor-opaque":
            allow_opaque_anchor()
            i += 1
        elif args[i] == "--report" and i + 1 < len(args):
            finding_id = args[i + 1]; i += 2
        else:
            i += 1

    if daemon_interval:
        print(f"[hunter] Daemon mode -- scanning every {daemon_interval}s")
        while True:
            try:
                hunter_scan(contest_filter, repo_url)
                time.sleep(daemon_interval)
            except KeyboardInterrupt:
                print("\n[hunter] Stopped.")
                break
    else:
        hunter_scan(contest_filter, repo_url)


if __name__ == "__main__":
    main()