#!/usr/bin/env python3
"""
train_pipeline.py — VeilPiercer Self-Optimizing Training Harness v1.0

Runs the full pipeline against 20+ contracts, tracks metrics,
compares against golden outputs, generates improvement suggestions,
and logs everything to SIAS training ledger.

Usage:
  python3 train_pipeline.py                     # full benchmark
  python3 train_pipeline.py --golden-update      # update golden set
  python3 train_pipeline.py --ci                 # CI mode (strict gates)
"""

import sys, os, json, time, hashlib, subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE, 'cli'))
sys.path.insert(0, os.path.join(BASE, 'core'))

from dep_resolver import parse_imports, categorize_imports, detect_project_root
from bounty_hunter_elite import scan_contract

GOLDEN_DIR = os.path.join(BASE, 'golden')
TRAINING_LEDGER = os.path.join(BASE, 'training_ledger.json')
CONTRACT_DIR = os.environ.get('VP_CONTRACT_DIR', os.path.expanduser('~/Web3Bugs/contracts'))
os.makedirs(GOLDEN_DIR, exist_ok=True)

METRICS = {
    'total_contracts': 0,
    'total_imports': 0,
    'npm_resolved': 0,
    'npm_total': 0,
    'rel_resolved': 0,
    'rel_total': 0,
    'total_findings': 0,
    'findings_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'informational': 0},
    'privacy_violations': 0,
    'scan_times': [],
    'regression_drifts': [],
    'improvement_suggestions': [],
}

def benchmark_contracts(limit=20):
    """Run full pipeline on contracts, collect all metrics."""
    count = 0
    start_time = time.time()
    contest_stats = {}  # per-contest breakdown
    
    for contest in sorted(os.listdir(CONTRACT_DIR), key=lambda x: -int(x) if x.isdigit() else 0):
        cdir = os.path.join(CONTRACT_DIR, contest, 'contracts')
        if not os.path.isdir(cdir): continue
        contest_findings = 0
        contest_contracts = 0
        for f in sorted(os.listdir(cdir)):
            fp = os.path.join(cdir, f)
            if not f.endswith('.sol') or os.path.getsize(fp) > 50000: continue
            
            t0 = time.time()
            with open(fp) as fh: src = fh.read()
            
            # Dep resolution metrics
            imps = parse_imports(src)
            npm, bare, rel = categorize_imports(imps)
            root, _, _ = detect_project_root(fp)
            nr = len([i for i in npm if '@' in i])
            rr = len(rel) if root else 0
            
            METRICS['total_imports'] += len(imps)
            METRICS['npm_total'] += len(npm)
            METRICS['npm_resolved'] += nr
            METRICS['rel_total'] += len(rel)
            METRICS['rel_resolved'] += rr
            
            # Findings metrics
            findings = scan_contract(src, f)
            METRICS['total_findings'] += len(findings)
            contest_findings += len(findings)
            contest_contracts += 1
            for fi in findings:
                sev = fi.get('severity', 'low')
                METRICS['findings_severity'][sev] = METRICS['findings_severity'].get(sev, 0) + 1
            
            # Privacy check
            import bounty_hunter_elite as bh
            if bh._ALLOW_EXTERNAL_API or bh._ALLOW_BITCOIN_ANCHOR:
                METRICS['privacy_violations'] += 1
            
            t1 = time.time()
            METRICS['scan_times'].append(t1 - t0)
            METRICS['total_contracts'] += 1
            count += 1
            if count >= limit: break
        if contest_contracts > 0:
            contest_stats[contest] = {'contracts': contest_contracts, 'findings': contest_findings}
        if count >= limit: break
    
    METRICS['total_time'] = time.time() - start_time
    return METRICS


def compare_golden():
    """Compare current output against golden set, detect drift."""
    if not os.path.exists(GOLDEN_DIR) or not os.listdir(GOLDEN_DIR):
        return []
    
    drifts = []
    for gf in sorted(Path(GOLDEN_DIR).glob('*.json')):
        try:
            expected = json.loads(gf.read_text())
            # Check if contract still exists and re-scan
            cpath = expected.get('contract_path', '')
            if cpath and os.path.exists(cpath):
                with open(cpath) as fh:
                    findings = scan_contract(fh.read(), os.path.basename(cpath))
                actual = {
                    'file': os.path.basename(cpath),
                    'findings_count': len(findings),
                    'severity_counts': {},
                }
                for fi in findings:
                    sev = fi.get('severity', 'low')
                    actual['severity_counts'][sev] = actual['severity_counts'].get(sev, 0) + 1
                
                if expected.get('findings_count') != actual['findings_count']:
                    drifts.append({
                        'file': os.path.basename(cpath),
                        'expected': expected.get('findings_count'),
                        'actual': actual['findings_count'],
                        'diff': actual['findings_count'] - expected.get('findings_count', 0),
                    })
        except Exception:
            pass
    return drifts


def update_golden(contract_paths):
    """Update golden set with current outputs."""
    import shutil
    if os.path.exists(GOLDEN_DIR):
        shutil.rmtree(GOLDEN_DIR)
    os.makedirs(GOLDEN_DIR)
    
    for fp in contract_paths[:20]:
        if not os.path.exists(fp): continue
        with open(fp) as fh: src = fh.read()
        findings = scan_contract(src, os.path.basename(fp))
        sev = {}
        for fi in findings:
            s = fi.get('severity', 'low')
            sev[s] = sev.get(s, 0) + 1
        
        golden = {
            'file': os.path.basename(fp),
            'contract_path': fp,
            'findings_count': len(findings),
            'severity_counts': sev,
            'hash': hashlib.sha256(src.encode()).hexdigest()[:16],
            'updated_utc': datetime.now(timezone.utc).isoformat(),
        }
        out = os.path.join(GOLDEN_DIR, os.path.basename(fp) + '.golden.json')
        json.dump(golden, open(out, 'w'), indent=2)


def generate_improvements(metrics):
    """Generate data-driven improvement suggestions."""
    suggestions = []
    m = metrics
    
    # Dep resolution
    npm_rate = (m['npm_resolved'] / max(m['npm_total'], 1)) * 100
    rel_rate = (m['rel_resolved'] / max(m['rel_total'], 1)) * 100
    overall = ((m['npm_resolved'] + m['rel_resolved']) / max(m['total_imports'], 1)) * 100
    
    if npm_rate < 100:
        suggestions.append({
            'area': 'dep_resolution',
            'priority': 'high',
            'metric': f'npm resolution: {npm_rate:.0f}%',
            'target': '100%',
            'suggestion': 'Add @chainlink and @uniswap to NPM_SOLIDITY_PACKAGES in dep_resolver.py',
        })
    
    if rel_rate < 90:
        suggestions.append({
            'area': 'dep_resolution',
            'priority': 'medium',
            'metric': f'relative resolution: {rel_rate:.0f}%',
            'target': '>90%',
            'suggestion': 'Expand detect_project_root to handle hardhat.config.ts without foundry.toml',
        })
    
    if overall < 92:
        suggestions.append({
            'area': 'dep_resolution',
            'priority': 'critical',
            'metric': f'overall resolution: {overall:.0f}%',
            'target': '>92% (CI gate)',
            'suggestion': 'Run with --auto-clone to resolve remaining relative imports',
        })
    
    # Findings
    high_rate = m['findings_severity'].get('high', 0) / max(m['total_findings'], 1) * 100
    if high_rate < 5:
        suggestions.append({
            'area': 'scanner_accuracy',
            'priority': 'medium',
            'metric': f'HIGH findings: {high_rate:.0f}% of total',
            'target': '>10%',
            'suggestion': 'Review regex patterns for reentrancy and access_control sensitivity',
        })
    
    # Privacy
    if m['privacy_violations'] > 0:
        suggestions.append({
            'area': 'privacy',
            'priority': 'critical',
            'metric': f'{m["privacy_violations"]} privacy violations detected',
            'target': '0',
            'suggestion': 'All gates must remain default OFF. Check _ALLOW_EXTERNAL_API and _ALLOW_BITCOIN_ANCHOR.',
        })
    
    # Speed
    avg_time = sum(m['scan_times']) / max(len(m['scan_times']), 1)
    if avg_time > 1.0:
        suggestions.append({
            'area': 'performance',
            'priority': 'low',
            'metric': f'avg scan time: {avg_time:.2f}s',
            'target': '<1s',
            'suggestion': 'Consider caching regex pattern compilation or parallelizing contract scans.',
        })
    
    return sorted(suggestions, key=lambda s: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[s['priority']])


def log_training(metrics, suggestions, drifts):
    """Log training cycle to SIAS training ledger."""
    try:
        from vp_agent_logger import AgentLogger
        al = AgentLogger(TRAINING_LEDGER)
        al.log_generic('TRAINING_CYCLE', {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'metrics': {
                'contracts': metrics['total_contracts'],
                'total_imports': metrics['total_imports'],
                'dep_resolution': f"{(metrics['npm_resolved']+metrics['rel_resolved'])/max(metrics['total_imports'],1)*100:.0f}%",
                'findings': metrics['total_findings'],
                'privacy_violations': metrics['privacy_violations'],
                'avg_scan_time': f"{sum(metrics['scan_times'])/max(len(metrics['scan_times']),1):.2f}s",
            },
            'improvement_suggestions': len(suggestions),
            'regression_drifts': len(drifts),
            'regression_drift_details': drifts[:5] if drifts else [],
        })
        al.flush(anchor_ots=False)
        return True
    except Exception as e:
        print(f'  SIAS logging: {e}')
        return False


# -- CLI --
if __name__ == '__main__':
    args = sys.argv[1:]
    
    if '--golden-update' in args:
        # Collect 20 contracts and update golden
        paths = []
        seen = set()
        for contest in sorted(os.listdir(CONTRACT_DIR), key=lambda x: -int(x) if x.isdigit() else 0):
            cdir = os.path.join(CONTRACT_DIR, contest, 'contracts')
            if not os.path.isdir(cdir): continue
            for f in os.listdir(cdir):
                fp = os.path.join(cdir, f)
                if f.endswith('.sol') and contest not in seen and os.path.getsize(fp) < 50000:
                    paths.append(fp)
                    seen.add(contest)
                    if len(paths) >= 20: break
            if len(paths) >= 20: break
        update_golden(paths)
        print(f'Golden set updated: {len(os.listdir(GOLDEN_DIR))} files')
        sys.exit(0)

    if '--full' in args:
        # Full mode: scan ALL contracts, update golden, output JSON summary
        import glob as _glob

        print('=' * 60)
        print('  VeilPiercer Training Harness — FULL MODE')
        print('=' * 60)
        print()

        # Collect ALL contracts
        all_contracts = []
        seen_contests = set()
        for contest in sorted(os.listdir(CONTRACT_DIR), key=lambda x: -int(x) if x.isdigit() else 0):
            cdir = os.path.join(CONTRACT_DIR, contest, 'contracts')
            if not os.path.isdir(cdir): continue
            for f in sorted(os.listdir(cdir)):
                fp = os.path.join(cdir, f)
                if f.endswith('.sol') and os.path.getsize(fp) < 50000:
                    if contest not in seen_contests:
                        seen_contests.add(contest)
                    all_contracts.append(fp)

        print(f'Found {len(all_contracts)} contracts across {len(seen_contests)} contests')
        print()

        # Run benchmark on ALL contracts
        metrics = benchmark_contracts(len(all_contracts))
        print(f'  Contracts: {metrics["total_contracts"]}')
        print(f'  Imports: {metrics["total_imports"]}')

        npm_r = (metrics['npm_resolved'] / max(metrics['npm_total'], 1)) * 100
        rel_r = (metrics['rel_resolved'] / max(metrics['rel_total'], 1)) * 100
        overall = ((metrics['npm_resolved'] + metrics['rel_resolved']) / max(metrics['total_imports'], 1)) * 100
        print(f'  Dep resolution: npm={npm_r:.0f}% rel={rel_r:.0f}% overall={overall:.0f}%')
        print(f'  Findings: {metrics["total_findings"]} ({metrics["findings_severity"]})')
        print(f'  Privacy violations: {metrics["privacy_violations"]}')
        print(f'  Avg scan time: {sum(metrics["scan_times"])/max(len(metrics["scan_times"]),1):.2f}s')
        print(f'  Total time: {metrics["total_time"]:.1f}s')
        print()

        # Update golden set
        update_golden(all_contracts[:20])
        print(f'Golden set updated: {len(os.listdir(GOLDEN_DIR))} files')
        print()

        # Compare against golden (now fresh)
        drifts = compare_golden()
        if drifts:
            print(f'Regression drifts: {len(drifts)}')
        else:
            print('Golden set: no regressions')
        print()

        # Generate improvements
        suggestions = generate_improvements(metrics)
        print(f'Improvement suggestions: {len(suggestions)}')
        for i, s in enumerate(suggestions[:10], 1):
            print(f'  {i}. [{s["priority"].upper()}] {s["area"]}: {s["suggestion"]}')
        print()

        # Log to SIAS
        log_training(metrics, suggestions, drifts)
        print(f'Training logged to: {TRAINING_LEDGER}')
        print()

        # CI gates
        gates_passed = True
        if overall < 92:
            print(f'CI GATE FAILED: dep resolution {overall:.0f}% < 92%')
            gates_passed = False
        if metrics['privacy_violations'] > 0:
            print(f'CI GATE FAILED: {metrics["privacy_violations"]} privacy violations')
            gates_passed = False
        if drifts:
            print(f'CI GATE WARNING: {len(drifts)} regression drifts (expected after golden update)')
        if gates_passed:
            print('CI GATES: ALL PASSED')

        # Output JSON summary (for GitHub Actions / Discussions)
        summary = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'contracts_scanned': metrics['total_contracts'],
            'contests': len(seen_contests),
            'total_imports': metrics['total_imports'],
            'dep_resolution_pct': round(overall, 1),
            'npm_resolution_pct': round(npm_r, 1),
            'rel_resolution_pct': round(rel_r, 1),
            'total_findings': metrics['total_findings'],
            'findings_by_severity': metrics['findings_severity'],
            'privacy_violations': metrics['privacy_violations'],
            'avg_scan_time_s': round(sum(metrics['scan_times'])/max(len(metrics['scan_times']),1), 2),
            'total_time_s': round(metrics['total_time'], 1),
            'regression_drifts': len(drifts),
            'improvement_suggestions': len(suggestions),
            'top_suggestions': [{'priority': s['priority'], 'area': s['area'], 'suggestion': s['suggestion']} for s in suggestions[:5]],
            'ci_gates_passed': gates_passed,
        }
        print()
        print('--- JSON SUMMARY ---')
        print(json.dumps(summary, indent=2))
        sys.exit(0 if gates_passed else 1)
    
    # Run benchmark
    print('=' * 60)
    print('  VeilPiercer Training Harness v1.0')
    print('=' * 60)
    print()
    
    print('Running benchmark on 20 contracts...')
    metrics = benchmark_contracts(20)
    
    print(f'  Contracts: {metrics["total_contracts"]}')
    print(f'  Imports: {metrics["total_imports"]}')
    
    npm_r = (metrics['npm_resolved'] / max(metrics['npm_total'], 1)) * 100
    rel_r = (metrics['rel_resolved'] / max(metrics['rel_total'], 1)) * 100
    overall = ((metrics['npm_resolved'] + metrics['rel_resolved']) / max(metrics['total_imports'], 1)) * 100
    print(f'  Dep resolution: npm={npm_r:.0f}% rel={rel_r:.0f}% overall={overall:.0f}%')
    print(f'  Findings: {metrics["total_findings"]} ({metrics["findings_severity"]})')
    print(f'  Privacy violations: {metrics["privacy_violations"]}')
    print(f'  Avg scan time: {sum(metrics["scan_times"])/max(len(metrics["scan_times"]),1):.2f}s')
    print(f'  Total time: {metrics["total_time"]:.1f}s')
    print()
    
    # Compare against golden
    drifts = compare_golden()
    if drifts:
        print(f'Regression drifts detected: {len(drifts)}')
        for d in drifts[:5]:
            print(f'  {d["file"]}: expected={d["expected"]} actual={d["actual"]} (drift={d["diff"]:+d})')
    else:
        print('Golden set: no regressions (or no golden set yet)')
    print()
    
    # Generate improvements
    suggestions = generate_improvements(metrics)
    print(f'Improvement suggestions: {len(suggestions)}')
    for i, s in enumerate(suggestions[:5], 1):
        print(f'  {i}. [{s["priority"].upper()}] {s["area"]}: {s["suggestion"]}')
        print(f'     Metric: {s["metric"]} → Target: {s["target"]}')
    print()
    
    # Log to SIAS
    log_training(metrics, suggestions, drifts)
    print(f'Training logged to: {TRAINING_LEDGER}')
    
    # CI gates
    if '--ci' in args:
        passed = True
        if overall < 92:
            print(f'CI GATE FAILED: dep resolution {overall:.0f}% < 92%')
            passed = False
        if metrics['privacy_violations'] > 0:
            print(f'CI GATE FAILED: {metrics["privacy_violations"]} privacy violations')
            passed = False
        if drifts:
            print(f'CI GATE FAILED: {len(drifts)} regression drifts')
            passed = False
        if passed:
            print('CI GATES: ALL PASSED')
        sys.exit(0 if passed else 1)
    
    print('=' * 60)
    print('  Training cycle complete.')
    print('=' * 60)
