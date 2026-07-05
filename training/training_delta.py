#!/usr/bin/env python3
"""
training_delta.py — Compare current training run against previous week.
Outputs markdown delta table for GitHub Discussions.

Usage:
  python3 training_delta.py <current_summary.json>

The file ~/veilpiercer/training_delta.json stores the previous run.
On first run (no previous), outputs current metrics only.
On subsequent runs, outputs a comparison table with +/- deltas.
"""
import json, sys, os
from datetime import datetime, timezone

DELTA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'training_delta.json')

def load_previous():
    if os.path.exists(DELTA_FILE):
        with open(DELTA_FILE) as f:
            return json.load(f)
    return None

def save_current(data):
    with open(DELTA_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def delta_str(prev, curr):
    """Return +N, -N, or = string."""
    if prev is None or curr is None:
        return "—"
    d = curr - prev
    if d > 0: return f"+{d}"
    if d < 0: return str(d)
    return "="

def delta_pct(prev, curr):
    """Return percentage point change string."""
    if prev is None or curr is None:
        return "—"
    d = curr - prev
    if d > 0: return f"+{d:.1f}pp"
    if d < 0: return f"{d:.1f}pp"
    return "="

def generate_delta_markdown(current):
    """Generate markdown delta section for Discussions."""
    prev = load_previous()
    save_current(current)

    sev = current.get('findings_by_severity', {})
    prev_sev = prev.get('findings_by_severity', {}) if prev else {}

    lines = []
    lines.append("### Week-over-Week Delta\n")
    lines.append("| Metric | Previous | Current | Delta |")
    lines.append("|--------|----------|---------|-------|")

    rows = [
        ("Contracts scanned",
         prev['contracts_scanned'] if prev else None,
         current.get('contracts_scanned'),
         delta_str(prev['contracts_scanned'] if prev else None, current.get('contracts_scanned'))),
        ("Dep resolution",
         f"{prev['dep_resolution_pct']}%" if prev else None,
         f"{current.get('dep_resolution_pct')}%",
         delta_pct(prev['dep_resolution_pct'] if prev else None, current.get('dep_resolution_pct'))),
        ("Total findings",
         prev['total_findings'] if prev else None,
         current.get('total_findings'),
         delta_str(prev['total_findings'] if prev else None, current.get('total_findings'))),
        ("High findings",
         prev_sev.get('high', 0) if prev else None,
         sev.get('high', 0),
         delta_str(prev_sev.get('high') if prev else None, sev.get('high', 0))),
        ("Medium findings",
         prev_sev.get('medium', 0) if prev else None,
         sev.get('medium', 0),
         delta_str(prev_sev.get('medium') if prev else None, sev.get('medium', 0))),
        ("Privacy violations",
         prev['privacy_violations'] if prev else None,
         current.get('privacy_violations'),
         delta_str(prev['privacy_violations'] if prev else None, current.get('privacy_violations'))),
        ("Regression drifts",
         prev['regression_drifts'] if prev else None,
         current.get('regression_drifts'),
         delta_str(prev['regression_drifts'] if prev else None, current.get('regression_drifts'))),
        ("Improvement suggestions",
         prev['improvement_suggestions'] if prev else None,
         current.get('improvement_suggestions'),
         delta_str(prev['improvement_suggestions'] if prev else None, current.get('improvement_suggestions'))),
    ]

    for label, pv, cv, delta in rows:
        pvs = str(pv) if pv is not None else "—"
        cvs = str(cv) if cv is not None else "—"
        lines.append(f"| {label} | {pvs} | {cvs} | {delta} |")

    if prev:
        prev_date = prev.get('timestamp', 'unknown')[:10]
        curr_date = current.get('timestamp', datetime.now(timezone.utc).isoformat())[:10]
        lines.append(f"\n*Comparing {prev_date} → {curr_date}*")
    else:
        lines.append("\n*First run — no previous data for comparison.*")

    return "\n".join(lines)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 training_delta.py <summary.json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        current = json.load(f)

    print(generate_delta_markdown(current))
