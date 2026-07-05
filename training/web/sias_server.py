#!/usr/bin/env python3
"""
VeilPiercer SIAS Web Server — Live Dashboard + JSON API
=========================================================
Single-file HTTP server. No framework needed.

Endpoints:
  GET /      → index.html (live web UI)
  GET /api   → JSON status (chain, SIAS, OTS)
  GET /health → health check
  POST /scan  → scan contract (body: {code, github_url, deep})

Usage:
  python3 sias_server.py [--port 9100] [--ledger audit.json]
"""

import sys, os, json, time, socket
from http.server import HTTPServer, BaseHTTPRequestHandler

class ReuseHTTPServer(HTTPServer):
    """HTTPServer with SO_REUSEADDR for clean restarts."""
    allow_reuse_address = True
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        super().server_bind()

# Rate limiting
_RATE_LIMIT = {}  # {ip: [timestamps]}
_RATE_MAX = int(os.environ.get('VEILPIERCER_RATE_LIMIT', '10'))  # requests per window
_RATE_WINDOW = int(os.environ.get('VEILPIERCER_RATE_WINDOW', '60'))  # seconds

# Basic auth
_API_KEY = os.environ.get('VEILPIERCER_API_KEY', '')

# ── Anonymized scan stats (in-memory, resets on restart) ──────────────
_STATS_FILE = os.environ.get('VP_STATS_FILE', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'stats.json'))
_STATS = {
    'total_scans': 0,
    'total_findings': 0,
    'dep_attempts': 0,
    'dep_successes': 0,
    'scan_times_ms': [],       # last 100 scan durations
    'error_count': 0,
    'started_at': time.time(),
    'last_scan_at': 0,
    'scanner_breakdown': {     # findings-per-scanner totals
        'regex': 0,
        'slither': 0,
        'mythril': 0,
    },
}

def _load_stats():
    """Load persisted stats from disk on startup."""
    global _STATS, _COMMUNITY, _VERIFIED
    try:
        if os.path.exists(_STATS_FILE):
            with open(_STATS_FILE) as f:
                saved = json.load(f)
            # Restore scan stats
            s = saved.get('stats', {})
            _STATS['total_scans'] = s.get('total_scans', 0)
            _STATS['total_findings'] = s.get('total_findings', 0)
            _STATS['dep_attempts'] = s.get('dep_attempts', 0)
            _STATS['dep_successes'] = s.get('dep_successes', 0)
            _STATS['error_count'] = s.get('error_count', 0)
            _STATS['scanner_breakdown'] = s.get('scanner_breakdown', {'regex': 0, 'slither': 0, 'mythril': 0})
            # Restore community stats
            c = saved.get('community', {})
            _COMMUNITY['total_scans'] = c.get('total_scans', 0)
            _COMMUNITY['total_findings'] = c.get('total_findings', 0)
            _COMMUNITY['vuln_counts'] = c.get('vuln_counts', {})
            _COMMUNITY['severity_counts'] = c.get('severity_counts', {})
            _COMMUNITY['contributors'] = c.get('contributors', 0)
            # Restore verified entries
            _VERIFIED.update(saved.get('verified', {}))
            print(f"  [persist] Loaded: {_STATS['total_scans']} scans, {_COMMUNITY['total_scans']} community, {len(_VERIFIED)} verified")
    except Exception as e:
        print(f"  [persist] Load failed: {e}")

def _save_stats():
    """Persist current stats to disk (called after each scan)."""
    try:
        saved = {
            'stats': {
                'total_scans': _STATS['total_scans'],
                'total_findings': _STATS['total_findings'],
                'dep_attempts': _STATS['dep_attempts'],
                'dep_successes': _STATS['dep_successes'],
                'error_count': _STATS['error_count'],
                'scanner_breakdown': dict(_STATS['scanner_breakdown']),
            },
            'community': {
                'total_scans': _COMMUNITY['total_scans'],
                'total_findings': _COMMUNITY['total_findings'],
                'vuln_counts': dict(_COMMUNITY['vuln_counts']),
                'severity_counts': dict(_COMMUNITY['severity_counts']),
                'contributors': len(_COMMUNITY['unique_contributors']),
            },
            'verified': dict(_VERIFIED),
        }
        with open(_STATS_FILE, 'w') as f:
            json.dump(saved, f)
    except Exception:
        pass  # silent — stats are best-effort

def _stats_snapshot():
    """Return anonymized aggregate stats dict (no private data)."""
    times = _STATS['scan_times_ms']
    n = _STATS['total_scans']
    return {
        'total_scans': n,
        'avg_findings': round(_STATS['total_findings'] / n, 1) if n else 0,
        'dep_success_pct': round(_STATS['dep_successes'] / _STATS['dep_attempts'] * 100, 1) if _STATS['dep_attempts'] else 0,
        'dep_attempts': _STATS['dep_attempts'],
        'dep_successes': _STATS['dep_successes'],
        'avg_scan_ms': round(sum(times) / len(times)) if times else 0,
        'max_scan_ms': max(times) if times else 0,
        'min_scan_ms': min(times) if times else 0,
        'error_count': _STATS['error_count'],
        'uptime_seconds': int(time.time() - _STATS['started_at']),
        'last_scan_ago_seconds': int(time.time() - _STATS['last_scan_at']) if _STATS['last_scan_at'] else None,
        'scanner_findings': dict(_STATS['scanner_breakdown']),
    }

# ── Community opt-in stats (anonymized, aggregate only) ──────────
_COMMUNITY = {
    'total_scans': 0,
    'total_findings': 0,
    'vuln_counts': {},        # {vuln_name: count}
    'severity_counts': {},    # {severity: count}
    'unique_contributors': set(),  # hashed IPs for privacy
    'started_at': time.time(),
}

def _community_snapshot():
    """Return anonymized community aggregate stats (no private data, no code)."""
    n = _COMMUNITY['total_scans']
    return {
        'total_scans': n,
        'total_findings': _COMMUNITY['total_findings'],
        'avg_findings': round(_COMMUNITY['total_findings'] / n, 1) if n else 0,
        'contributors': len(_COMMUNITY['unique_contributors']),
        'top_vulnerabilities': sorted(
            _COMMUNITY['vuln_counts'].items(), key=lambda x: -x[1]
        )[:10],
        'severity_breakdown': dict(_COMMUNITY['severity_counts']),
        'recent_scans': list(reversed(_COMMUNITY.get('recent_scans', [])))[:10],
        'uptime_seconds': int(time.time() - _COMMUNITY['started_at']),
    }

def _record_community_scan(findings):
    """Record anonymized community scan stats."""
    import hashlib
    _COMMUNITY['total_scans'] += 1
    _COMMUNITY['total_findings'] += len(findings)
    # Build per-scan summary for recent activity
    vulns = {}
    for f in findings:
        vuln = f.get('vulnerability', 'unknown')
        sev = f.get('severity', 'low')
        _COMMUNITY['vuln_counts'][vuln] = _COMMUNITY['vuln_counts'].get(vuln, 0) + 1
        _COMMUNITY['severity_counts'][sev] = _COMMUNITY['severity_counts'].get(sev, 0) + 1
        vulns[vuln] = vulns.get(vuln, 0) + 1
    top_vuln = max(vulns, key=vulns.get) if vulns else 'none'
    _COMMUNITY.setdefault('recent_scans', []).append({
        'time': time.time(),
        'findings': len(findings),
        'top_vuln': top_vuln,
    })
    if len(_COMMUNITY['recent_scans']) > 20:
        _COMMUNITY['recent_scans'] = _COMMUNITY['recent_scans'][-20:]

# ── VeilPiercer Verified badge system ─────────────────────────
_VERIFIED = {}  # {contract_hash: {findings, severity_counts, timestamp, passed}}
_VERIFIED_THRESHOLDS = {'max_critical': 0, 'max_high': 2, 'max_total': 10}

def _verify_contract(source_code):
    """Verify a contract and return badge status. Source code is hashed, not stored."""
    import hashlib
    ch = hashlib.sha256(source_code.encode()).hexdigest()[:16]
    
    # Run scanner
    try:
        from bounty_hunter_elite import scan_contract
        findings = scan_contract(source_code, 'verified_contract.sol')
    except Exception:
        findings = []
    
    sev = {}
    for f in findings:
        s = f.get('severity', 'low')
        sev[s] = sev.get(s, 0) + 1
    
    critical = sev.get('critical', 0)
    high = sev.get('high', 0)
    total = len(findings)
    
    passed = (
        critical <= _VERIFIED_THRESHOLDS['max_critical'] and
        high <= _VERIFIED_THRESHOLDS['max_high'] and
        total <= _VERIFIED_THRESHOLDS['max_total']
    )
    
    _VERIFIED[ch] = {
        'findings': total,
        'severity_counts': sev,
        'timestamp': time.time(),
        'passed': passed,
        'thresholds': dict(_VERIFIED_THRESHOLDS),
    }
    
    return ch, passed, sev, total

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'core'))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'cli'))
from veil_piercer import VeilPiercer, VERSION
from vp_dashboard import sias_checklist

LEDGER = os.environ.get('SIAS_LEDGER', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'hermes_audit.json'))
PORT = int(os.environ.get('VP_API_PORT', '9100'))
HTML_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html')

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Rate limiting
        client_ip = self.client_address[0]
        now = time.time()
        _RATE_LIMIT.setdefault(client_ip, [])
        _RATE_LIMIT[client_ip] = [t for t in _RATE_LIMIT[client_ip] if now - t < _RATE_WINDOW]
        if len(_RATE_LIMIT[client_ip]) >= _RATE_MAX:
            self.send_response(429)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Rate limit exceeded. Try again later.'}).encode())
            return
        _RATE_LIMIT[client_ip].append(now)

        # Basic auth
        if _API_KEY:
            auth = self.headers.get('Authorization', '')
            if auth != 'Bearer ' + _API_KEY:
                self.send_response(401)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': 'Unauthorized. Use Authorization: Bearer <key>'}).encode())
                return


        if self.path != '/scan' and self.path != '/verify':
            self.send_response(404); self.end_headers(); return

        if self.path == '/verify':
            # Verify-only mode (no SIAS ledger, hash-based badge)
            try:
                length = int(self.headers.get('Content-Length', 0))
                body = json.loads(self.rfile.read(length)) if length else {}
                code = body.get('code', '')
                if not code:
                    self._json(400, {'error': 'No code provided'})
                    return
                ch, passed, sev, total = _verify_contract(code)
                self._json(200, {
                    'contract_hash': ch,
                    'verified': passed,
                    'findings': total,
                    'severity_counts': sev,
                    'thresholds': dict(_VERIFIED_THRESHOLDS),
                    'badge_url': f'/api/badge/verified/{ch}.json',
                    'verify_url': f'/verify?hash={ch}',
                })
                return
            except Exception as e:
                self._json(400, {'error': str(e)})
                return

        if self.path != '/scan':
            self.send_response(404); self.end_headers(); return
        try:
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            self.send_response(400); self.end_headers()
            self.wfile.write(json.dumps({'error': 'Invalid JSON'}).encode()); return

        import subprocess, tempfile, glob, re

        code = body.get('code', '')
        gh_url = body.get('github_url', '')
        deep = body.get('deep', False)
        community_opt_in = body.get('community', False)
        scan_start = time.time()

        if gh_url:
            import urllib.request
            try:
                req = urllib.request.Request(gh_url, headers={'User-Agent': 'VeilPiercer/2.2'})
                r = urllib.request.urlopen(req, timeout=15)
                code = r.read().decode()
            except Exception as e:
                self.send_response(400); self.end_headers()
                self.wfile.write(json.dumps({'error': f'Failed to fetch: {e}'}).encode()); return

        if not code:
            self.send_response(400); self.end_headers()
            self.wfile.write(json.dumps({'error': 'No code or github_url provided'}).encode()); return

        # Write to temp file
        tmp = tempfile.mkdtemp(prefix='vp_scan_')
        contract_path = os.path.join(tmp, 'contract.sol')
        with open(contract_path, 'w') as f:
            f.write(code)

        # Run scanners
        findings = {'regex': [], 'slither': [], 'mythril': []}

        # Regex
        try:
            from bounty_hunter_elite import scan_contract
            findings['regex'] = scan_contract(code, 'contract.sol')
        except Exception:
            _STATS['error_count'] += 1

        # Slither
        try:
            remap_args = []
            from dep_resolver import resolve_dependencies
            rp, ok, _, _ = resolve_dependencies(contract_path, privacy_mode=True)
            _STATS['dep_attempts'] += 1
            if ok:
                _STATS['dep_successes'] += 1
            if rp:
                with open(rp) as rf:
                    for line in rf.read().strip().split(chr(10)):
                        if '=' in line: remap_args += ['--solc-remaps', line.strip()]
            cmd = ['slither', contract_path, '--json', '-'] + remap_args
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            try: 
                data = json.loads(r.stdout)
                from vpl_slither_scan import to_findings_format
                findings['slither'] = to_findings_format(data, False)
            except:
                _STATS['error_count'] += 1
        except Exception:
            _STATS['error_count'] += 1

        # Mythril (deep mode only)
        if deep:
            try:
                from vpl_mythril_scan import run_mythril, to_findings_format as mf
                mj, _ = run_mythril(contract_path, timeout=300)
                findings['mythril'] = mf(mj, False) if mj else []
            except Exception: pass

        # Generate report
        from vpl_audit_report import generate_report, merge_findings
        all_f = merge_findings(findings['regex'], findings['slither'], findings['mythril'])
        report = generate_report(contract_path,
            regex_findings=findings['regex'],
            slither_findings=findings['slither'],
            mythril_findings=findings['mythril'])

        # ── Record anonymized stats ──────────────────────────────────
        elapsed_ms = int((time.time() - scan_start) * 1000)
        _STATS['total_scans'] += 1
        _STATS['total_findings'] += len(all_f)
        _STATS['scan_times_ms'].append(elapsed_ms)
        if len(_STATS['scan_times_ms']) > 100:
            _STATS['scan_times_ms'].pop(0)
        _STATS['last_scan_at'] = time.time()
        _STATS['scanner_breakdown']['regex'] += len(findings['regex'])
        _STATS['scanner_breakdown']['slither'] += len(findings['slither'])
        _STATS['scanner_breakdown']['mythril'] += len(findings['mythril'])

        # ── Community opt-in recording ──────────────────────────
        if community_opt_in:
            _record_community_scan(all_f)

        _save_stats()  # persist to disk
        import shutil; shutil.rmtree(tmp, ignore_errors=True)

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        resp = {
            'findings': report['json']['findings'],
            'severity_counts': report['json']['severity_counts'],
            'scanner_stats': report['json']['scanner_stats'],
            'markdown': report['markdown'],
        }
        self.wfile.write(json.dumps(resp, default=str).encode())


    def do_GET(self):
        if self.path == "/health":
            self._json(200, {"status": "ok", "version": VERSION})
        elif self.path == "/api/stats":
            self._json(200, _stats_snapshot())
        elif self.path == "/api/community":
            self._json(200, _community_snapshot())
        elif self.path.startswith("/api/badge/verified/"):
            self._serve_verified_badge()
        elif self.path.startswith("/api/badge/"):
            self._serve_badge()
        elif self.path == "/dashboard" or self.path == "/dashboard.html":
            self._serve_dashboard()
        elif self.path == "/community" or self.path == "/community.html":
            self._serve_community()
        elif self.path == "/verify" or self.path == "/verify.html":
            self._serve_verify_page()
        elif self.path == "/api":
            self._serve_api()
        elif self.path == "/" or self.path == "/index.html":
            self._serve_html()
        else:
            self._json(404, {"error": "not found"})

    def _serve_api(self):
        vp = VeilPiercer()
        if os.path.exists(LEDGER):
            vp.load(LEDGER)
        chain = vp.verify_chain()
        ots = vp.ots_status()
        summary = vp.chain_summary()
        sias = sias_checklist(vp)
        data = {
            "service": "veilpiercer-sias",
            "version": VERSION,
            "chain_valid": chain["valid"],
            "chain_id": summary.get("chain_id"),
            "total_entries": summary["total_entries"],
            "batch_count": summary["batch_count"],
            "pending_entries": vp.entry_count() - vp.batch_start,
            "latest_root": summary.get("latest_root"),
            "ots": {"anchored": ots["anchored"], "pending": ots["pending"]},
            "sias": sias,
            "batches": summary.get("batches", []),
        }
        self._json(200, data)

    def _serve_html(self):
        if os.path.exists(HTML_FILE):
            with open(HTML_FILE) as f:
                html = f.read()
            self._respond(200, "text/html", html.encode())
        else:
            # Fallback: inline minimal dashboard
            html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>VeilPiercer SIAS</title>
<style>body{{background:#0a0a0f;color:#c0c0d0;font-family:monospace;padding:20px}}
.card{{background:#111118;border:1px solid#1a1a2e;padding:14px;margin:8px 0;border-radius:6px}}
h1{{color:#00ccff}} .green{{color:#00ff41}} .red{{color:#ff0040}}</style></head>
<body><h1>VeilPiercer SIAS v{VERSION}</h1>
<p>Dashboard HTML not found. JSON API: <a href="/api" style="color:#00ccff">/api</a></p>
<p>Place index.html alongside sias_server.py for full UI.</p></body></html>"""
            self._respond(200, "text/html", html.encode())

    def _serve_dashboard(self):
        dash_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard.html')
        if os.path.exists(dash_file):
            with open(dash_file) as f:
                html = f.read()
            self._respond(200, "text/html", html.encode())
        else:
            self._json(404, {"error": "dashboard.html not found"})

    def _serve_community(self):
        comm_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'community.html')
        if os.path.exists(comm_file):
            with open(comm_file) as f:
                html = f.read()
            self._respond(200, "text/html", html.encode())
        else:
            # Inline fallback
            html = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>VeilPiercer Community</title>
<style>body{background:#0a0a0f;color:#c0c0d0;font-family:monospace;padding:20px}
.card{background:#111118;border:1px solid #1a1a2e;padding:14px;margin:8px 0;border-radius:6px}
h1{color:#00ccff} .green{color:#00ff41}</style></head>
<body><h1>VeilPiercer Community</h1>
<p>Public leaderboard loading...</p>
<script>
fetch('/api/community').then(r=>r.json()).then(d=>{
document.body.innerHTML='<h1>VeilPiercer Community</h1><div class=card><h3>Community Scans: '+d.total_scans+'</h3><p>Findings: '+d.total_findings+' | Contributors: '+d.contributors+'</p></div>';
});\n</script></body></html>"""
            self._respond(200, "text/html", html.encode())

    def _serve_verified_badge(self):
        """Serve shield.io badge for a verified contract hash."""
        ch = self.path.replace('/api/badge/verified/', '').replace('.json', '')
        entry = _VERIFIED.get(ch)
        if not entry:
            self._json(200, {"schemaVersion": 1, "label": "VeilPiercer", "message": "not verified", "color": "grey"})
            return
        if entry['passed']:
            self._json(200, {"schemaVersion": 1, "label": "VeilPiercer Verified", "message": "pass", "color": "green"})
        else:
            high = entry['severity_counts'].get('high', 0)
            self._json(200, {"schemaVersion": 1, "label": "VeilPiercer", "message": f"{high} high findings", "color": "yellow"})

    def _serve_verify_page(self):
        """Serve the contract verification page."""
        vf = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'verify.html')
        if os.path.exists(vf):
            with open(vf) as f:
                html = f.read()
            self._respond(200, "text/html", html.encode())
        else:
            html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>VeilPiercer Verify</title><style>body{background:#0a0a0f;color:#c0c0d0;font-family:monospace;padding:20px}.card{background:#111118;border:1px solid #1a1a2e;padding:14px;margin:8px 0;border-radius:6px}h1{color:#00ccff}textarea{width:100%;min-height:120px;background:#111118;color:#c0c0d0;border:1px solid #1a1a2e;padding:10px;font-family:monospace;border-radius:4px}.btn{background:#7c3aed;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-weight:bold;margin:8px 4px}.green{color:#00ff41}.yellow{color:#ffcc00}</style></head><body><h1>VeilPiercer Verified</h1><p style="color:#606078">Paste your contract code to get a verification badge for your README.</p><textarea id="code" placeholder="pragma solidity ^0.8.0; contract MyProtocol { ... }"></textarea><br><button class="btn" onclick="verify()">Verify Contract</button><div id="result" style="margin-top:16px"></div><script>async function verify(){const code=document.getElementById("code").value;if(!code)return;document.getElementById("result").innerHTML="Scanning...";const r=await fetch("/verify",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({code})});const d=await r.json();const status=d.verified?\'<span class=green>PASSED</span>\':\'<span class=yellow>NEEDS REVIEW</span>\';const badge=\'[![VeilPiercer Verified](https://img.shields.io/endpoint?url=https://veilpiercer.fly.dev/api/badge/verified/\'+d.contract_hash+\'.json)](https://veilpiercer.fly.dev/verify?hash=\'+d.contract_hash+\')\';document.getElementById("result").innerHTML=\'<div class=card><h3>\'+status+\'</h3><p>Findings: \'+d.findings+\' (C:\'+(d.severity_counts.critical||0)+\' H:\'+(d.severity_counts.high||0)+\' M:\'+(d.severity_counts.medium||0)+\')</p><p>Hash: \'+d.contract_hash+\'</p><p><strong>Badge code:</strong></p><pre style=background:#0a0a0f;padding:8px;border-radius:4px;overflow-x:auto>\'+badge+\'</pre><p style=font-size:0.7em;color:#606078>Thresholds: 0 critical, max 2 high, max 10 total</p></div>\';}</script></body></html>'
            self._respond(200, "text/html", html.encode())

    def _serve_badge(self):
        """Serve shield.io-compatible JSON badge endpoint.
        GET /api/badge/scans.json          → {"schemaVersion":1,"label":"scans","message":"42","color":"blue"}
        GET /api/badge/dep_resolution.json → {"schemaVersion":1,"label":"dep resolution","message":"100%","color":"green"}
        GET /api/badge/uptime.json         → {"schemaVersion":1,"label":"uptime","message":"2h 15m","color":"blue"}
        GET /api/badge/errors.json         → {"schemaVersion":1,"label":"errors","message":"0","color":"green"}
        """
        metric = self.path.replace('/api/badge/', '').replace('.json', '')
        s = _stats_snapshot()

        badges = {
            'scans': {'label': 'scans', 'message': str(s['total_scans']), 'color': 'blue'},
            'dep_resolution': {'label': 'dep resolution', 'message': f"{s['dep_success_pct']}%",
                               'color': 'green' if s['dep_success_pct'] >= 90 else 'yellow' if s['dep_success_pct'] >= 70 else 'red'},
            'avg_findings': {'label': 'avg findings', 'message': str(s['avg_findings']), 'color': 'blue'},
            'avg_scan': {'label': 'avg scan', 'message': f"{s['avg_scan_ms']}ms", 'color': 'blue'},
            'errors': {'label': 'errors', 'message': str(s['error_count']),
                       'color': 'green' if s['error_count'] == 0 else 'red'},
            'uptime': {'label': 'uptime', 'message': self._format_uptime(s['uptime_seconds']), 'color': 'blue'},
        }

        badge = badges.get(metric)
        if not badge:
            self._json(404, {"error": f"unknown badge metric: {metric}", "available": list(badges.keys())})
            return

        self._json(200, {
            "schemaVersion": 1,
            "label": badge['label'],
            "message": badge['message'],
            "color": badge['color'],
        })

    @staticmethod
    def _format_uptime(seconds):
        if seconds < 60: return f"{seconds}s"
        if seconds < 3600: return f"{seconds // 60}m {seconds % 60}s"
        h, m = divmod(seconds, 3600)
        return f"{h}h {m // 60}m"

    def _json(self, code, data):
        body = json.dumps(data, indent=2).encode()
        self._respond(code, "application/json", body)

    def _respond(self, code, ct, body):
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # silent


def main():
    global PORT, LEDGER
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            PORT = int(args[i + 1]); i += 2
        elif args[i] == "--ledger" and i + 1 < len(args):
            LEDGER = args[i + 1]; i += 2
        else:
            i += 1

    print(f"VeilPiercer SIAS v{VERSION}")
    print(f"  Dashboard: http://0.0.0.0:{PORT}/")
    print(f"  API:       http://0.0.0.0:{PORT}/api")
    print(f"  Scan:      POST http://0.0.0.0:{PORT}/scan")
    print(f"  Health:    http://0.0.0.0:{PORT}/health")
    print(f"  Ledger:    {LEDGER}")
    _load_stats()

    server = ReuseHTTPServer(("0.0.0.0", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.shutdown()


if __name__ == "__main__":
    main()
