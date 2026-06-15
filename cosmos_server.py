#!/usr/bin/env python3
"""
COSMOS SERVER — Backend for VEILPIERCER
FastAPI server powering the 5-agent AI swarm dashboard.
Port 8000 — matches the pitch page's WebSocket + API expectations.
"""

import asyncio
import json
import time
import sqlite3
import random
import os
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from contextlib import asynccontextmanager

# ── CONFIG ───────────────────────────────────────────────────
BRAIN_DB = Path(__file__).parent / "cosmos_brain.db"
WS_CLIENTS = set()

# ── SQLite Brain ─────────────────────────────────────────────
def init_brain():
    conn = sqlite3.connect(str(BRAIN_DB))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now')),
            source TEXT,
            content TEXT,
            embedding BLOB
        )
    """)
    conn.execute("""
        CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
            source, content, content=memory, content_rowid=id
        )
    """)
    conn.execute("""
        CREATE TRIGGER IF NOT EXISTS memory_ai AFTER INSERT ON memory BEGIN
            INSERT INTO memory_fts(rowid, source, content)
            VALUES (new.id, new.source, new.content);
        END
    """)
    conn.commit()
    return conn

brain = init_brain()

# ── Agent State ──────────────────────────────────────────────
class SwarmState:
    def __init__(self):
        self.start_time = time.time()
        self.tasks_completed = 0
        self.threats_blocked = 0
        self.memory_entries = brain.execute("SELECT COUNT(*) FROM memory").fetchone()[0]
        self.status = "ONLINE"
        self.active_protocol = "IDLE"

    def uptime(self):
        secs = int(time.time() - self.start_time)
        h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

swarm = SwarmState()

AGENTS = [
    {"id": 1, "name": "SUPERVISOR",  "role": "Orchestrates task decomposition",  "status": "active", "load": 0.0, "color": "#00e5ff"},
    {"id": 2, "name": "PLANNER",     "role": "Builds execution strategies",      "status": "active", "load": 0.0, "color": "#00ff88"},
    {"id": 3, "name": "RESEARCHER",  "role": "Web scraping & knowledge ingest",  "status": "active", "load": 0.0, "color": "#c84dff"},
    {"id": 4, "name": "DEVELOPER",   "role": "Code execution & sandbox",         "status": "active", "load": 0.0, "color": "#ff9500"},
    {"id": 5, "name": "VALIDATOR",   "role": "Quality gates & threat detection", "status": "active", "load": 0.0, "color": "#ffd100"},
]

def recall(query, limit=5):
    """FTS5 memory search"""
    try:
        rows = brain.execute(
            "SELECT source, content, timestamp FROM memory_fts WHERE memory_fts MATCH ? ORDER BY rank LIMIT ?",
            (query, limit)
        ).fetchall()
        return [{"source": r[0], "content": r[1][:200], "timestamp": r[2]} for r in rows]
    except:
        return []

def remember(source, content):
    """Store in brain"""
    brain.execute("INSERT INTO memory (source, content) VALUES (?, ?)", (source, content))
    brain.commit()
    swarm.memory_entries += 1

# ── FastAPI App ──────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    remember("system", "COSMOS SERVER online — swarm initialized")
    yield

app = FastAPI(title="NEXUS COSMOS", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── REST Endpoints ───────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": swarm.status,
        "uptime": swarm.uptime(),
        "memory_entries": swarm.memory_entries,
        "tasks_completed": swarm.tasks_completed,
        "threats_blocked": swarm.threats_blocked,
        "active_protocol": swarm.active_protocol,
        "gpu": "CPU (Android/Termux)",
        "agents": len(AGENTS),
    }

@app.get("/agents")
async def agents():
    # Simulate live agent load for the dashboard
    for ag in AGENTS:
        ag["load"] = round(random.uniform(0.05, 0.95), 2)
    return {
        "agents": AGENTS,
        "swarm_uptime": swarm.uptime(),
        "protocol": swarm.active_protocol,
    }

@app.get("/memory")
async def memory_search(q: str = "", limit: int = 5):
    if not q:
        return {"results": [], "total": swarm.memory_entries}
    return {"results": recall(q, limit), "total": swarm.memory_entries}

@app.post("/execute")
async def execute_task(task: dict):
    """Execute a task through the swarm — stub for now, routes to Hermes tools later"""
    protocol = task.get("protocol", "ANALYZE")
    content = task.get("content", "")
    swarm.active_protocol = protocol
    swarm.tasks_completed += 1
    remember("task", f"[{protocol}] {content}")
    return {
        "ok": True,
        "protocol": protocol,
        "task_id": swarm.tasks_completed,
        "result": f"Task queued: {content[:80]}"
    }

@app.post("/scrape")
async def scrape(url: dict):
    """Web scrape — uses system tools"""
    from urllib.request import urlopen, Request
    target = url.get("url", "")
    try:
        req = Request(target, headers={"User-Agent": "VEILPIERCER/1.0"})
        with urlopen(req, timeout=10) as resp:
            html = resp.read().decode("utf-8", errors="replace")[:5000]
        remember("scrape", f"URL: {target} — {len(html)} chars ingested")
        swarm.tasks_completed += 1
        return {"ok": True, "url": target, "chars": len(html)}
    except Exception as e:
        return {"ok": False, "url": target, "error": str(e)}

@app.get("/threats")
async def threats():
    return {
        "threats_blocked": swarm.threats_blocked,
        "active_threats": 0,
        "anomaly_score": round(random.uniform(0, 0.3), 2),
    }

# ── WebSocket ────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    WS_CLIENTS.add(ws)
    try:
        await ws.send_json({
            "type": "connected",
            "swarm": swarm.status,
            "agents": len(AGENTS),
            "uptime": swarm.uptime(),
        })
        while True:
            data = await ws.receive_text()
            msg = json.loads(data)
            cmd = msg.get("cmd", "")

            if cmd == "status":
                await ws.send_json(await health())
            elif cmd == "agents":
                await ws.send_json(await agents())
            elif cmd == "remember":
                remember(msg.get("source", "ws"), msg.get("content", ""))
                await ws.send_json({"ok": True, "memory": swarm.memory_entries})
            elif cmd == "protocol":
                swarm.active_protocol = msg.get("protocol", "IDLE")
                await ws.send_json({"ok": True, "protocol": swarm.active_protocol})
            else:
                await ws.send_json({"type": "echo", "data": data})
    except WebSocketDisconnect:
        pass
    finally:
        WS_CLIENTS.discard(ws)

# ── Dashboard ────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEXUS COSMOS — Live</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:#040608; color:#ddeaf5; font-family:'Fira Code',monospace; padding:24px; }}
h1 {{ color:#00e5ff; font-size:18px; letter-spacing:4px; margin-bottom:8px; }}
h1 span {{ color:#c84dff; }}
.status {{ font-size:11px; color:#4a6a80; margin-bottom:24px; }}
.card {{ background:#0c1219; border:1px solid #14222e; border-radius:6px; padding:16px; margin-bottom:16px; }}
.card h3 {{ font-size:11px; letter-spacing:2px; color:#00e5ff; margin-bottom:10px; }}
.row {{ display:flex; gap:16px; flex-wrap:wrap; }}
.agent {{ background:#080c10; border:1px solid #1e3448; border-radius:4px; padding:12px; flex:1; min-width:150px; }}
.agent .name {{ font-size:12px; font-weight:bold; }}
.agent .role {{ font-size:9px; color:#4a6a80; margin:4px 0; }}
.agent .load {{ font-size:20px; font-weight:bold; margin-top:6px; }}
.bar-wrap {{ width:100%; height:4px; background:#14222e; border-radius:2px; margin-top:6px; }}
.bar {{ height:4px; border-radius:2px; transition:width 0.3s; }}
.metric {{ display:flex; justify-content:space-between; font-size:10px; padding:4px 0; }}
.metric .label {{ color:#4a6a80; }}
.metric .val {{ color:#00ff88; }}
button {{ background:#0c1219; border:1px solid #00e5ff; color:#00e5ff; font-family:'Fira Code',monospace; font-size:10px; padding:6px 14px; cursor:pointer; letter-spacing:1px; margin:4px; }}
button:hover {{ background:#14222e; }}
#log {{ max-height:200px; overflow-y:auto; font-size:9px; color:#4a6a80; margin-top:8px; line-height:1.6; }}
</style>
</head>
<body>
<h1>NEXUS <span>COSMOS</span></h1>
<div class="status" id="status">● CONNECTING to localhost:8000…</div>

<div class="card">
<h3>🧠 5-AGENT SWARM</h3>
<div class="row" id="agents"></div>
</div>

<div class="card">
<h3>📊 SWARM METRICS</h3>
<div id="metrics"></div>
</div>

<div class="card">
<h3>🎮 COMMANDS</h3>
<button onclick="sendCmd('status')">STATUS</button>
<button onclick="sendCmd('agents')">REFRESH AGENTS</button>
<button onclick="sendCmd('protocol', {{protocol:'RESEARCH'}})">RESEARCH MODE</button>
<button onclick="sendCmd('protocol', {{protocol:'DEVELOP'}})">DEVELOP MODE</button>
<button onclick="sendCmd('protocol', {{protocol:'DEFEND'}})">DEFEND MODE</button>
<button onclick="sendCmd('remember', {{source:'dashboard',content:'Manual entry — test memory'}})">TEST MEMORY</button>
</div>

<div class="card">
<h3>📜 LIVE LOG</h3>
<div id="log"></div>
</div>

<script>
const WS_URL = `ws://${{location.hostname}}:8000/ws`;
let ws;

function connect() {{
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {{
        document.getElementById('status').innerHTML = '● NEXUS ANTIGRAVITY · LIVE';
        document.getElementById('status').style.color = '#00ff88';
        log('Connected to COSMOS server');
        sendCmd('agents');
    }};
    ws.onmessage = (e) => {{
        const data = JSON.parse(e.data);
        if (data.type === 'connected') {{
            log(`Swarm online — ${{data.agents}} agents, uptime ${{data.uptime}}`);
        }}
        if (data.agents) renderAgents(data.agents);
        if (data.uptime) updateMetrics(data);
        if (data.protocol) log(`Protocol: ${{data.protocol}}`);
    }};
    ws.onclose = () => {{
        document.getElementById('status').innerHTML = '● OFFLINE — reconnecting…';
        document.getElementById('status').style.color = '#ff1f3d';
        setTimeout(connect, 2000);
    }};
    ws.onerror = () => ws.close();
}}

function sendCmd(cmd, extra={{}}) {{
    if (ws && ws.readyState === WebSocket.OPEN) {{
        ws.send(JSON.stringify({{cmd, ...extra}}));
    }}
}}

function renderAgents(agents) {{
    document.getElementById('agents').innerHTML = agents.map(a => `
        <div class="agent">
            <div class="name" style="color:${{a.color}}">${{a.name}}</div>
            <div class="role">${{a.role}}</div>
            <div class="load" style="color:${{a.color}}">${{(a.load*100).toFixed(0)}}%</div>
            <div class="bar-wrap"><div class="bar" style="width:${{a.load*100}}%;background:${{a.color}}"></div></div>
        </div>
    `).join('');
}}

function updateMetrics(data) {{
    document.getElementById('metrics').innerHTML = `
        <div class="metric"><span class="label">UPTIME</span><span class="val">${{data.uptime || '--'}}</span></div>
        <div class="metric"><span class="label">MEMORY ENTRIES</span><span class="val">${{data.memory_entries || 0}}</span></div>
        <div class="metric"><span class="label">TASKS COMPLETED</span><span class="val">${{data.tasks_completed || 0}}</span></div>
        <div class="metric"><span class="label">THREATS BLOCKED</span><span class="val">${{data.threats_blocked || 0}}</span></div>
    `;
}}

function log(msg) {{
    const el = document.getElementById('log');
    const line = document.createElement('div');
    line.textContent = `[${{new Date().toLocaleTimeString()}}] ${{msg}}`;
    el.prepend(line);
    if (el.children.length > 50) el.removeChild(el.lastChild);
}}

connect();
</script>
</body>
</html>"""

# ── Run ──────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
