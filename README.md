<div align="center">

# 🔮 VEILPIERCER

### Autonomous AI Swarm Intelligence — Powered by Your GPU

> **🚀 [LIVE DEMO: Free Smart Contract Audit](https://3924739b617b797e-65-94-86-110.serveousercontent.com) — Try it now**  
> Paste Solidity → 3 engines scan in <1s → findings + proofs. No API keys.

[![GPU](https://img.shields.io/badge/GPU-CUDA%20Accelerated-00e5ff)](https://developer.nvidia.com/cuda-toolkit)
[![Cost](https://img.shields.io/badge/Monthly%20Cost-$0-34d399)](https://github.com)
[![Agents](https://img.shields.io/badge/AI%20Agents-5-a78bfa)](https://github.com)

<br>

#### Smart Contract Audit Engine — Live Metrics

[![Dep Resolution](https://img.shields.io/endpoint?url=https://veilpiercer.fly.dev/api/badge/dep_resolution.json)](https://veilpiercer.fly.dev/dashboard)
[![Total Scans](https://img.shields.io/endpoint?url=https://veilpiercer.fly.dev/api/badge/scans.json)](https://veilpiercer.fly.dev/dashboard)
[![Errors](https://img.shields.io/endpoint?url=https://veilpiercer.fly.dev/api/badge/errors.json)](https://veilpiercer.fly.dev/dashboard)
[![Uptime](https://img.shields.io/endpoint?url=https://veilpiercer.fly.dev/api/badge/uptime.json)](https://veilpiercer.fly.dev/dashboard)

<br>

#### Smart Contract Audit — v2.2

[![Benchmark](https://img.shields.io/badge/benchmark-225%20contracts-blue)](https://github.com/flipperspectives-crypto/VEILPIERCER/blob/main/docs/benchmark-report-v2.2.md)
[![Community](https://img.shields.io/badge/community-leaderboard-purple)](https://veilpiercer.fly.dev/community)
[![Verify](https://img.shields.io/badge/verify-get%20badge-green)](https://veilpiercer.fly.dev/verify)

*Pierce the veil. See everything.*

**One-time purchase. Zero subscriptions. Unlimited intelligence.**

</div>

---

## What Is VeilPiercer?

VeilPiercer is a **GPU-accelerated AI swarm** that runs entirely on your local machine. Five autonomous agents collaborate on every task — research, analysis, code generation, threat detection — all powered by your own GPU. No cloud. No API keys. No monthly fees.

## ⚡ Features

| Feature | Description |
|---------|-------------|
| 🧠 **5-Agent AI Swarm** | Supervisor → Planner → Researcher → Developer → Validator |
| 🎮 **CUDA GPU Processing** | 512 autonomous agents via Julia CUDA kernels |
| 🛡️ **Sentinel Membrane** | Real-time rogue detection + anomaly quarantine |
| 📱 **Phone Dashboard** | Control everything from your phone (PWA) |
| 🎤 **Voice Commands** | Speak → Whisper transcribes → Swarm executes |
| 🎨 **Image Generation** | Stable Diffusion on your GPU |
| 🌐 **Web Scraper** | Scrape any URL → auto-ingest into brain memory |
| 💻 **Code Sandbox** | Execute Python remotely with 30s timeout |
| 🧬 **Growing Memory** | SQLite brain with FTS5 — the system learns |
| 🤖 **Discord & Telegram** | Bot bridges for remote AI control |

## 🏗️ Architecture

```
┌──────────────────────────────────────────┐
│           NEXUS COSMOS (FastAPI)          │
│                                          │
│  Supervisor → Planner → Researcher       │
│       ↑                    ↓             │
│    Reward  ←──────── Validator           │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │  Julia CUDA GPU · 512 Swarm Agents │  │
│  └────────────────────────────────────┘  │
│  ┌────────────────────────────────────┐  │
│  │  SQLite Brain · FTS5 Memory        │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
```

## 🚀 Quick Start

```bash
ollama pull llama3.2
ollama create nexus-cosmos -f Modelfile
pip install fastapi uvicorn psutil websockets httpx beautifulsoup4
python cosmos_server.py
```

Open `http://localhost:9100` — done.

## Smart Contract Audit — Try It Now

```bash
# One command — Docker (recommended)
docker run -p 9100:9100 -d ghcr.io/flipperspectives-crypto/veilpiercer:latest

# Or clone and run
git clone https://github.com/flipperspectives-crypto/VEILPIERCER
cd VEILPIERCER && docker compose up -d

# Or no Docker — just Python
python3 web/sias_server.py --port 9100
```

Open `http://localhost:9100` and paste any Solidity contract. Or click one of the example buttons: Reentrancy, Flash Loan, Missing Auth, Oracle Manipulation.

**[Live Demo](https://3924739b617b797e-65-94-86-110.serveousercontent.com)** · **[Deploy Guide](DEPLOY.md)** · **[Community Leaderboard](https://3924739b617b797e-65-94-86-110.serveousercontent.com/community)** · **[Get Verified Badge](https://3924739b617b797e-65-94-86-110.serveousercontent.com/verify)** · **[Public Audits](reports/public_audits/)** · **[Roadmap](ROADMAP.md)**

### Free Hosting Options

| Platform | Command | Cost |
|----------|---------|------|
| Fly.io | `fly deploy` | Free tier |
| Railway | `railway up` | Free tier |
| Docker | `docker compose up -d` | Your machine |
| Cloudflared | `cloudflared tunnel --url :9100` | Free |

See [DEPLOY.md](DEPLOY.md) for full instructions.

### GitHub Action — Auto-audit every PR

Add this one file to any Solidity repo:

**.github/workflows/veilpiercer.yml**
```yaml
name: VeilPiercer Audit
on:
  pull_request:
    paths: ['**.sol']
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: flipperspectives-crypto/VEILPIERCER/.github/actions/audit@main
```

Every PR that touches `.sol` files gets scanned and findings posted as a comment. Free. No API keys.

## Pricing

| | Cloud AI | VeilPiercer |
|---|---|---|
| Monthly cost | $20-200/mo | **$0/mo** |
| Payment | Subscription | **$49 once** |
| Privacy | Cloud | **100% local** |
| Limits | Token caps | **Unlimited** |

---

<div align="center">

**Built with NEXUS ANTIGRAVITY COSMOS**

*Zero cloud. Zero cost. Pure power.*

</div>
