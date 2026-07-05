# Deploy VeilPiercer

Five ways to make your audit demo publicly accessible. Pick one.

## Option 1: Docker Compose (recommended — any machine)

```bash
git clone https://github.com/flipperspectives-crypto/VEILPIERCER
cd VEILPIERCER
docker compose up -d
# Open http://localhost:9100
```

One command. Stats persist in `stats.json`. Auto-restarts on crash.

## Option 2: Fly.io (free tier, managed hosting)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Deploy
cd VEILPIERCER
fly launch    # first time only
fly deploy    # subsequent updates
```

Your app at: `veilpiercer.fly.dev`. `fly.toml` is configured.

## Option 3: Railway (free tier, one-click deploy)

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/veilpiercer)

Or manually:
```bash
railway init
railway up
```

`railway.json` is configured.

## Option 4: Cloudflared Tunnel (zero setup, temporary URL)

```bash
# Start server locally
python3 web/sias_server.py --port 9100

# In another terminal
cloudflared tunnel --url http://localhost:9100
# Output: https://random-name.trycloudflare.com
```

No account needed. URL changes each restart. Good for demos.

## Option 5: ngrok (quick public URL)

```bash
# Start server
python3 web/sias_server.py --port 9100

# Expose publicly
ngrok http 9100
# Output: https://xxxx.ngrok.io
```

Free tier gives temporary URLs with rate limiting.

## Verify

```bash
curl https://your-url/health
# → {"status": "ok", "version": "2.1.0"}

curl https://your-url/api/stats
# → {"total_scans": 0, "uptime_seconds": 12, ...}
```

## Persistence

Stat files are mounted as volumes in Docker, or written to disk locally:
- `stats.json` — scan metrics (survives restarts)
- `training_ledger.json` — SIAS audit chain
- `reports/` — generated audit reports
