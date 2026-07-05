# Deploy VeilPiercer

Two options to make your demo publicly accessible.

## Option 1: Fly.io (recommended)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Deploy
cd veilpiercer
fly deploy

# Your app will be at: veilpiercer.fly.dev
```

The `fly.toml` is already configured. Fly.io has a generous free tier.

## Option 2: Cloudflared Tunnel (zero cost, runs from any machine)

```bash
# Install cloudflared
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared
chmod +x cloudflared

# Start a tunnel (first time requires browser auth)
cloudflared tunnel --url http://localhost:9100

# Output: https://your-tunnel.trycloudflare.com
```

No account needed for quick tunnels. For permanent tunnels, use `cloudflared tunnel create`.

## Option 3: Run locally + share via ngrok

```bash
# Start server
python3 web/sias_server.py --port 9100

# In another terminal
ngrok http 9100
# Output: https://xxxx.ngrok.io
```

## Verify deployment

```bash
curl https://your-url/health
# → {"status": "ok", "version": "2.1.0"}

curl https://your-url/api/stats
# → {"total_scans": ..., "uptime_seconds": ...}
```

## Production notes

- Stats persist to `stats.json` (survives restarts)
- Use `web/start.sh` for auto-restart on crash
- Max 10 restarts in 5 minutes, then gives up
- No API keys, no cloud — fully self-contained
