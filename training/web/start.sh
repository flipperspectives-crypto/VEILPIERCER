#!/bin/bash
# VeilPiercer — Production Server Start Script
# Usage: ./start.sh [PORT]

PORT="${1:-9100}"
[ "$PORT" = "--port" ] && PORT="${2:-9100}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAX_RESTARTS=10
RESTART_WINDOW=300
RESTART_COUNT=0
RESTART_START=$(date +%s)

echo "═══ VeilPiercer v2.2 — Production Server ═══"
echo "  Port:     $PORT"
echo "  Stats:    $SCRIPT_DIR/../stats.json"
echo "  Max restarts: $MAX_RESTARTS/${RESTART_WINDOW}s"
echo ""

cd "$SCRIPT_DIR"

# Kill any old server on this port
OLD_PID=$(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K\d+' | head -1)
if [ -n "$OLD_PID" ]; then
    echo "[$(date '+%H:%M:%S')] Killing old server on port $PORT (pid $OLD_PID)..."
    kill "$OLD_PID" 2>/dev/null
    sleep 1
fi

while true; do
    echo "[$(date '+%H:%M:%S')] Starting server on port $PORT..."
    python3 sias_server.py --port "$PORT" 2>&1
    EXIT_CODE=$?

    NOW=$(date +%s)
    if [ $((NOW - RESTART_START)) -gt $RESTART_WINDOW ]; then
        RESTART_COUNT=0
        RESTART_START=$NOW
    fi

    RESTART_COUNT=$((RESTART_COUNT + 1))

    if [ $RESTART_COUNT -gt $MAX_RESTARTS ]; then
        echo "[$(date '+%H:%M:%S')] FATAL: $MAX_RESTARTS restarts in ${RESTART_WINDOW}s — giving up"
        exit 1
    fi

    echo "[$(date '+%H:%M:%S')] Exited (code $EXIT_CODE). Restart $RESTART_COUNT/$MAX_RESTARTS in 3s..."
    sleep 3
done
