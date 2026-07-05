#!/bin/bash
# VeilPiercer — Production Server Start Script
# Auto-restarts on crash, persists stats to disk
# Usage: ./start.sh [--port 9100]

set -e

PORT="${1:-9100}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MAX_RESTARTS=10
RESTART_WINDOW=300  # 5 minutes
RESTART_COUNT=0
RESTART_START=$(date +%s)

echo "═══ VeilPiercer v2.2 — Production Server ═══"
echo "  Port:     $PORT"
echo "  Stats:    $SCRIPT_DIR/../stats.json"
echo "  Ledger:   $SCRIPT_DIR/../training_ledger.json"
echo "  Max restarts: $MAX_RESTARTS in ${RESTART_WINDOW}s"
echo ""

cd "$SCRIPT_DIR"

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

    echo "[$(date '+%H:%M:%S')] Server exited (code $EXIT_CODE). Restarting in 3s ($RESTART_COUNT/$MAX_RESTARTS)..."
    sleep 3
done
