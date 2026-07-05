# VeilPiercer — Self-Contained Audit Server
# ==========================================
# One-command deploy: docker compose up -d
# Opens on http://localhost:9100
#
# Also deployable on: Fly.io, Railway, any Docker host

FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY web/ ./web/
COPY cli/ ./cli/
COPY core/ ./core/

RUN pip install --no-cache-dir opentimestamps-client 2>/dev/null || true

ENV PORT=9100
ENV VP_API_PORT=9100

EXPOSE 9100

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -sf http://localhost:9100/health || exit 1

WORKDIR /app/web
CMD ["python3", "sias_server.py", "--port", "9100"]
