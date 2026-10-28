# AlgoVoi Retention Chain Service
# Stateless FastAPI microservice — self-verifiable payment-receipt audit chains.
#
# POST /v1/chain-ref        — compute retention_chain_ref for a record
# POST /v1/verify-link      — verify a single chain link
# POST /v1/verify-sequence  — verify a sequence forms an unbroken chain
# GET  /health              — liveness probe
#
# Bridged into the substrate-2 control plane via S2_HUB_URL + S2_HUB_TOKEN.
#
# Build context: algovoi-retention-chain/python/ (not the monorepo root)
# docker build -t algovoi-retention-chain:0.1.0 .

FROM python:3.11-slim

LABEL org.opencontainers.image.title="AlgoVoi Retention Chain"
LABEL org.opencontainers.image.description="Self-verifiable retention chain for payment receipts. IETF: draft-hopley-x402-retention-chain"
LABEL org.opencontainers.image.vendor="AlgoVoi"
LABEL org.opencontainers.image.licenses="LicenseRef-AlgoVoi-Commercial"
LABEL org.opencontainers.image.version="0.1.0"

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md CHANGELOG.md LICENSE ./
COPY algovoi_retention_chain ./algovoi_retention_chain
COPY app ./app
COPY scripts ./scripts

RUN pip install --no-cache-dir -e ".[serve]"

RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

ENV PYTHONUNBUFFERED=1
ENV RETENTION_CHAIN_BIND=0.0.0.0:8096

EXPOSE 8096

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8096/health || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host $(echo $RETENTION_CHAIN_BIND | cut -d: -f1) --port $(echo $RETENTION_CHAIN_BIND | cut -d: -f2) --log-level info"]
