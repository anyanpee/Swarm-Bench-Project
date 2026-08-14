# Agent runtime image for the canada-ca SBOM compliance audit task.
# Provides all tools the agent needs; does NOT contain tests, verify.py,
# or any solution material.

FROM python:3.11-slim

# ── System dependencies ────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        jq \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ── Python dependencies ────────────────────────────────────────────────────────
RUN pip install --no-cache-dir \
        requests \
        pandas \
        matplotlib \
        PyYAML \
        python-dateutil

# ── Workspace and output directories ──────────────────────────────────────────
RUN mkdir -p /workspace /logs/agent

# ── Task input artifacts ───────────────────────────────────────────────────────
# Only the files the agent is allowed to read at runtime are copied here.
# Tests and verify.py are intentionally excluded.
COPY input_artifacts/ /task/

# ── Default working directory ─────────────────────────────────────────────────
WORKDIR /workspace
