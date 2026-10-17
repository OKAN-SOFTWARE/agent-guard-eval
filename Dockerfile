# Multi-stage secure build for AgentGuard
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tooling
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY agentguard/ ./agentguard/

# Build wheel package
RUN pip install --no-cache-dir --upgrade pip build && \
    python -m build --wheel

# Runtime stage
FROM python:3.12-slim AS runner

# Security hardening: create non-root user
RUN groupadd -g 10001 agentguard && \
    useradd -u 10001 -g agentguard -s /bin/sh -m agentguard

WORKDIR /app

# Copy wheel from builder and install
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir /tmp/*.whl && \
    rm -rf /tmp/*.whl

# Switch to unprivileged user
USER agentguard:agentguard

# Default working volume
VOLUME ["/workspace"]
WORKDIR /workspace

ENTRYPOINT ["agentguard"]
CMD ["--help"]
