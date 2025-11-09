# Multi-stage Dockerfile for System Cleaner
# Build stage: install dependencies
FROM python:3.12-slim as builder

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies using uv (frozen lockfile)
RUN uv sync --frozen --no-dev

# Runtime stage: minimal image
FROM python:3.12-slim

# Install uv for runtime (needed for uv run)
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY src/ ./src/
COPY config.yaml.example ./

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app/src:$PYTHONPATH"

# Create non-root user for security
RUN useradd -m -u 1000 syscleaner && \
    chown -R syscleaner:syscleaner /app

USER syscleaner

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -m syscleaner health || exit 1

# Default command
ENTRYPOINT ["python", "-m", "syscleaner"]
CMD ["--help"]

