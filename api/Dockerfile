# API Dockerfile - Optimized with multi-stage build and security hardening
# Stage 1: Build stage
FROM python:3.11.9-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Stage 2: Production stage
FROM python:3.11.9-slim-bookworm AS production

LABEL org.opencontainers.image.title="Nubicustos API"
LABEL org.opencontainers.image.description="REST API for Nubicustos cloud security auditing platform"
LABEL org.opencontainers.image.vendor="Nubicustos"
LABEL org.opencontainers.image.source="https://github.com/Su1ph3r/Cloud-Stack"

# Security: Set environment variables to prevent Python from writing bytecode and buffering
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean \
    # Security: Remove unnecessary packages
    && apt-get autoremove -y

# Copy wheels from builder and install
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application code
COPY . .

# Create non-root user for security
# Use specific UID/GID for predictable permissions
RUN groupadd -r -g 1000 apigroup \
    && useradd -r -u 1000 -g apigroup -s /sbin/nologin apiuser \
    && chown -R apiuser:apigroup /app \
    # Security: Remove write permissions from app directory
    && chmod -R a-w /app \
    # Create tmp directory for runtime needs
    && mkdir -p /tmp/app \
    && chown apiuser:apigroup /tmp/app

# Switch to non-root user
USER apiuser

# Expose port
EXPOSE 8000

# Health check with improved settings
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/health/live || exit 1

# Run application with graceful shutdown support
# --timeout-graceful-shutdown enables proper SIGTERM handling
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "30"]
