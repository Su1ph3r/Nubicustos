# Report Processor Dockerfile - Optimized with multi-stage build
# Stage 1: Build stage
FROM python:3.11.9-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy and build Python dependencies as wheels
COPY requirements.txt .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# Stage 2: Production stage
FROM python:3.11.9-slim-bookworm AS production

LABEL org.opencontainers.image.title="Nubicustos Report Processor"
LABEL org.opencontainers.image.description="Report processing and analysis for Nubicustos"
LABEL org.opencontainers.image.vendor="Nubicustos"
LABEL org.opencontainers.image.source="https://github.com/Su1ph3r/Cloud-Stack"

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy wheels from builder and install
COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy application files
COPY process_reports.py .
COPY merge_findings.py .
COPY db_loader.py .
COPY generate_summary.py .
COPY send_notifications.py .
COPY compare_scans.py .
COPY analyze_report.py .
COPY remediation_kb.py .
COPY attack_path_edges.py .
COPY attack_path_analyzer.py .
COPY severity_scoring.py .

# Create directories
RUN mkdir -p /reports /processed

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash processor \
    && chown -R processor:processor /app /reports /processed

USER processor

# Set environment variables
ENV PYTHONUNBUFFERED=1

CMD ["python", "process_reports.py"]
