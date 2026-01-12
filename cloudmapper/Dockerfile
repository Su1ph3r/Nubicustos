# CloudMapper Dockerfile - Optimized with multi-stage build
# Stage 1: Build stage
# Using Python 3.9 for compatibility with CloudMapper's older dependencies
FROM python:3.9-slim-bookworm AS builder

LABEL org.opencontainers.image.title="Nubicustos CloudMapper"
LABEL org.opencontainers.image.description="AWS infrastructure visualization for Nubicustos"
LABEL org.opencontainers.image.vendor="Nubicustos"
LABEL org.opencontainers.image.source="https://github.com/Su1ph3r/Cloud-Stack"

WORKDIR /opt/cloudmapper

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    autoconf \
    automake \
    libtool \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Clone CloudMapper and build wheels
RUN git clone --depth 1 https://github.com/duo-labs/cloudmapper.git . \
    && pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Stage 2: Production stage
FROM python:3.9-slim-bookworm AS production

WORKDIR /opt/cloudmapper

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    python3-tk \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install AWS CLI v2
RUN curl -sL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && apt-get update && apt-get install -y --no-install-recommends unzip \
    && unzip -q awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws \
    && apt-get remove -y unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels from builder and install
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

# Copy CloudMapper source
COPY --from=builder /opt/cloudmapper /opt/cloudmapper

# Create directories
RUN mkdir -p /root/.aws /reports

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
