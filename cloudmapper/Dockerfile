# CloudMapper AWS Visualization Tool
# https://github.com/duo-labs/cloudmapper

FROM python:3.9-slim

WORKDIR /opt/cloudmapper

# Install system dependencies (including build tools for Python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    jq \
    awscli \
    gcc \
    g++ \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libjq-dev \
    libonig-dev \
    autoconf \
    automake \
    libtool \
    make \
    && rm -rf /var/lib/apt/lists/*

# Clone CloudMapper
RUN git clone --depth 1 https://github.com/duo-labs/cloudmapper.git .

# Upgrade pip and install Python dependencies
# Use --ignore-installed to avoid conflicts with system packages
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt || \
    pip install --no-cache-dir boto3 policyuniverse pyjq pyyaml parliament netaddr

# Create necessary directories
RUN mkdir -p /reports /config

# Set up the entry point
ENTRYPOINT ["python", "cloudmapper.py"]

CMD ["--help"]
