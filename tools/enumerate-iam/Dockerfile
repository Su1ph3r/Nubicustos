# enumerate-iam Dockerfile
# Builds container for AWS IAM permission enumeration
FROM python:3.11-slim

LABEL maintainer="nubicustos"
LABEL description="enumerate-iam - AWS IAM permission brute-forcing tool"

# Install git and dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Clone enumerate-iam
WORKDIR /opt
RUN git clone https://github.com/andresriancho/enumerate-iam.git

# Install Python dependencies
WORKDIR /opt/enumerate-iam
RUN pip install --no-cache-dir -r requirements.txt

# Create reports directory
RUN mkdir -p /reports

# Set working directory
WORKDIR /opt/enumerate-iam

# Default command
ENTRYPOINT ["python", "enumerate-iam.py"]
CMD ["--help"]
