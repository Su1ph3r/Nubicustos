# Cloudsplaining Docker Image
# AWS IAM Security Assessment tool - identifies least privilege violations
# https://github.com/salesforce/cloudsplaining

FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Cloudsplaining
RUN pip install --no-cache-dir cloudsplaining

# Create directories for output and AWS credentials
RUN mkdir -p /output /root/.aws

# Set working directory
WORKDIR /output

# Default entrypoint
ENTRYPOINT ["cloudsplaining"]

# Default command shows help
CMD ["--help"]
