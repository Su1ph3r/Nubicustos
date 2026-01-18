# PMapper (Principal Mapper) Docker Image
# IAM privilege escalation path analysis tool
# https://github.com/nccgroup/PMapper

FROM python:3.11-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        graphviz \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install PMapper
RUN pip install --no-cache-dir principalmapper

# Create directories for output and AWS credentials
RUN mkdir -p /output /root/.aws /root/.principalmap

# Set working directory
WORKDIR /output

# Default entrypoint
ENTRYPOINT ["pmapper"]

# Default command shows help
CMD ["--help"]
