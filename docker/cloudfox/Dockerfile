# CloudFox Docker Image
# Downloads pre-built binary from https://github.com/BishopFox/cloudfox/releases

FROM debian:bookworm-slim

# CloudFox version
ARG CLOUDFOX_VERSION=1.17.0

# Install required dependencies and download CloudFox
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip \
    && curl -sL "https://github.com/BishopFox/cloudfox/releases/download/v${CLOUDFOX_VERSION}/cloudfox-linux-amd64.zip" \
       -o /tmp/cloudfox.zip \
    && unzip /tmp/cloudfox.zip -d /tmp \
    && mv /tmp/cloudfox/cloudfox /usr/local/bin/cloudfox \
    && chmod +x /usr/local/bin/cloudfox \
    && rm -rf /tmp/* \
    && apt-get purge -y curl unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Install AWS CLI v2
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl unzip \
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip" \
    && unzip /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/* \
    && apt-get purge -y curl unzip \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Create reports directory
RUN mkdir -p /reports /root/.aws

# Set working directory
WORKDIR /reports

# No entrypoint - commands should include 'cloudfox' as first argument
CMD ["cloudfox", "--help"]
