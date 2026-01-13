# CloudSploit Security Scanner
# https://github.com/aquasecurity/cloudsploit

FROM node:18-alpine

WORKDIR /var/scan

# Install git for cloning the repo
RUN apk add --no-cache git python3 make g++

# Clone CloudSploit
RUN git clone --depth 1 https://github.com/aquasecurity/cloudsploit.git

WORKDIR /var/scan/cloudsploit

# Install dependencies
RUN npm install

# Create reports directory
RUN mkdir -p /reports

WORKDIR /var/scan/cloudsploit

# Default entrypoint is node
ENTRYPOINT ["node", "index.js"]

# Default command shows help
CMD ["--help"]
