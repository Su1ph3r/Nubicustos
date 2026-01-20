#!/bin/bash
# Setup script for Linux deployments of Nubicustos
# Fixes permission issues with credential storage and Docker socket access

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_ROOT/.env"

echo "Nubicustos Linux Permission Setup"
echo "=================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "Running as root - will set permissions for API user (UID 1000)"
else
    echo "Note: Some operations may require sudo. Run with sudo if you encounter permission errors."
fi

# ============================================================================
# Docker Socket Group Configuration
# ============================================================================
echo ""
echo "Configuring Docker socket access..."

# Detect Docker socket group ID
if [ -S /var/run/docker.sock ]; then
    DOCKER_GID=$(stat -c '%g' /var/run/docker.sock 2>/dev/null || stat -f '%g' /var/run/docker.sock 2>/dev/null)
    echo "Detected Docker socket GID: $DOCKER_GID"

    # Update or create .env file with DOCKER_GID
    if [ -f "$ENV_FILE" ]; then
        # Check if DOCKER_GID is already set
        if grep -q "^DOCKER_GID=" "$ENV_FILE"; then
            # Update existing value
            sed -i "s/^DOCKER_GID=.*/DOCKER_GID=$DOCKER_GID/" "$ENV_FILE" 2>/dev/null || \
            sed -i '' "s/^DOCKER_GID=.*/DOCKER_GID=$DOCKER_GID/" "$ENV_FILE"
            echo "Updated DOCKER_GID in .env"
        else
            # Append to file
            echo "" >> "$ENV_FILE"
            echo "# Docker socket group ID for Linux (auto-detected)" >> "$ENV_FILE"
            echo "DOCKER_GID=$DOCKER_GID" >> "$ENV_FILE"
            echo "Added DOCKER_GID to .env"
        fi
    else
        # Create .env with DOCKER_GID
        echo "# Nubicustos Environment Configuration" > "$ENV_FILE"
        echo "" >> "$ENV_FILE"
        echo "# Docker socket group ID for Linux (auto-detected)" >> "$ENV_FILE"
        echo "DOCKER_GID=$DOCKER_GID" >> "$ENV_FILE"
        echo "Created .env with DOCKER_GID"
    fi
else
    echo "Warning: Docker socket not found at /var/run/docker.sock"
    echo "Make sure Docker is installed and running."
fi

# ============================================================================
# Directory Creation
# ============================================================================
echo ""
echo "Creating required directories..."
mkdir -p "$PROJECT_ROOT/credentials/aws"
mkdir -p "$PROJECT_ROOT/credentials/azure"
mkdir -p "$PROJECT_ROOT/reports"
mkdir -p "$PROJECT_ROOT/logs"
mkdir -p "$PROJECT_ROOT/iac-staging"

# ============================================================================
# Permission Configuration
# ============================================================================
echo ""
echo "Setting directory permissions..."

if [ "$EUID" -eq 0 ]; then
    # Set ownership to UID 1000 (the API container user)
    chown -R 1000:1000 "$PROJECT_ROOT/credentials"
    chown -R 1000:1000 "$PROJECT_ROOT/iac-staging"
    # Reports needs to be writable by multiple containers
    chmod -R 777 "$PROJECT_ROOT/reports"
    chmod -R 777 "$PROJECT_ROOT/logs"
    echo "Permissions set successfully."
else
    echo ""
    echo "Run the following commands with sudo to set permissions:"
    echo ""
    echo "  sudo chown -R 1000:1000 $PROJECT_ROOT/credentials"
    echo "  sudo chown -R 1000:1000 $PROJECT_ROOT/iac-staging"
    echo "  sudo chmod -R 777 $PROJECT_ROOT/reports"
    echo "  sudo chmod -R 777 $PROJECT_ROOT/logs"
    echo ""
    echo "Or run this script with sudo:"
    echo "  sudo $0"
fi

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "============================================"
echo "Setup complete!"
echo "============================================"
echo ""
if [ -n "$DOCKER_GID" ]; then
    echo "Docker GID configured: $DOCKER_GID"
fi
echo ""
echo "You can now run: docker compose up -d"
echo ""
echo "If you still encounter Docker permission issues, ensure your user"
echo "is in the docker group: sudo usermod -aG docker \$USER"
echo "(Then log out and back in)"
