#!/bin/bash
# ============================================================================
# Argus - Update Library
# ============================================================================
# Shared helper functions for the update system

# ============================================================================
# Tool Categories and Mappings
# ============================================================================

# Tool categories (space-separated lists)
# Note: cloudmapper is a custom build, not an external image
CATEGORY_AWS="prowler scoutsuite-aws pacu cloudsploit cloud-custodian cartography"
CATEGORY_KUBERNETES="kube-bench kubescape kube-hunter trivy grype popeye kube-linter polaris falco"
CATEGORY_IAC="checkov terrascan tfsec"
CATEGORY_INFRASTRUCTURE="postgresql neo4j nginx grafana"
CATEGORY_CUSTOM="api cloudmapper"

# All external tools (excludes custom builds)
ALL_EXTERNAL_TOOLS="$CATEGORY_AWS $CATEGORY_KUBERNETES $CATEGORY_IAC $CATEGORY_INFRASTRUCTURE"

# Service to Docker image mapping
declare -A TOOL_IMAGES=(
    # AWS Tools
    ["prowler"]="prowler-cloud/prowler:latest"
    ["scoutsuite-aws"]="rossja/scoutsuite:latest"
    ["pacu"]="rhinosecuritylabs/pacu:latest"
    ["cloudsploit"]="aquasec/cloudsploit:latest"
    ["cloud-custodian"]="cloudcustodian/c7n:latest"
    ["cartography"]="lyft/cartography:latest"
    # Kubernetes Tools
    ["kube-bench"]="aquasec/kube-bench:latest"
    ["kubescape"]="quay.io/armosec/kubescape:latest"
    ["kube-hunter"]="aquasec/kube-hunter:latest"
    ["trivy"]="aquasec/trivy:latest"
    ["grype"]="anchore/grype:latest"
    ["popeye"]="derailed/popeye:latest"
    ["kube-linter"]="stackrox/kube-linter:latest"
    ["polaris"]="quay.io/fairwinds/polaris:latest"
    ["falco"]="falcosecurity/falco-no-driver:latest"
    # IaC Tools
    ["checkov"]="bridgecrew/checkov:latest"
    ["terrascan"]="tenable/terrascan:latest"
    ["tfsec"]="aquasec/tfsec:latest"
    # Infrastructure
    ["postgresql"]="postgres:15-alpine"
    ["neo4j"]="neo4j:5.14-community"
    ["nginx"]="nginx:alpine"
    ["grafana"]="grafana/grafana:10.2-alpine"
)

# Health check commands for each tool
declare -A HEALTH_CHECKS=(
    # AWS Tools
    ["prowler"]="--version"
    ["scoutsuite-aws"]="--help"
    ["pacu"]="--help"
    ["cloudsploit"]="--help"
    ["cloud-custodian"]="version"
    ["cartography"]="--help"
    # Kubernetes Tools
    ["kube-bench"]="version"
    ["kubescape"]="version"
    ["kube-hunter"]="--help"
    ["trivy"]="version"
    ["grype"]="version"
    ["popeye"]="version"
    ["kube-linter"]="version"
    ["polaris"]="version"
    ["falco"]="--version"
    # IaC Tools
    ["checkov"]="--version"
    ["terrascan"]="version"
    ["tfsec"]="--version"
    # Infrastructure
    ["postgresql"]="postgres --version"
    ["neo4j"]="neo4j --version"
    ["nginx"]="nginx -v"
    ["grafana"]="grafana --version"
)

# ============================================================================
# Logging Functions (matching run-all-audits.sh style)
# ============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        INFO)
            echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message"
            ;;
        WARN)
            echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} ${timestamp} - $message"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} ${timestamp} - $message"
            ;;
        *)
            echo -e "${BLUE}[$level]${NC} ${timestamp} - $message"
            ;;
    esac
}

# ============================================================================
# Version File Management
# ============================================================================

VERSIONS_FILE="$PROJECT_DIR/data/versions.json"

# Initialize versions file if it doesn't exist
init_versions_file() {
    if [ ! -f "$VERSIONS_FILE" ]; then
        mkdir -p "$(dirname "$VERSIONS_FILE")"
        cat > "$VERSIONS_FILE" << 'EOF'
{
  "schema_version": "1.0",
  "last_updated": null,
  "tools": {},
  "stack": {
    "current_commit": null,
    "previous_commit": null,
    "last_update": null
  }
}
EOF
        log INFO "Initialized versions file at $VERSIONS_FILE"
    fi
}

# Read a value from versions.json using jq
read_version_value() {
    local path="$1"
    if [ -f "$VERSIONS_FILE" ] && command -v jq &>/dev/null; then
        jq -r "$path // empty" "$VERSIONS_FILE" 2>/dev/null
    fi
}

# Update versions.json using jq
update_versions_file() {
    local tool="$1"
    local digest="$2"
    local version="$3"
    local timestamp=$(date -Iseconds)

    if ! command -v jq &>/dev/null; then
        log WARN "jq not installed - version tracking disabled"
        return 1
    fi

    init_versions_file

    local image="${TOOL_IMAGES[$tool]}"
    local current_digest=$(read_version_value ".tools[\"$tool\"].current_digest")

    # Create temp file for atomic update
    local tmp_file=$(mktemp)

    jq --arg tool "$tool" \
       --arg image "$image" \
       --arg digest "$digest" \
       --arg prev_digest "$current_digest" \
       --arg version "$version" \
       --arg timestamp "$timestamp" \
       '.last_updated = $timestamp |
        .tools[$tool] = {
          "image": $image,
          "current_digest": $digest,
          "previous_digest": ($prev_digest // null),
          "version": $version,
          "last_pull": $timestamp
        }' "$VERSIONS_FILE" > "$tmp_file" && mv "$tmp_file" "$VERSIONS_FILE"
}

# Update stack commit info
update_stack_info() {
    local current_commit="$1"
    local timestamp=$(date -Iseconds)

    if ! command -v jq &>/dev/null; then
        return 1
    fi

    init_versions_file

    local prev_commit=$(read_version_value ".stack.current_commit")
    local tmp_file=$(mktemp)

    jq --arg commit "$current_commit" \
       --arg prev "$prev_commit" \
       --arg timestamp "$timestamp" \
       '.stack.current_commit = $commit |
        .stack.previous_commit = ($prev // null) |
        .stack.last_update = $timestamp |
        .last_updated = $timestamp' "$VERSIONS_FILE" > "$tmp_file" && mv "$tmp_file" "$VERSIONS_FILE"
}

# ============================================================================
# Docker Image Functions
# ============================================================================

# Get the Docker image for a tool
get_tool_image() {
    local tool="$1"
    echo "${TOOL_IMAGES[$tool]}"
}

# Get current image digest
get_image_digest() {
    local image="$1"
    docker inspect --format='{{index .RepoDigests 0}}' "$image" 2>/dev/null | sed 's/.*@//'
}

# Get image version from labels or version command
get_image_version() {
    local tool="$1"
    local image="${TOOL_IMAGES[$tool]}"
    local health_cmd="${HEALTH_CHECKS[$tool]}"

    if [ -z "$image" ]; then
        echo "unknown"
        return
    fi

    # Try to get version from running the health check command
    local version
    version=$(docker run --rm "$image" $health_cmd 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)

    if [ -n "$version" ]; then
        echo "$version"
    else
        echo "latest"
    fi
}

# Pull a Docker image and record the digest
pull_image() {
    local tool="$1"
    local dry_run="${2:-false}"
    local image="${TOOL_IMAGES[$tool]}"

    if [ -z "$image" ]; then
        log ERROR "Unknown tool: $tool"
        return 1
    fi

    # Get current digest before pull
    local old_digest=$(get_image_digest "$image")

    if [ "$dry_run" = "true" ]; then
        log INFO "[DRY-RUN] Would pull: $image"
        return 0
    fi

    log INFO "Pulling $image..."
    if docker pull "$image" > /dev/null 2>&1; then
        local new_digest=$(get_image_digest "$image")
        local version=$(get_image_version "$tool")

        if [ "$old_digest" != "$new_digest" ]; then
            log SUCCESS "Updated $tool: $version (new digest)"
            update_versions_file "$tool" "$new_digest" "$version"
        else
            log INFO "$tool is already up to date: $version"
            update_versions_file "$tool" "$new_digest" "$version"
        fi
        return 0
    else
        log ERROR "Failed to pull $image"
        return 1
    fi
}

# ============================================================================
# Health Check Functions
# ============================================================================

# Run health check for a tool
health_check_tool() {
    local tool="$1"
    local image="${TOOL_IMAGES[$tool]}"
    local health_cmd="${HEALTH_CHECKS[$tool]}"

    if [ -z "$image" ] || [ -z "$health_cmd" ]; then
        log WARN "No health check defined for $tool"
        return 0
    fi

    log INFO "Health check: $tool..."
    if docker run --rm "$image" $health_cmd > /dev/null 2>&1; then
        log SUCCESS "$tool health check passed"
        return 0
    else
        log ERROR "$tool health check failed"
        return 1
    fi
}

# ============================================================================
# Category Functions
# ============================================================================

# Get tools in a category
get_tools_in_category() {
    local category="$1"
    case "$category" in
        aws)
            echo "$CATEGORY_AWS"
            ;;
        kubernetes|k8s)
            echo "$CATEGORY_KUBERNETES"
            ;;
        iac)
            echo "$CATEGORY_IAC"
            ;;
        infrastructure|infra)
            echo "$CATEGORY_INFRASTRUCTURE"
            ;;
        custom)
            echo "$CATEGORY_CUSTOM"
            ;;
        all)
            echo "$ALL_EXTERNAL_TOOLS"
            ;;
        *)
            log ERROR "Unknown category: $category"
            return 1
            ;;
    esac
}

# Check if a tool exists in our mappings
is_valid_tool() {
    local tool="$1"
    [ -n "${TOOL_IMAGES[$tool]}" ]
}

# Check if a tool is a custom build
is_custom_build() {
    local tool="$1"
    [[ " $CATEGORY_CUSTOM " == *" $tool "* ]]
}

# ============================================================================
# Rollback Functions
# ============================================================================

# Rollback a tool to its previous digest
rollback_tool() {
    local tool="$1"
    local dry_run="${2:-false}"

    local image="${TOOL_IMAGES[$tool]}"
    local prev_digest=$(read_version_value ".tools[\"$tool\"].previous_digest")

    if [ -z "$prev_digest" ] || [ "$prev_digest" = "null" ]; then
        log ERROR "No previous version available for $tool"
        return 1
    fi

    # Extract base image name (without tag)
    local base_image="${image%%:*}"
    local full_ref="$base_image@$prev_digest"

    if [ "$dry_run" = "true" ]; then
        log INFO "[DRY-RUN] Would rollback $tool to $prev_digest"
        return 0
    fi

    log INFO "Rolling back $tool to previous digest..."
    if docker pull "$full_ref" > /dev/null 2>&1; then
        # Tag as the expected image name
        docker tag "$full_ref" "$image"

        # Update versions file (swap current and previous)
        local current_digest=$(read_version_value ".tools[\"$tool\"].current_digest")
        local tmp_file=$(mktemp)
        local timestamp=$(date -Iseconds)

        jq --arg tool "$tool" \
           --arg current "$prev_digest" \
           --arg prev "$current_digest" \
           --arg timestamp "$timestamp" \
           '.tools[$tool].current_digest = $current |
            .tools[$tool].previous_digest = $prev |
            .tools[$tool].last_pull = $timestamp' "$VERSIONS_FILE" > "$tmp_file" && mv "$tmp_file" "$VERSIONS_FILE"

        log SUCCESS "Rolled back $tool to previous version"
        return 0
    else
        log ERROR "Failed to rollback $tool"
        return 1
    fi
}

# Rollback stack to previous git commit
rollback_stack() {
    local dry_run="${1:-false}"

    local prev_commit=$(read_version_value ".stack.previous_commit")

    if [ -z "$prev_commit" ] || [ "$prev_commit" = "null" ]; then
        log ERROR "No previous stack commit available"
        return 1
    fi

    if [ "$dry_run" = "true" ]; then
        log INFO "[DRY-RUN] Would rollback stack to commit $prev_commit"
        return 0
    fi

    log WARN "Rolling back stack to commit $prev_commit..."
    log WARN "This will discard any local changes!"

    cd "$PROJECT_DIR" || return 1

    if git reset --hard "$prev_commit"; then
        # Swap commits in versions file
        local current_commit=$(read_version_value ".stack.current_commit")
        local tmp_file=$(mktemp)
        local timestamp=$(date -Iseconds)

        jq --arg current "$prev_commit" \
           --arg prev "$current_commit" \
           --arg timestamp "$timestamp" \
           '.stack.current_commit = $current |
            .stack.previous_commit = $prev |
            .stack.last_update = $timestamp' "$VERSIONS_FILE" > "$tmp_file" && mv "$tmp_file" "$VERSIONS_FILE"

        log SUCCESS "Stack rolled back to $prev_commit"
        return 0
    else
        log ERROR "Failed to rollback stack"
        return 1
    fi
}
