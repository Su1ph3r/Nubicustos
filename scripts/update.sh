#!/bin/bash
# ============================================================================
# Argus - Update Manager
# ============================================================================
# Updates external tools, custom images, and the stack itself

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Source helper library
source "$SCRIPT_DIR/update-lib.sh"

# CLI Options (defaults)
DRY_RUN=false
NO_HEALTH_CHECK=false
FORCE=false
CATEGORY=""
COMMAND=""
TOOLS=()

# ============================================================================
# Help
# ============================================================================

show_help() {
    cat << EOF
Argus - Update Manager

Usage: $(basename "$0") [COMMAND] [OPTIONS] [TOOLS...]

COMMANDS:
  all                   Update everything (pull + build + self)
  pull                  Pull latest images for external tools
  build                 Rebuild custom images (api, cloudmapper)
  self                  Update stack from git repository
  versions              Show current versions of all tools
  rollback [TOOL]       Rollback tool to previous version (or 'stack' for git)

OPTIONS:
  --category CATEGORY   Filter by category: aws, kubernetes, iac, infrastructure
  --dry-run             Show what would be updated without executing
  --no-health-check     Skip post-update health validation
  --force               Force update even if up-to-date
  -h, --help            Show this help message

EXAMPLES:
  $(basename "$0") all                         # Update everything
  $(basename "$0") pull                        # Pull all external images
  $(basename "$0") pull prowler trivy          # Update specific tools
  $(basename "$0") pull --category kubernetes  # Update all K8s tools
  $(basename "$0") versions                    # Show installed versions
  $(basename "$0") rollback prowler            # Revert prowler to previous version
  $(basename "$0") rollback stack              # Revert git to previous commit
  $(basename "$0") self                        # Update from git

CATEGORIES:
  aws           Prowler, ScoutSuite, Pacu, CloudSploit, Cloud Custodian, etc.
  kubernetes    kube-bench, Kubescape, Trivy, Grype, Popeye, etc.
  iac           Checkov, Terrascan, tfsec
  infrastructure PostgreSQL, Neo4j, Nginx, Grafana

EOF
}

# ============================================================================
# Argument Parsing
# ============================================================================

parse_args() {
    if [ $# -eq 0 ]; then
        show_help
        exit 0
    fi

    # First argument should be the command
    case "$1" in
        all|pull|build|self|versions|rollback)
            COMMAND="$1"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log ERROR "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac

    # Parse remaining arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --no-health-check)
                NO_HEALTH_CHECK=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --category)
                CATEGORY="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            -*)
                log WARN "Unknown option: $1"
                shift
                ;;
            *)
                # Remaining args are tool names
                TOOLS+=("$1")
                shift
                ;;
        esac
    done
}

# ============================================================================
# Commands
# ============================================================================

# Pull external Docker images
cmd_pull() {
    log INFO "========================================"
    log INFO "Pulling External Tool Images"
    log INFO "========================================"

    local tools_to_update=()
    local failed_tools=()
    local updated_count=0

    # Determine which tools to update
    if [ ${#TOOLS[@]} -gt 0 ]; then
        # Specific tools provided
        for tool in "${TOOLS[@]}"; do
            if is_valid_tool "$tool"; then
                if is_custom_build "$tool"; then
                    log WARN "$tool is a custom build - use 'build' command instead"
                else
                    tools_to_update+=("$tool")
                fi
            else
                log ERROR "Unknown tool: $tool"
            fi
        done
    elif [ -n "$CATEGORY" ]; then
        # Category filter
        local category_tools
        category_tools=$(get_tools_in_category "$CATEGORY")
        if [ $? -eq 0 ]; then
            for tool in $category_tools; do
                if ! is_custom_build "$tool"; then
                    tools_to_update+=("$tool")
                fi
            done
        fi
    else
        # All external tools
        for tool in $ALL_EXTERNAL_TOOLS; do
            tools_to_update+=("$tool")
        done
    fi

    if [ ${#tools_to_update[@]} -eq 0 ]; then
        log WARN "No tools to update"
        return 0
    fi

    log INFO "Tools to update: ${tools_to_update[*]}"
    echo ""

    # Pull each tool
    for tool in "${tools_to_update[@]}"; do
        if pull_image "$tool" "$DRY_RUN"; then
            updated_count=$((updated_count + 1))

            # Run health check unless disabled
            if [ "$NO_HEALTH_CHECK" = "false" ] && [ "$DRY_RUN" = "false" ]; then
                if ! health_check_tool "$tool"; then
                    failed_tools+=("$tool")
                fi
            fi
        else
            failed_tools+=("$tool")
        fi
        echo ""
    done

    # Summary
    log INFO "========================================"
    log INFO "Update Summary"
    log INFO "========================================"
    log INFO "Tools processed: ${#tools_to_update[@]}"
    log INFO "Successfully updated: $updated_count"

    if [ ${#failed_tools[@]} -gt 0 ]; then
        log ERROR "Failed tools: ${failed_tools[*]}"
        return 1
    fi

    return 0
}

# Rebuild custom Docker images
cmd_build() {
    log INFO "========================================"
    log INFO "Rebuilding Custom Images"
    log INFO "========================================"

    local builds=()

    # Determine which to build
    if [ ${#TOOLS[@]} -gt 0 ]; then
        for tool in "${TOOLS[@]}"; do
            if is_custom_build "$tool"; then
                builds+=("$tool")
            else
                log WARN "$tool is not a custom build"
            fi
        done
    else
        for tool in $CATEGORY_CUSTOM; do
            builds+=("$tool")
        done
    fi

    if [ ${#builds[@]} -eq 0 ]; then
        log WARN "No custom builds to update"
        return 0
    fi

    log INFO "Custom builds: ${builds[*]}"
    echo ""

    cd "$PROJECT_DIR" || return 1

    for build in "${builds[@]}"; do
        if [ "$DRY_RUN" = "true" ]; then
            log INFO "[DRY-RUN] Would rebuild: $build"
        else
            log INFO "Rebuilding $build..."
            local build_args=""
            if [ "$FORCE" = "true" ]; then
                build_args="--no-cache"
            fi

            if docker-compose build $build_args "$build"; then
                log SUCCESS "Rebuilt $build"
            else
                log ERROR "Failed to rebuild $build"
                return 1
            fi
        fi
        echo ""
    done

    return 0
}

# Update stack from git
cmd_self() {
    log INFO "========================================"
    log INFO "Updating Stack from Git"
    log INFO "========================================"

    cd "$PROJECT_DIR" || return 1

    # Check for uncommitted changes
    if ! git diff-index --quiet HEAD -- 2>/dev/null; then
        log WARN "You have uncommitted changes"
        if [ "$FORCE" != "true" ]; then
            log ERROR "Use --force to update anyway, or commit/stash your changes"
            return 1
        fi
    fi

    # Get current commit before update
    local current_commit
    current_commit=$(git rev-parse HEAD 2>/dev/null)

    if [ "$DRY_RUN" = "true" ]; then
        log INFO "[DRY-RUN] Would run: git pull"
        log INFO "[DRY-RUN] Would rebuild custom images"
        return 0
    fi

    # Pull latest
    log INFO "Pulling latest from git..."
    if git pull; then
        local new_commit
        new_commit=$(git rev-parse HEAD)

        if [ "$current_commit" != "$new_commit" ]; then
            log SUCCESS "Updated from $current_commit to $new_commit"
            update_stack_info "$new_commit"

            # Rebuild custom images
            log INFO "Rebuilding custom images..."
            cmd_build
        else
            log INFO "Stack is already up to date"
            update_stack_info "$new_commit"
        fi

        return 0
    else
        log ERROR "Git pull failed"
        return 1
    fi
}

# Show versions of all tools
cmd_versions() {
    echo ""
    echo -e "${CYAN}Argus - Installed Versions${NC}"
    echo "================================================"
    echo ""

    init_versions_file

    # Show stack info
    echo -e "${BLUE}STACK${NC}"
    echo "-----"
    local stack_commit
    stack_commit=$(git -C "$PROJECT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    local stack_branch
    stack_branch=$(git -C "$PROJECT_DIR" branch --show-current 2>/dev/null || echo "unknown")
    local last_update
    last_update=$(read_version_value ".stack.last_update")
    echo "  Git commit: $stack_commit"
    echo "  Branch: $stack_branch"
    if [ -n "$last_update" ] && [ "$last_update" != "null" ]; then
        echo "  Last update: $last_update"
    fi
    echo ""

    # Show by category
    show_category_versions "AWS SECURITY TOOLS" "$CATEGORY_AWS"
    show_category_versions "KUBERNETES SECURITY TOOLS" "$CATEGORY_KUBERNETES"
    show_category_versions "IAC SCANNERS" "$CATEGORY_IAC"
    show_category_versions "INFRASTRUCTURE" "$CATEGORY_INFRASTRUCTURE"

    # Custom builds
    echo -e "${BLUE}CUSTOM BUILDS${NC}"
    echo "-------------"
    for tool in $CATEGORY_CUSTOM; do
        local build_dir="$PROJECT_DIR/$tool"
        if [ -d "$build_dir" ]; then
            echo "  $tool (local build)"
        fi
    done
    echo ""
}

# Helper to show versions for a category
show_category_versions() {
    local title="$1"
    local tools="$2"

    echo -e "${BLUE}$title${NC}"
    echo "$(echo "$title" | sed 's/./-/g')"

    for tool in $tools; do
        local image="${TOOL_IMAGES[$tool]:-}"
        if [ -z "$image" ]; then
            continue  # Skip tools without image mappings (custom builds)
        fi
        local version
        local digest
        local last_pull

        # Try to get info from versions.json first
        version=$(read_version_value ".tools[\"$tool\"].version")
        digest=$(read_version_value ".tools[\"$tool\"].current_digest")
        last_pull=$(read_version_value ".tools[\"$tool\"].last_pull")

        # If not in versions.json, try to get from Docker
        if [ -z "$version" ] || [ "$version" = "null" ]; then
            if docker image inspect "$image" &>/dev/null; then
                version=$(get_image_version "$tool")
                digest=$(get_image_digest "$image")
            else
                version="not pulled"
                digest=""
            fi
        fi

        # Format output
        local short_digest=""
        if [ -n "$digest" ] && [ "$digest" != "null" ]; then
            short_digest="${digest:0:12}..."
        fi

        printf "  %-20s %-10s %s\n" "$tool" "$version" "$short_digest"
    done
    echo ""
}

# Rollback a tool or the stack
cmd_rollback() {
    log INFO "========================================"
    log INFO "Rollback"
    log INFO "========================================"

    if [ ${#TOOLS[@]} -eq 0 ]; then
        log ERROR "Please specify a tool to rollback (or 'stack' for git rollback)"
        return 1
    fi

    local target="${TOOLS[0]}"

    if [ "$target" = "stack" ]; then
        # Rollback git
        if [ "$DRY_RUN" = "false" ]; then
            echo -e "${YELLOW}WARNING: This will reset your local repository to the previous commit.${NC}"
            echo -e "${YELLOW}Any uncommitted changes will be lost!${NC}"
            read -p "Are you sure? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log INFO "Rollback cancelled"
                return 0
            fi
        fi
        rollback_stack "$DRY_RUN"
    elif is_valid_tool "$target"; then
        # Rollback tool
        if [ "$DRY_RUN" = "false" ]; then
            echo -e "${YELLOW}This will revert $target to its previous version.${NC}"
            read -p "Are you sure? (y/N) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log INFO "Rollback cancelled"
                return 0
            fi
        fi
        rollback_tool "$target" "$DRY_RUN"
    else
        log ERROR "Unknown target: $target"
        return 1
    fi
}

# Update everything
cmd_all() {
    log INFO "========================================"
    log INFO "Full Stack Update"
    log INFO "========================================"

    # Update from git first
    cmd_self || true
    echo ""

    # Pull all external images
    cmd_pull || true
    echo ""

    # Rebuild custom images
    cmd_build || true
    echo ""

    log INFO "========================================"
    log INFO "Full Update Complete"
    log INFO "========================================"
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    parse_args "$@"

    # Show mode
    if [ "$DRY_RUN" = "true" ]; then
        log WARN "DRY RUN MODE - No changes will be made"
    fi

    # Initialize versions file
    init_versions_file

    # Execute command
    case "$COMMAND" in
        all)
            cmd_all
            ;;
        pull)
            cmd_pull
            ;;
        build)
            cmd_build
            ;;
        self)
            cmd_self
            ;;
        versions)
            cmd_versions
            ;;
        rollback)
            cmd_rollback
            ;;
        *)
            log ERROR "Unknown command: $COMMAND"
            exit 1
            ;;
    esac
}

# Run main
main "$@"
