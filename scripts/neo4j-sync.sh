#!/bin/bash
#
# Neo4j Synchronization Script
# =============================
#
# This script manages synchronization between PostgreSQL and Neo4j databases.
# Cartography populates Neo4j with cloud asset data, and this script ensures
# PostgreSQL stays in sync with Neo4j.
#
# Usage:
#   ./scripts/neo4j-sync.sh [command] [options]
#
# Commands:
#   status      - Show sync status between databases
#   sync        - Trigger full bidirectional sync
#   pull        - Pull assets from Neo4j to PostgreSQL only
#   push        - Push finding counts to Neo4j only
#   health      - Check sync health with recommendations
#   discrepancies - Show detailed discrepancy report
#
# Options:
#   --mark-stale    - Mark assets not in Neo4j as inactive (with sync/pull)
#   --background    - Run sync in background (with sync/pull/push)
#   --json          - Output in JSON format
#   --quiet         - Suppress non-essential output
#
# Examples:
#   ./scripts/neo4j-sync.sh status
#   ./scripts/neo4j-sync.sh sync --mark-stale
#   ./scripts/neo4j-sync.sh health --json
#

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
API_URL="${API_URL:-http://localhost:8000}"
API_KEY="${API_KEY:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
MARK_STALE=false
BACKGROUND=false
JSON_OUTPUT=false
QUIET=false

# Parse command line arguments
COMMAND="${1:-status}"
shift || true

while [[ $# -gt 0 ]]; do
    case $1 in
        --mark-stale)
            MARK_STALE=true
            shift
            ;;
        --background)
            BACKGROUND=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --quiet|-q)
            QUIET=true
            shift
            ;;
        --api-url)
            API_URL="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Build curl options
build_curl_opts() {
    local opts="-s"
    if [[ -n "$API_KEY" ]]; then
        opts="$opts -H 'X-API-Key: $API_KEY'"
    fi
    echo "$opts"
}

# Make API request
api_request() {
    local method="$1"
    local endpoint="$2"
    local data="${3:-}"
    local opts=$(build_curl_opts)

    local url="${API_URL}/api${endpoint}"

    if [[ "$method" == "GET" ]]; then
        eval "curl $opts '$url'"
    else
        eval "curl $opts -X $method -H 'Content-Type: application/json' -d '$data' '$url'"
    fi
}

# Print status with color
print_status() {
    local status="$1"
    local message="$2"

    case "$status" in
        success|healthy|connected)
            echo -e "${GREEN}[OK]${NC} $message"
            ;;
        warning|degraded)
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        error|unhealthy|disconnected)
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        info)
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
}

# Show sync status
cmd_status() {
    if [[ "$QUIET" != "true" ]]; then
        echo "=============================================="
        echo "Neo4j Synchronization Status"
        echo "=============================================="
    fi

    local response=$(api_request GET "/sync/status")

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
        return
    fi

    # Parse response with Python for reliable JSON handling
    python3 << EOF
import json
import sys

try:
    data = json.loads('''$response''')

    # Connection status
    neo4j_status = "connected" if data.get("neo4j_connected") else "disconnected"
    pg_status = "connected" if data.get("postgres_connected") else "disconnected"

    print(f"Neo4j:      {neo4j_status}")
    print(f"PostgreSQL: {pg_status}")
    print()
    print(f"Neo4j Assets:      {data.get('neo4j_asset_count', 0):,}")
    print(f"PostgreSQL Assets: {data.get('postgres_asset_count', 0):,}")
    print(f"Count Mismatch:    {data.get('count_mismatch', 0):,}")
    print()
    print(f"Missing in PostgreSQL: {data.get('missing_in_postgres', 0):,}")
    print(f"Missing in Neo4j:      {data.get('missing_in_neo4j', 0):,}")
    print()

    in_sync = data.get("in_sync", False)
    if in_sync:
        print("Status: IN SYNC")
    else:
        print("Status: OUT OF SYNC")

except json.JSONDecodeError:
    print("Error: Could not parse API response")
    print("$response")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
}

# Show sync health
cmd_health() {
    if [[ "$QUIET" != "true" ]]; then
        echo "=============================================="
        echo "Neo4j Sync Health Check"
        echo "=============================================="
    fi

    local response=$(api_request GET "/sync/health")

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
        return
    fi

    python3 << EOF
import json
import sys

try:
    data = json.loads('''$response''')

    status = data.get("status", "unknown")
    print(f"Overall Status: {status.upper()}")
    print(f"Neo4j:          {data.get('neo4j_status', 'unknown')}")
    print(f"PostgreSQL:     {data.get('postgres_status', 'unknown')}")
    print(f"Sync Lag:       ~{data.get('sync_lag', 0)} minutes")
    print()

    issues = data.get("issues", [])
    if issues:
        print("Issues Detected:")
        for issue in issues:
            print(f"  - {issue}")
        print()

    recommendations = data.get("recommendations", [])
    if recommendations:
        print("Recommendations:")
        for rec in recommendations:
            print(f"  - {rec}")

except json.JSONDecodeError:
    print("Error: Could not parse API response")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
}

# Trigger sync
cmd_sync() {
    local direction="${1:-bidirectional}"

    if [[ "$QUIET" != "true" ]]; then
        echo "=============================================="
        echo "Triggering Neo4j Sync"
        echo "=============================================="
        echo "Direction: $direction"
        echo "Mark Stale: $MARK_STALE"
        echo ""
    fi

    local data="{\"direction\": \"$direction\", \"mark_stale\": $MARK_STALE}"
    local endpoint="/sync/trigger"

    if [[ "$BACKGROUND" == "true" ]]; then
        endpoint="/sync/trigger/background"
    fi

    local response=$(api_request POST "$endpoint" "$data")

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
        return
    fi

    python3 << EOF
import json
import sys

try:
    data = json.loads('''$response''')

    if "status" in data and data["status"] == "accepted":
        # Background sync response
        print("Sync started in background")
        print(f"Check status at: {data.get('check_status', '/api/sync/status')}")
    else:
        # Sync result response
        success = data.get("success", False)
        print(f"Success: {success}")
        print(f"Assets Synced: {data.get('assets_synced', 0)}")
        print(f"Findings Propagated: {data.get('findings_propagated', 0)}")
        print(f"Duration: {data.get('duration_ms', 0)} ms")

        errors = data.get("errors", [])
        if errors:
            print()
            print("Errors:")
            for err in errors:
                print(f"  - {err}")

        warnings = data.get("warnings", [])
        if warnings:
            print()
            print("Warnings:")
            for warn in warnings[:5]:  # Limit to first 5
                print(f"  - {warn}")
            if len(warnings) > 5:
                print(f"  ... and {len(warnings) - 5} more")

except json.JSONDecodeError:
    print("Error: Could not parse API response")
    print("$response")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
}

# Pull from Neo4j
cmd_pull() {
    cmd_sync "neo4j_to_pg"
}

# Push to Neo4j
cmd_push() {
    if [[ "$QUIET" != "true" ]]; then
        echo "=============================================="
        echo "Propagating Findings to Neo4j"
        echo "=============================================="
    fi

    local response=$(api_request POST "/sync/propagate-findings" "{}")

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
        return
    fi

    python3 << EOF
import json
import sys

try:
    data = json.loads('''$response''')

    success = data.get("success", False)
    print(f"Success: {success}")
    print(f"Findings Propagated: {data.get('findings_propagated', 0)}")
    print(f"Duration: {data.get('duration_ms', 0)} ms")

    errors = data.get("errors", [])
    if errors:
        print()
        print("Errors:")
        for err in errors:
            print(f"  - {err}")

except json.JSONDecodeError:
    print("Error: Could not parse API response")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
}

# Show discrepancies
cmd_discrepancies() {
    if [[ "$QUIET" != "true" ]]; then
        echo "=============================================="
        echo "Sync Discrepancies Report"
        echo "=============================================="
    fi

    local response=$(api_request GET "/sync/discrepancies")

    if [[ "$JSON_OUTPUT" == "true" ]]; then
        echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response"
        return
    fi

    python3 << EOF
import json
import sys

try:
    data = json.loads('''$response''')

    total = data.get("total_discrepancies", 0)
    print(f"Total Discrepancies: {total}")
    print()

    by_type = data.get("by_type", {})
    if by_type:
        print("By Asset Type:")
        for asset_type, count in sorted(by_type.items(), key=lambda x: -x[1]):
            print(f"  {asset_type}: {count}")
        print()

    missing_pg = data.get("missing_in_postgres", [])
    if missing_pg:
        print(f"Missing in PostgreSQL ({len(missing_pg)} shown):")
        for asset_id in missing_pg[:10]:
            print(f"  - {asset_id}")
        if len(missing_pg) > 10:
            print(f"  ... and {len(missing_pg) - 10} more")
        print()

    missing_neo4j = data.get("missing_in_neo4j", [])
    if missing_neo4j:
        print(f"Missing in Neo4j ({len(missing_neo4j)} shown):")
        for asset_id in missing_neo4j[:10]:
            print(f"  - {asset_id}")
        if len(missing_neo4j) > 10:
            print(f"  ... and {len(missing_neo4j) - 10} more")

except json.JSONDecodeError:
    print("Error: Could not parse API response")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    sys.exit(1)
EOF
}

# Show help
cmd_help() {
    echo "Neo4j Synchronization Script"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  status         Show sync status between databases"
    echo "  sync           Trigger full bidirectional sync"
    echo "  pull           Pull assets from Neo4j to PostgreSQL"
    echo "  push           Push finding counts to Neo4j"
    echo "  health         Check sync health with recommendations"
    echo "  discrepancies  Show detailed discrepancy report"
    echo "  help           Show this help message"
    echo ""
    echo "Options:"
    echo "  --mark-stale   Mark assets not in Neo4j as inactive (sync/pull)"
    echo "  --background   Run sync in background (sync/pull/push)"
    echo "  --json         Output in JSON format"
    echo "  --quiet, -q    Suppress non-essential output"
    echo "  --api-url URL  Override API URL (default: http://localhost:8000)"
    echo "  --api-key KEY  Set API key for authentication"
    echo ""
    echo "Examples:"
    echo "  $0 status"
    echo "  $0 sync --mark-stale"
    echo "  $0 health --json"
    echo "  $0 pull --background"
}

# Main command dispatcher
case "$COMMAND" in
    status)
        cmd_status
        ;;
    health)
        cmd_health
        ;;
    sync)
        cmd_sync "bidirectional"
        ;;
    pull)
        cmd_pull
        ;;
    push)
        cmd_push
        ;;
    discrepancies|disc)
        cmd_discrepancies
        ;;
    help|--help|-h)
        cmd_help
        ;;
    *)
        echo -e "${RED}Unknown command: $COMMAND${NC}"
        echo ""
        cmd_help
        exit 1
        ;;
esac
