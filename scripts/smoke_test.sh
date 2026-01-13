#!/bin/bash
# Smoke test script to verify scan pipeline works end-to-end
# Run this after any changes to API, report processor, or docker-compose.yml

set -e

API_URL="${API_URL:-http://localhost:8000}"
AWS_PROFILE="${AWS_PROFILE:-nubicustos-audit}"

echo "=== Nubicustos Smoke Test ==="
echo "API URL: $API_URL"
echo ""

# 1. Check API health
echo "[1/5] Checking API health..."
health=$(curl -sf "$API_URL/api/health" | python -c "import json,sys; print(json.load(sys.stdin)['status'])")
if [ "$health" != "healthy" ]; then
    echo "FAIL: API is not healthy (status: $health)"
    exit 1
fi
echo "PASS: API is healthy"

# 2. Run integration tests inside API container
echo ""
echo "[2/5] Running integration tests in API container..."
if docker exec security-api pytest /app/tests/test_report_processing.py -v --tb=short 2>/dev/null; then
    echo "PASS: Integration tests passed"
else
    echo "FAIL: Integration tests failed"
    exit 1
fi

# 3. Start a quick scan
echo ""
echo "[3/5] Starting quick scan..."
scan_response=$(curl -sf -X POST "$API_URL/api/scans" \
    -H "Content-Type: application/json" \
    -d "{\"profile\": \"quick\", \"aws_profile\": \"$AWS_PROFILE\"}")

scan_id=$(echo "$scan_response" | python -c "import json,sys; print(json.load(sys.stdin)['scan_id'])")
scan_type=$(echo "$scan_response" | python -c "import json,sys; print(json.load(sys.stdin)['scan_type'])")

if [ "$scan_type" != "quick" ]; then
    echo "FAIL: Expected scan_type 'quick', got '$scan_type'"
    exit 1
fi
echo "PASS: Scan started (ID: $scan_id, Type: $scan_type)"

# 4. Wait for scan completion (max 10 minutes)
echo ""
echo "[4/5] Waiting for scan completion (max 10 min)..."
max_wait=600
waited=0
while [ $waited -lt $max_wait ]; do
    status=$(curl -sf "$API_URL/api/scans/$scan_id" | python -c "import json,sys; print(json.load(sys.stdin)['status'])")

    if [ "$status" = "completed" ]; then
        echo "PASS: Scan completed"
        break
    elif [ "$status" = "failed" ]; then
        echo "FAIL: Scan failed"
        exit 1
    fi

    sleep 15
    waited=$((waited + 15))
    echo "  Status: $status (waited ${waited}s)"
done

if [ $waited -ge $max_wait ]; then
    echo "FAIL: Scan timed out after ${max_wait}s"
    exit 1
fi

# 5. Verify findings were populated
echo ""
echo "[5/5] Verifying findings were populated..."
scan_result=$(curl -sf "$API_URL/api/scans/$scan_id")
total_findings=$(echo "$scan_result" | python -c "import json,sys; print(json.load(sys.stdin)['total_findings'])")

if [ "$total_findings" -eq 0 ]; then
    echo "FAIL: No findings recorded (report processing may have failed)"
    exit 1
fi

# Also check findings API
findings_total=$(curl -sf "$API_URL/api/findings?page_size=1" | python -c "import json,sys; print(json.load(sys.stdin).get('total', 0))")
if [ "$findings_total" -eq 0 ]; then
    echo "FAIL: Findings not visible in findings API"
    exit 1
fi

echo "PASS: $total_findings findings recorded, $findings_total total in database"

echo ""
echo "=== All smoke tests passed ==="
