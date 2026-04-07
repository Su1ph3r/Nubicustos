# Nubicustos

Cloud security scanners are great at generating findings. They're terrible at telling you which ones matter. You run Prowler, ScoutSuite, kube-bench, and a dozen others, and you end up with thousands of lines of output in incompatible formats, no sense of priority, and no idea which findings are actually exploitable in your environment. Nubicustos ingests all of that raw output and turns it into something you can act on.

## What it does

- Normalizes findings from Prowler, ScoutSuite, Trivy, Checkov, TruffleHog, and many other scanners into one database
- Discovers attack paths by correlating findings into exploitable chains with risk scores
- Maps every finding to compliance frameworks automatically
- Generates proof-of-concept commands (AWS CLI) so you can verify findings are real
- Analyzes IAM privilege escalation paths via PMapper and Cloudsplaining
- Tracks scan history with diff, MTTR, and trend metrics
- Scans secrets with TruffleHog (700+ detectors, active credential verification) and Gitleaks
- Provides a REST API and MCP server for LLM integration

## Supported clouds

AWS, Azure, GCP, and Kubernetes.

## Install

```bash
git clone https://github.com/Su1ph3r/Nubicustos.git
cd Nubicustos
docker compose up -d
```

Requires Docker Engine 20.10+ and Docker Compose 2.0+. Recommended 32 GB RAM.

## Quick start

```bash
# Run a fast scan (5-10 min, Prowler only)
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "quick", "aws_profile": "default"}'

# Run a full audit with all tools (30-60 min)
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "comprehensive", "aws_profile": "prod-audit"}'

# Deep-dive IAM privilege escalation analysis
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"profile": "iam-analysis", "aws_profile": "default"}'

# Compare two scans to see what changed
python3 report-processor/compare_scans.py \
  --baseline-id abc123 --current-id def456 --include-mttr
```

Other scan profiles: `compliance-only`, `secrets`, `iac`.

## Compliance

Findings are automatically mapped to CIS AWS Benchmarks (1.4–3.0), SOC 2, PCI-DSS 3.2.1, HIPAA, NIST 800-53 Rev 4 & 5, NIST 800-171, NIST CSF, FedRAMP Low & Moderate, CISA, GDPR, ISO 27001, MITRE ATT&CK, and the AWS Well-Architected Framework Security and Reliability Pillars.

## API

Full Swagger docs at `http://localhost:8000/docs`.

```bash
GET  /api/findings?severity=critical,high   # unified findings
GET  /api/attack-paths                       # attack path graph
GET  /api/compliance                         # compliance posture
GET  /api/privesc-paths                      # privilege escalation paths
GET  /api/exports/csv                        # CSV export
POST /api/scans                              # trigger a scan
GET  /api/scans/compare?baseline=X&current=Y # scan diff with MTTR
```

## Frontend

Nubicustos ships with a Vue.js 3 web interface at `http://localhost:8080`. It covers dashboards, findings, attack path visualization, compliance status, scan management, IAM analysis, and credential management.

## Configuration

```bash
# Mount AWS credentials
mkdir -p credentials/aws
cp ~/.aws/credentials credentials/aws/
cp ~/.aws/config credentials/aws/

# MCP server (for LLM integration)
NUBICUSTOS_MCP_API_URL=http://localhost:8000
```

Key ports: 8080 (frontend), 8000 (API), 5432 (PostgreSQL), 7474/7687 (Neo4j).

## Testing

```bash
# Check cloud provider permissions before scanning
python scripts/check-permissions.py
python scripts/check-permissions.py --provider aws

# Dry-run a scan without execution
./scripts/run-all-audits.sh --dry-run
```

## License

MIT
