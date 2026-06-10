# Nubicustos v2

The single-binary rewrite. A native cloud-posture engine — no Docker, no
external scanners, no Postgres/Neo4j — that scans cloud accounts and exports
runtime-proven findings. See [`../REFACTOR-PLAN.md`](../REFACTOR-PLAN.md) for the
full design.

> Status: **Phase 0 + 1a + Phase 1 (AWS core) complete.** Auth/MFA layer plus a
> native AWS posture engine: **32 checks across S3, IAM, EC2, VPC, RDS,
> CloudTrail, KMS, Config, GuardDuty, Secrets Manager, ELB, and ACM**,
> multi-region by default, persisted to SQLite, queryable offline, and
> exportable as Cairn / SARIF / CSV / HTML. The attack-path graph, the TUI, and
> the Tier-1 capabilities follow per the plan.

### Finding shapes

Two shapes, chosen per check:

- **Per-resource** — one finding per misconfigured resource (bucket, instance, DB, user, key, trail). Independently trackable across scans.
- **Aggregate** — one finding with an `affected` list, for control-level posture (e.g. "Config not recording in N of M regions", "these security groups expose sensitive ports", "these snapshots are public"). The `affected` array carries each region/rule/ARN.

### Check catalog (Phase 1)

| Service | Checks |
|---------|--------|
| S3 | public access (ACL/policy) |
| IAM | root MFA, root access keys, weak password policy, access-key rotation, console user without MFA, directly-attached AdministratorAccess |
| EC2 | open ingress on sensitive ports*, IMDSv2 not enforced, public IP, unencrypted EBS volume, EBS default encryption disabled* |
| VPC | flow logs disabled* |
| RDS | publicly accessible, unencrypted storage, backups disabled, deletion protection disabled, public snapshot* |
| CloudTrail | no logging multi-region trail, log-file validation disabled, not KMS-encrypted |
| KMS | customer-managed key rotation disabled |
| Config | not recording all resources* |
| GuardDuty | not enabled* |
| Exposure | public EBS snapshot*, public AMI* |
| Secrets Manager | rotation disabled* |
| ELB | internet-facing HTTP listener, weak TLS policy, access logs disabled |
| ACM | certificate expired, certificate expiring (<30d) |

`*` = aggregate finding (single finding with an `affected` list).

## Build

```bash
cd v2
go build -o nubicustos ./cmd/nubicustos
```

## Use

```bash
# AWS — default credential chain
nubicustos scan --provider aws

# AWS — SSO profile (opens a browser if the session is expired)
nubicustos scan --provider aws --profile prod-sso --sso-login

# AWS — AssumeRole + MFA (prompts for a TOTP once, then scans)
nubicustos scan --provider aws --profile cross-account

# AWS — static keys + MFA-condition policy (uses sts:GetSessionToken)
nubicustos scan --provider aws --profile dev --mfa-serial arn:aws:iam::123:mfa/me
#   ... non-interactive: add --mfa-token 123456

# Azure — reuse `az login`, or pick a flow
nubicustos scan --provider azure
nubicustos scan --provider azure --auth device-code

# Export Cairn-format findings JSON inline with the scan
nubicustos scan --provider aws --export findings.cairn.json
```

Results persist to `nubicustos.db` (SQLite) by default; override with `--db`.

### Query & export stored scans (no rescan)

`scan` writes to the database; `findings`, `export`, and `paths` read back from
it. They default to the most recent scan (`--scan latest`) and accept
`--severity` / `--service` filters.

```bash
# List findings from the latest scan (most-severe first)
nubicustos findings

# Filter and switch to JSON
nubicustos findings --severity critical,high --service iam,s3 --format json

# Re-serialize a stored scan into any format, to stdout or a file
nubicustos export cairn                       # normalized JSON for the Cairn pipeline
nubicustos export sarif --out report.sarif    # SARIF 2.1.0 for code-scanning dashboards
nubicustos export csv   --out findings.csv    # flat spreadsheet rows
nubicustos export html  --out report.html     # self-contained shareable report

# Attack paths (graph engine lands in Phase 2)
nubicustos paths
```

## Layout

| Package | Role |
|---------|------|
| `cmd/nubicustos` | cobra CLI entrypoint |
| `internal/auth` | up-front credential resolution + MFA (all AWS & Azure paths) — plan §8 |
| `internal/engine` | registry + concurrent collect→check scanner |
| `internal/state` | normalized collected cloud state |
| `internal/providers/aws` | AWS collectors (read-only API gatherers) |
| `internal/checks/aws` | native AWS posture checks |
| `internal/findings` | normalized domain model |
| `internal/store` | embedded SQLite persistence |
| `internal/export` | Cairn / report serializers |

## Test

```bash
go test ./...
```
