# Nubicustos v2

The single-binary rewrite. A native cloud-posture engine — no Docker, no
external scanners, no Postgres/Neo4j — that scans cloud accounts and exports
runtime-proven findings. See [`../REFACTOR-PLAN.md`](../REFACTOR-PLAN.md) for the
full design.

> Status: **Phase 0 + 1a + Phase 1 (AWS core) complete.** Auth/MFA layer plus a
> native AWS posture engine: **32 checks across S3, IAM, EC2, VPC, RDS,
> CloudTrail, KMS, Config, GuardDuty, Secrets Manager, ELB, and ACM**,
> multi-region by default, persisted to SQLite, queryable offline, and
> exportable as Cairn / SARIF / CSV / HTML. An in-process attack-path graph
> derives scored internet-exposure, privilege-escalation, and assume-role/trust
> paths with chained PoCs, gated by a local network-reachability solver to cut
> false positives. An opt-in, read-only active-validation pass confirms findings
> with captured evidence. The TUI and the remaining Tier-1 capabilities follow per the
> plan.

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

# Attack paths: internet-exposure chains and admin-privilege concentrations,
# scored 0-100 with step-by-step, resource-specific PoCs
nubicustos paths
nubicustos paths --format json

# Active validation (opt-in, read-only): confirm findings and capture evidence
nubicustos scan --provider aws --validate   # validate inline with the scan
nubicustos validate                          # re-validate the latest stored scan
```

### Active validation (opt-in, read-only)

`--validate` (and the `validate` command) run a confirmation pass that proves a
finding is real and attaches captured evidence (the request issued, the response,
the vantage, and a `confirmed`/`unconfirmed`/`blocked` verdict) — turning a
config assertion into a runtime-proven report item that flows into the export.

This is the only part of the tool that reaches out to the scanned resources, so
it is bound by a strict safety contract:

- **Opt-in** — nothing here runs during a plain scan; it requires `--validate`
  or the `validate` command.
- **Read-only** — validators confirm the open door, never walk through it: no
  writes, modifications, deletes, or denial of service.
- **Blast radius none** — every validator declares its blast radius, and the
  runner refuses to execute any validator that does not declare `none`
  (rejected at registration — fail closed).
- **Rate-limited**, with a per-action timeout.
- Evidence records the **vantage** (`external` = no credentials, the operator's
  network; `authenticated` = scan credentials exercised as a low-privilege check).

Implemented validator: anonymous (unsigned) S3 listing for public-bucket
findings (external vantage). The framework registers validators by check id;
TCP-port banner grabs, loose-OIDC AssumeRole tests, public-snapshot describes,
and dangling-DNS checks are the next validators to slot in.

### Attack-path graph

`scan` derives an in-process attack-path graph from the collected state (no
Neo4j, no external graph tooling) and persists it alongside the findings.
`paths` renders it. Each path is scored 0-100 (exploitability × impact, with an
intrinsic severity floor for cases like root compromise) and carries a chained,
resource-specific proof of concept. Edges modelled:

- **Internet exposure** — public EC2 (with the IMDSv1 → instance-role-credential
  hop as a 2-step chain that names the instance's role when resolved), world-open
  security groups, public RDS, internet-facing plaintext load balancers, public
  S3 buckets, and publicly shared EBS/AMI/RDS snapshots.
- **Administrative privilege** — the account root holding active access keys, and
  IAM principals that are administrator-equivalent (via the managed policy or a
  custom/inline wildcard).
- **Privilege escalation** (`can-escalate`) — principals granted privesc-prone
  IAM/STS actions (e.g. `iam:PutUserPolicy`, `iam:PassRole`, `sts:AssumeRole`) on
  `Resource: "*"`.
- **Assume-role & trust** (`can-assume-role`) — intra-account assume edges, plus
  scored paths for risky trust: a wildcard (`Principal: "*"`) trust, an external
  AWS account, or an OIDC provider without a subject (`sub`/`aud`) condition.

Internet-exposure paths are gated by a local **reachability solver** (§9.5):
a public resource in a subnet with no internet-gateway route, or with no
security group admitting inbound traffic, is annotated `not-reachable` and
**downgraded** (not dropped) rather than presented as live exposure.

### IAM trust & privilege findings

The trust analyzer (§9.3) also emits standalone findings, surfaced through
`findings`/`export`: `aws_iam_role_trust_wildcard_principal` (critical),
`aws_iam_role_trust_external_account`, `aws_iam_oidc_trust_no_subject_condition`,
`aws_iam_admin_via_policy`, and `aws_iam_privilege_escalation`.

## Layout

| Package | Role |
|---------|------|
| `cmd/nubicustos` | cobra CLI entrypoint |
| `internal/auth` | up-front credential resolution + MFA (all AWS & Azure paths) — plan §8 |
| `internal/engine` | registry + concurrent collect→check scanner + graph build |
| `internal/state` | normalized collected cloud state |
| `internal/providers/aws` | AWS collectors (read-only API gatherers) |
| `internal/checks/aws` | native AWS posture checks |
| `internal/trust` | IAM trust & privilege analysis (assume/federation/privesc) — plan §9.3 |
| `internal/reachability` | network reachability solver for FP reduction — plan §9.5 |
| `internal/graph` | in-process attack-path graph (nodes, edges, scored paths) — plan §3.2 |
| `internal/validate` | opt-in read-only active validation + evidence capture — plan §9.1 |
| `internal/findings` | normalized domain model |
| `internal/store` | embedded SQLite persistence |
| `internal/export` | Cairn / report serializers |

## Test

```bash
go test ./...
```
