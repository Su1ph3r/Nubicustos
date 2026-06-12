# Nubicustos v2

The single-binary rewrite. A native cloud-posture engine — no Docker, no
external scanners, no Postgres/Neo4j — that scans cloud accounts and exports
runtime-proven findings. See [`../REFACTOR-PLAN.md`](../REFACTOR-PLAN.md) for the
full design.

> Status: **native multi-cloud posture engine.** Up-front auth/MFA across AWS
> (SSO/AssumeRole+MFA/GetSessionToken/default chain), Azure (CLI/browser/device-
> code/SP/MI), GCP (ADC), and Kubernetes (kubeconfig contexts). Native checks for
> AWS (S3/IAM/EC2/VPC/RDS/CloudTrail/KMS/Config/GuardDuty/Secrets Manager/ELB/ACM),
> Azure (storage/NSG/key vault), GCP (storage/firewall/IAM), and Kubernetes
> (pod-security/RBAC), persisted to SQLite, queryable offline, and exportable as
> Cairn / SARIF / CSV / HTML. An in-process attack-path graph derives scored
> internet-exposure, privilege-escalation, and assume-role/trust paths with
> chained PoCs, gated by a local network-reachability solver. An opt-in,
> read-only active-validation pass confirms findings with evidence; a terminal UI
> browses a scan; optional plugins integrate trivy/grype/checkov/terrascan/
> kube-bench when present; a CEL/YAML policy-as-code engine evaluates built-in and
> user rules at runtime; and a read-only MCP server exposes results to an LLM.
> Distributed as a single static cross-platform binary. The optional embedded web
> UI is the remaining planned item.

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

### Check catalog (Azure)

Native Azure checks run across the subscriptions discovered from the credential
(or `--subscription <id>`):

| Service | Checks |
|---------|--------|
| Storage | anonymous blob public access, HTTPS-only not enforced, network rules default to Allow |
| Network | NSG exposes sensitive ports to the internet (inbound Allow from `*`/`Internet`/`0.0.0.0/0`) |
| Key Vault | soft-delete disabled, purge protection disabled, network rules default to Allow |

```bash
# Azure — scan all enabled subscriptions (or pick one with --subscription)
nubicustos scan --provider azure
nubicustos scan --provider azure --subscription 00000000-0000-0000-0000-000000000000
```

### Check catalog (GCP)

Native GCP checks run across the projects discovered from Application Default
Credentials (or `--project <id>`):

| Service | Checks |
|---------|--------|
| Cloud Storage | public IAM (allUsers/allAuthenticatedUsers), uniform bucket-level access disabled, public access prevention not enforced |
| Compute | firewall ingress exposes sensitive ports to `0.0.0.0/0` |
| IAM | project binding grants a role to all users, broad primitive role (owner/editor) in use |

```bash
# GCP — scan all active projects (uses ADC; or pick one with --project)
nubicustos scan --provider gcp
nubicustos scan --provider gcp --project my-project-id
```

### Check catalog (Kubernetes)

Native Kubernetes checks run across the kubeconfig contexts requested with
`--context` (default: the current context):

| Area | Checks |
|------|--------|
| Workload | privileged container, shares a host namespace (hostNetwork/PID/IPC), privilege escalation not disabled, may run as root |
| RBAC | cluster-admin bound to a broad subject (anonymous / all-authenticated / all-service-accounts), role grants verb `*` on resource `*` |

```bash
# Kubernetes — scan the current context (or named contexts)
nubicustos scan --provider k8s
nubicustos scan --provider k8s --context prod-cluster --context staging
```

`*` = aggregate finding (single finding with an `affected` list).

## Build

```bash
cd v2
go build -o nubicustos ./cmd/nubicustos
```

The build is CGO-free (the SQLite driver is pure Go), so it cross-compiles to
any `GOOS`/`GOARCH` with no toolchain setup. The version is injected at release
time: `go build -ldflags "-X main.version=v2.0.0" ./cmd/nubicustos`.

## Distribution

Releases are cut with goreleaser (`.goreleaser.yaml`) on a `v2.*` tag via the
`release-v2` workflow: static binaries for **linux / macOS / windows × amd64 /
arm64**, plus SHA-256 checksums and an SBOM per archive.

Distribution to customers is via the sanctioned internal channels — **Azure
Artifacts** and **per-customer-deployment-hosted install** — not public package
managers; goreleaser is configured with no Homebrew/Scoop/apt/yum publishers.

Docker is an **optional thin wrapper** around the single binary (`Dockerfile`,
distroless static base), not the primary run model:

```bash
docker build -t nubicustos --build-arg VERSION=v2.0.0 .
docker run --rm -v ~/.aws:/home/nonroot/.aws nubicustos scan --provider aws
```

> **Cutover:** this single binary replaces the v1 Docker + PostgreSQL + Neo4j
> compose stack. Archiving/retiring that v1 stack (the repository root) is the
> final cutover step and is handled at the repository level once v2 reaches
> parity in production — it is intentionally not part of this branch.

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

# Terminal UI: browse a stored scan (dashboard, findings+detail, attack paths)
nubicustos tui
nubicustos tui --scan <id>
```

### MCP server (LLM integration)

`mcp` runs a Model Context Protocol server over stdio, exposing **read-only**
tools so an LLM can explore stored results: `list_scans`, `scan_summary`,
`list_findings` (severity/service filters), `get_finding`, and
`list_attack_paths`. It performs no cloud calls and never triggers a scan — it
reads the local results database — so connecting an MCP client cannot launch a
cloud scan with live credentials.

```bash
nubicustos mcp                 # serve over stdio (point your MCP client at this)
nubicustos mcp --db prod.db
```

### Policy-as-code rules

Posture checks can be authored declaratively as CEL/YAML rules and evaluated
during a scan — built-in rules plus any user rules from `--rules-dir`, loaded at
runtime so a finding can be encoded without recompiling. A rule declares a
`resource_type` and a CEL `expression` over that type's documented attributes:

```yaml
- id: rule_aws_s3_public_acl_or_policy
  title: S3 bucket is publicly accessible
  severity: high
  provider: aws
  service: s3
  resource_type: aws_s3_bucket
  expression: '(resource.acl_public || resource.policy_public) && !resource.fully_blocked'
  remediation: Enable Block Public Access and remove public grants.
```

```bash
nubicustos rules list                      # built-in + --rules-dir rules
nubicustos rules validate --rules-dir ./r  # compile + metadata-check user rules
nubicustos rules test --rules-dir ./r      # fire rules against a built-in sample
nubicustos scan --provider aws --rules-dir ./r
```

The Go-coded native checks remain the source of truth for complex/graph logic;
rules cover simple config assertions and field-velocity additions. Supported
resource types today: `aws_s3_bucket`, `aws_rds_instance`, `aws_iam_user`,
`aws_security_group`, `azure_storage_account`, `azure_key_vault`,
`gcp_storage_bucket`, `k8s_pod` (extended by surfacing more of the state model).

### Optional tool plugins

`plugins` runs well-known read-only scanners **if they are installed** and
normalizes their output into the findings model — specialized coverage without
making any tool a hard dependency. An absent tool is skipped, never required.

| Tool | Category |
|------|----------|
| trivy | dependency/filesystem vulnerabilities + misconfigurations |
| grype | package vulnerabilities |
| checkov | infrastructure-as-code |
| terrascan | infrastructure-as-code |
| kube-bench | CIS Kubernetes benchmark |

```bash
nubicustos plugins list                  # tools, PATH status, and last-run + finding count
nubicustos plugins run trivy --target .   # run one tool; findings persist as a scan
nubicustos plugins run --all --target .   # run every installed tool; skip + report the rest
```

`list` shows each tool's install status alongside when it last ran and how many
findings that run produced (read from the results database; it does not create
one if absent). `run --all` sweeps every tool on PATH (bounded by `--concurrency`, default 4;
`1` = sequential), persisting each tool's output as its own `plugin:<tool>` scan
in `Builtin` order, and reports which ran, which were skipped (not installed),
and which failed — no tool is silently dropped. The same sweep backs the TUI
Tools view's "run all".

Each run is persisted as a scan (provider `plugin:<tool>`), so its findings are
queryable, exportable, and browsable in the TUI like native findings. The tool
is invoked with a fixed argument template plus the target as a separate argv
element (never a shell), so there is no command-injection path. (The offensive
exploitation framework Pacu is intentionally not integrated.)

### Terminal UI

`tui` launches a bubbletea/lipgloss interface over a stored scan. Browsing
performs no cloud calls; the Tools view runs external scanners locally on
request. Four views (`1`/`2`/`3`/`4` or `tab` to switch):

- **Dashboard** — severity counts and the top attack paths by score.
- **Findings** — a severity-sorted table; `enter` opens a detail pane with the
  rationale, impact, remediation, resource-specific PoC, and any captured
  validation evidence.
- **Attack Paths** — the scored path list; selecting one shows its step-by-step
  chained PoC.
- **Tools** — the optional external scanners with their install status and
  last-run history. Pick a target (`e` to edit), then `enter` runs the selected
  tool or `a` runs every installed one; the run executes in the background with
  a spinner, and on completion the views refresh to the new scan's findings.

Severity is color-coded throughout (critical/high/medium/low/info).

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

Implemented validators:

- **Public S3 bucket** (external vantage) — anonymous (unsigned) `ListObjectsV2`;
  a 200 confirms unauthenticated listing, a 403 leaves the finding unconfirmed
  (object-level public read may still apply), a network failure is blocked.
- **Publicly accessible RDS** (external vantage) — a TCP connect to the
  instance's collected endpoint with a passive banner read (no bytes sent, no
  auth attempt). A banner, or a connection held open with none (a client-speaks-
  first engine), confirms a live, internet-reachable port — distinguishing a
  real exposure from an instance merely flagged `PubliclyAccessible` while a
  security group still blocks it. A handshake that the peer immediately
  closes/resets (a possible scrubbing middlebox, not the database) is
  unconfirmed; a refused connection is unconfirmed and explicitly noted as
  vantage-limited (it does not refute config-level public access); a timeout is
  blocked.
- **Public EBS snapshot** (authenticated vantage) — re-reads each snapshot's
  `createVolumePermission` with the scan credentials and confirms an explicit
  grant to the `all` group — the exact mechanism that makes a snapshot
  world-restorable, re-checked at validation time so a since-remediated snapshot
  reads as unconfirmed; a denied/throttled read is blocked.
- **Public AMI** (authenticated vantage) — re-reads each image's
  `launchPermission` and confirms a grant to the `all` group.
- **Public RDS snapshot** (authenticated vantage) — re-reads each manual
  snapshot's `restore` attribute and confirms it lists `all`.

Each authenticated-vantage validator probes per affected resource and folds the
results into one evidence record carrying a `confirmed/errored/clean/probed`
summary, so a confirmed verdict from a partial run (some resources unreadable,
or beyond the per-finding probe cap) is never mistaken for a complete all-clear;
any unprobed remainder is reported, never silently dropped.

Authenticated-vantage validators need a live session. Inline `--validate` uses
the scan's own session. The standalone `validate` command resolves a read-only
session on demand — only when the stored scan actually has authenticated-vantage
findings (it takes the same `--profile` / `--region` / `--mfa-*` / `--sso-login`
flags as `scan`); a scan with only external-vantage findings never prompts. If
that session can't be resolved, the authenticated validators are skipped with an
explicit notice (never silently), and the external-vantage validators still run.

The framework registers validators by check id; loose-OIDC AssumeRole tests and
dangling-DNS checks are the next to slot in.

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
| `internal/providers/azure` | Azure collectors (storage, NSG, key vault, subscription discovery) |
| `internal/providers/gcp` | GCP collectors (Cloud Storage, firewall, IAM, project discovery) |
| `internal/providers/k8s` | Kubernetes collectors (pods, RBAC across kubeconfig contexts) |
| `internal/checks/aws` | native AWS posture checks |
| `internal/checks/azure` | native Azure posture checks |
| `internal/checks/gcp` | native GCP posture checks |
| `internal/checks/k8s` | native Kubernetes posture checks |
| `internal/portspec` | shared sensitive-port catalog + range parsing |
| `internal/mcp` | read-only MCP server (LLM integration over stdio) — plan §3.7 |
| `internal/rules` | policy-as-code engine (CEL/YAML rules + state flattening) — plan §9.6 |
| `internal/checks/rules` | rules-engine umbrella check |
| `internal/plugins` | optional external-tool runner + parsers (trivy/grype/checkov/terrascan/kube-bench) — plan §5 |
| `internal/trust` | IAM trust & privilege analysis (assume/federation/privesc) — plan §9.3 |
| `internal/reachability` | network reachability solver for FP reduction — plan §9.5 |
| `internal/graph` | in-process attack-path graph (nodes, edges, scored paths) — plan §3.2 |
| `internal/validate` | opt-in read-only active validation + evidence capture — plan §9.1 |
| `internal/tui` | terminal UI (bubbletea/lipgloss) — dashboard, findings, paths — plan §3.5 |
| `internal/findings` | normalized domain model |
| `internal/store` | embedded SQLite persistence |
| `internal/export` | Cairn / report serializers |

## Test

```bash
go test ./...
```
