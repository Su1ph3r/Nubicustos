# Nubicustos v2

The single-binary rewrite. A native cloud-posture engine (no Docker, no
external scanners, no Postgres/Neo4j) that scans cloud accounts and exports
runtime-proven findings.

> Status: **native multi-cloud posture engine.** Up-front auth/MFA across AWS
> (SSO/AssumeRole+MFA/GetSessionToken/default chain), Azure (CLI/browser/device-
> code/SP/MI), GCP (ADC), and Kubernetes (kubeconfig contexts), with AWS
> Organization-wide scanning that fans out across member accounts off a single
> MFA-satisfied session and Azure management-group/subscription estate scoping.
> 100+ native checks across
> AWS (S3/IAM/EC2/VPC/RDS/CloudTrail/KMS/Config/GuardDuty/Secrets Manager/ELB/classic ELB/ACM/Route53/Lambda/SNS/SQS/Redshift/ECR/EFS/ElastiCache/DynamoDB/CloudWatch monitoring/control-plane secrets),
> Azure (storage/NSG/Key Vault/SQL/Cosmos DB/MySQL+PostgreSQL/App Service/VMs/Redis/RBAC/Entra ID/Defender for Cloud/activity-log alerts/control-plane secrets),
> GCP (Cloud Storage/firewall/IAM/Cloud SQL/Compute/KMS/GKE/audit logging/log-metric alerts/control-plane secrets), and
> Kubernetes (pod-security/RBAC/control-plane secrets), persisted to SQLite,
> queryable offline, and exportable as Cairn / SARIF / CSV / HTML plus a
> container inventory for downstream container-escape analysis. An in-process
> attack-path graph derives scored internet-exposure, privilege-escalation, and
> assume-role/trust paths with chained PoCs, gated by a local network-reachability
> solver (AWS + Azure). Federation/trust analysis (AWS IAM, Azure RBAC + Entra
> workload-identity federation, GCP cross-project service accounts), including
> cross-cloud federation (an AWS role assumable from Azure/GCP, or an Entra app
> impersonable from AWS/GCP), and an opt-in,
> read-only active-validation pass (AWS + Azure) confirm findings with evidence.
> Compliance mapping onto SOC 2 / PCI-DSS / NIST 800-53 (on top of per-check
> CIS / Well-Architected references). A terminal UI browses a scan; optional
> plugins integrate trivy/grype/checkov/terrascan/kube-bench when present; a
> CEL/YAML policy-as-code engine evaluates built-in and user rules at runtime; a
> read-only MCP server exposes results (and compliance) to an LLM; and an optional
> embedded web UI (REST + SPA over SSE) browses and drives scans. Distributed as a
> single static cross-platform binary.

### Finding shapes

Two shapes, chosen per check:

- **Per-resource** — one finding per misconfigured resource (bucket, instance, DB, user, key, trail). Independently trackable across scans.
- **Aggregate** — one finding with an `affected` list, for control-level posture (e.g. "Config not recording in N of M regions", "these security groups expose sensitive ports", "these snapshots are public"). The `affected` array carries each region/rule/ARN.

### Check catalog (AWS)

| Service | Checks |
|---------|--------|
| S3 | public access (ACL/policy) |
| IAM | root MFA, root access keys, weak password policy, access-key rotation, console user without MFA, directly-attached AdministratorAccess; trust/privilege-escalation analysis; role assumable from another cloud via OIDC federation (cross-cloud) |
| EC2 | open ingress on sensitive ports*, IMDSv2 not enforced, public IP, unencrypted EBS volume, EBS default encryption disabled* |
| VPC | flow logs disabled* |
| RDS | publicly accessible, unencrypted storage, backups disabled, deletion protection disabled, public snapshot* |
| CloudTrail | no logging multi-region trail, log-file validation disabled, not KMS-encrypted |
| KMS | customer-managed key rotation disabled |
| Config | not recording all resources* |
| GuardDuty | not enabled* |
| CloudWatch | missing log metric filter + alarm for sensitive events (CIS monitoring: root usage, unauthorized calls, IAM/CloudTrail/Config/S3/CMK/SG/NACL/gateway/route/VPC/org changes) |
| Exposure | public EBS snapshot*, public AMI* |
| Secrets Manager | rotation disabled* |
| Lambda | public function URL (AuthType NONE), resource policy grants public invoke |
| SNS / SQS | resource policy grants public access |
| Redshift | publicly accessible, not encrypted at rest |
| ECR | repository policy grants public access, image scan-on-push disabled |
| EFS | not encrypted at rest |
| ElastiCache | at-rest encryption disabled, in-transit encryption disabled |
| DynamoDB | point-in-time recovery disabled |
| ELB | internet-facing HTTP listener, weak TLS policy, access logs disabled; classic-ELB cleartext (HTTP/TCP) listener |
| ACM | certificate expired, certificate expiring (<30d) |
| Route53 | record delegates to a takeover-prone target (dangling DNS / subdomain takeover) |
| Secrets | credential material embedded in the control plane (Lambda env / EC2 userdata / SSM plaintext) |

### Org-wide scanning (AWS)

By default `scan --provider aws` scans the one account the profile resolves to.
`--org` turns that into "scan the estate": it enumerates the AWS Organization
from the management (or a delegated-admin) account, then assumes the org access
role into each member and scans them — attributing each account to its own scan
row for per-account filtering and diffing. MFA is satisfied **once** on the base
session; the chained per-member `AssumeRole` inherits it and never re-prompts.

```bash
# Whole organization (skips suspended accounts and the management account itself)
nubicustos scan --provider aws --org --profile mgmt

# Also scan the management account, and assume a custom role name in members
nubicustos scan --provider aws --org --include-mgmt --org-role MyAuditRole

# Restrict to an OU subtree (recursive), excluding a couple of accounts
nubicustos scan --provider aws --ou ou-prod-abc123 --exclude 111111111111,222222222222

# Explicit account list (skips Organizations enumeration entirely)
nubicustos scan --provider aws --accounts 333333333333,444444444444

# Tune per-account parallelism (default 4) and export per-account Cairn files
nubicustos scan --provider aws --org --account-concurrency 8 --export findings.json
```

Accounts scan in parallel (bounded by `--account-concurrency`); a single
account's `AccessDenied` (assume-role or a collector) is tolerated and reported,
never fatal to the run. Out-of-scope accounts — suspended, excluded, or
un-assumable — are listed with their reason so a partial run never reads as full
coverage. With `--export`, each account is written to its own file derived from
the path (`findings.json` → `findings.<account-id>.json`). Requires
`organizations:ListAccounts` (and `ListAccountsForParent`/
`ListOrganizationalUnitsForParent` for `--ou`) on the base identity, plus
`sts:AssumeRole` into the member role.

### Cloud-side secrets detection (AWS)

Source scanners (trufflehog, gitleaks) read code; the cloud control plane is the
under-scanned surface where credentials actually accumulate. On every AWS scan a
detector sweeps three high-signal text surfaces for embedded secrets:

- **Lambda environment variables**
- **EC2 instance userdata** (base64-decoded bootstrap scripts)
- **SSM Parameter Store** plaintext (`String`/`StringList`) parameters —
  `SecureString` parameters are encrypted by design and skipped

The detector pairs a high-confidence pattern library (AWS access keys, private
keys, GitHub/Slack/Google/Stripe tokens, JWTs, credentialed connection strings)
with an entropy-gated heuristic for credential-named fields holding high-entropy,
non-placeholder values. **Privacy is a hard invariant:** a detection records only
a masked rendering (last four characters), its length, entropy, and a
secret-safe locator — the raw value is dropped at the detector boundary, so
nothing downstream (findings, the SQLite store, the Cairn export, logs) can leak
it. Hits roll up into one `aws_exposed_secret` finding.

Liveness is confirmed on demand: `scan --capture-secrets
--validate` retains the raw AWS key material **in-process only** (never written
to disk, the store, or any export — discarded when the command returns) and the
active-validation pass probes each captured key with `sts:GetCallerIdentity`. A
masked posture finding ("a secret is in this Lambda env") becomes runtime-proven
("that key is **live** and maps to `arn:aws:iam::…:user/deploy`", or
rejected/expired). Key id and secret are paired within a single surface, and only
when unambiguous (exactly one access-key-id present), so a pairing is never
guessed. Evidence carries only the masked key id and the ARN it resolves to.

**Exposed-key privilege-escalation chains.** When a captured key is proven live,
its identity is joined to the IAM privilege graph: if the user or role the key
maps to holds administrator access or a privilege-escalation path, the scan emits
a single critical finding and a scored attack path that reads end-to-end: "the
key in function `ingest` is live, maps to `user/deploy`, and `deploy` can escalate
to admin via `iam:PutUserPolicy`." This joins three signals (a control-plane
secret, proof it is valid, and the privilege of the identity behind it) that
single-signal scanners flag, at most, as three unrelated facts. The chain's
terminal node is the same principal node the trust graph builds, so it slots into
the existing attack-path view. Produced under `--capture-secrets --validate`;
appears in `findings`, `paths`, exports, and the MCP/TUI surfaces like any other.

**Public-object content scan.** A public bucket is a config assertion until an
object in it is shown to actually serve secret material to an unauthenticated
caller. `scan --scan-public-content` anonymously (credential-free, operator
vantage) reads a bounded sample of each public bucket's objects and runs the
secret detector over the real content, emitting "this public object is serving a
file containing an AWS key" as confirmed runtime proof of an active leak. It is
strictly bounded and privacy-careful: read-only GETs, a per-bucket object cap, a
per-object byte cap (oversized objects are skipped by their listed size, never
downloaded), a total byte budget, and masked-only output (raw content never
enters a finding or the store). Combined with `--capture-secrets --validate`, a
recovered AWS key is liveness-probed and fed the same privilege-escalation chain
above: public object to live key to admin.

Requires `lambda:ListFunctions`, `ec2:DescribeInstanceAttribute`,
`ssm:DescribeParameters`, and `ssm:GetParameters`; the last (reading parameter
values) is not granted by `SecurityAudit`, so `preflight` flags it and emits it
in the remediation policy when missing.

### Check catalog (Azure)

Native Azure checks run across the subscriptions discovered from the credential
(or `--subscription <id>`):

| Service | Checks |
|---------|--------|
| Storage | anonymous blob public access, HTTPS-only not enforced, network rules default to Allow, minimum TLS below 1.2, shared-key (account-key) auth permitted |
| Network | NSG exposes sensitive ports to the internet (inbound Allow from `*`/`Internet`/`0.0.0.0/0`), gated by reachability (NSG governs a public-IP NIC) |
| Key Vault | soft-delete disabled, purge protection disabled, network rules default to Allow |
| SQL | public network access enabled, firewall allows the whole internet, minimum TLS below 1.2 |
| Cosmos DB | public network access enabled, key-based (local) auth permitted |
| MySQL / PostgreSQL | flexible server public network access enabled |
| App Service | HTTPS-only not enforced, minimum TLS below 1.2, plaintext FTP allowed |
| Virtual Machines | encryption at host disabled |
| Redis | non-TLS port enabled |
| RBAC | custom role grants a wildcard (`*`) action |
| Entra ID | app registration with an external workload-identity federated credential, app impersonable from another cloud via federation (cross-cloud), multi-tenant app, expired credential still configured |
| Defender for Cloud | plans on the Free tier |
| Monitor | no activity-log alert for sensitive operations (policy/NSG/SQL-firewall/security-solution/public-IP changes) |
| Secrets | credential material embedded in the control plane (App Service settings / connection strings) |

```bash
# Azure — scan all enabled subscriptions (or pick one with --subscription)
nubicustos scan --provider azure
nubicustos scan --provider azure --subscription 00000000-0000-0000-0000-000000000000

# Restrict the estate to a management-group subtree, excluding a subscription
nubicustos scan --provider azure --management-group mg-prod --exclude 11111111-1111-1111-1111-111111111111
```

**Estate scoping.** One Azure credential already spans every subscription
the identity can see, so Azure "discovery" is about *scoping and classification*
rather than cross-account role assumption: it enumerates the visible
subscriptions, optionally restricts to a `--management-group` subtree
(recursive), drops `--exclude`d and disabled subscriptions — each listed with its
reason so a partial run never reads as full coverage — and scans the in-scope
set. `--subscription` remains an explicit allowlist.

**Cloud-side secrets.** The same detector that sweeps AWS surfaces runs
over Azure App Service (and Function app) **application settings** and
**connection strings** — the richest Azure secrets surface, where storage keys,
database passwords, and API tokens routinely sit in plaintext. Application
settings go through the pattern + entropy detector; connection strings are
credentials by construction and each is flagged directly. Output is masked
(last four only); hits roll up into one `azure_exposed_secret` finding per
subscription. Reading these settings needs `Microsoft.Web/sites/config/list`
(granted by Website Contributor / Contributor, not by Reader). Secret-liveness
validation is AWS-only; Azure active validation currently covers public-SQL
reachability.

### Check catalog (GCP)

Native GCP checks run across the projects discovered from Application Default
Credentials (or `--project <id>`):

| Service | Checks |
|---------|--------|
| Cloud Storage | public IAM (allUsers/allAuthenticatedUsers), uniform bucket-level access disabled, public access prevention not enforced |
| Compute Engine | default service account with full cloud-platform API access, Shielded VM not fully enabled, interactive serial console enabled |
| VPC firewall | ingress exposes sensitive ports to `0.0.0.0/0` |
| Cloud SQL | public IP, SSL/TLS not required, authorized networks include `0.0.0.0/0`, automated backups disabled |
| KMS | symmetric key with no rotation configured, key IAM grants public access |
| GKE | legacy ABAC enabled, network policy not enforced, control plane not restricted to authorized networks |
| IAM | project binding grants a role to all users, broad primitive role (owner/editor) in use, role granted to a service account from another project (cross-project trust) |
| Logging / Monitoring | data-access audit logging not configured for all services; no log-based metric + alert for sensitive changes (ownership/audit-config/custom-role/firewall/route/network/storage-IAM/SQL changes) |
| Secrets | credential material embedded in the control plane (Cloud Function env / instance metadata) |

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
| Secrets | credential material embedded in the control plane (ConfigMap data / literal pod env) |

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

# Posture drift: compare two stored scans of the same estate. Reports findings
# added/resolved, exposures that opened (a finding that became internet-
# reachable), severity shifts, and attack paths gained/lost. Computed locally
# over the scan history, so it is exact — point-in-time scanners cannot do this.
nubicustos diff                              # latest scan vs the one before it
nubicustos diff --from <id> --to <id>        # compare two specific scans
nubicustos diff --fail-on reachable          # exit non-zero in CI when an exposure opens

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
`list_findings` (severity/service filters), `get_finding`, `list_attack_paths`,
`scan_diff` (posture drift between two scans), and `compliance_report` (control
coverage for soc2/pci/nist). It performs no cloud calls and never triggers a scan — it
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

### Compliance mapping (SOC 2 / PCI-DSS / NIST 800-53)

On top of the per-check CIS and AWS Well-Architected references, `compliance`
maps the native check catalog onto external control frameworks. Each check is
classified into a control category (encryption at rest/in transit, public
exposure, network, access control, MFA, logging, secrets, backup, threat
detection) and each category maps to the equivalent SOC 2 Trust Services
Criterion, PCI-DSS v4.0 requirement, and NIST 800-53 Rev.5 control, so new
checks are covered automatically once classified.

```bash
# Control coverage matrix for a framework (which checks assess each control)
nubicustos compliance --framework soc2
nubicustos compliance --framework pci  --format json

# Overlay a scan's open findings to mark each control pass/fail
nubicustos compliance --framework nist --db nubicustos.db
```

Without a results database it is a pure coverage matrix; with one, a scan's open
findings mark controls pass/fail. The same report is available through the MCP
server (`compliance_report` tool) and as a screen in the terminal and web UIs.

### Preflight: confirm a credential has the access the tooling needs

`preflight` answers, before a scan runs, whether the identity behind a
credential holds the permissions each tool requires — Nubicustos's own native
checks plus the optional external tools (Prowler, CloudSploit) — and
produces a client-ready report of exactly what is missing and how to grant it.
It supports all four providers (`--provider aws | azure | gcp | k8s`).

```bash
nubicustos preflight --profile prod                 # AWS: check all tools
nubicustos preflight --tools nubicustos,prowler     # a subset
nubicustos preflight --format json                  # machine-readable report
nubicustos preflight --write-policies ./fixes       # emit a remediation policy/role per non-ready tool
nubicustos preflight --org                          # AWS: also verify org-wide scan access (Organizations + assume-role)

nubicustos preflight --provider azure --subscription <id>
nubicustos preflight --provider gcp --project <id>
nubicustos preflight --provider k8s --context <name>
```

`--org` adds the org-wide scan permissions (`organizations:ListAccounts`,
`ListAccountsForParent`/`ListOrganizationalUnitsForParent`, and `sts:AssumeRole`)
to the native-checks requirement set, so an estate operator can confirm a base
identity is ready for `scan --org` before launching the fan-out.

It is read-only and verifies access two ways: it leads with IAM policy
simulation (`iam:SimulatePrincipalPolicy`) for an exact allow/deny on every
required action without firing a scan, and cross-checks with a thin live
read-probe (one representative call per service) that catches denials simulation
cannot see — SCPs and permission boundaries — and that covers the case where the
identity cannot simulate at all. Each action's verdict records its basis
(simulated / probed / both), and a disagreement (IAM allows but the runtime
probe is denied) is flagged as a likely SCP block and treated as denied, so a
"ready" verdict is never optimistic.

Per tool it reports `ready` / `partial` / `failed`, the exact missing actions,
and a **generated least-privilege IAM policy of precisely those actions**
(`--write-policies` saves one JSON per tool) alongside the managed-policy
recommendation (`SecurityAudit` / `ViewOnlyAccess`) — the artifact to hand a
client team. The Nubicustos requirement set is authoritative (derived from the
collectors' API calls); the external-tool sets are their documented requirements.
The command exits non-zero unless every selected tool is `ready`, so it can gate
a pipeline.

**Azure (`--provider azure`).** The verification engine is provider-agnostic; only
the access source and the remediation format differ per cloud. Azure has no
`SimulatePrincipalPolicy` equivalent, so Azure preflight is **probe-only**: it
performs one representative read per required ARM operation
(`Microsoft.Storage/storageAccounts/read`, `Microsoft.KeyVault/vaults/read`,
`Microsoft.Web/sites/config/list/Action`, …) against the in-scope subscription. A
live read is in fact the strongest signal — it reflects deny assignments and
Azure Policy that role math would miss: success is `allowed`, a 403 /
`AuthorizationFailed` is `denied`, and an operation with no resource to read
against (e.g. listing a web app's settings when there are no web apps) is honestly
reported as unverified rather than passed. Gaps are rendered as Azure RBAC: the
recommended built-in roles (`Reader` + `Website Contributor`, the latter for the
App Service settings-listing action Reader does not grant) plus a generated
**custom role definition** of exactly the missing actions, scoped to the
subscription and ready for `az role definition create`.

**GCP (`--provider gcp`).** GCP *does* have an authoritative permission API:
Resource Manager `TestIamPermissions` returns exactly which of a queried
permission set the caller holds. Preflight checks the whole required set
(`storage.buckets.list`, `storage.buckets.getIamPolicy`, `compute.firewalls.list`,
`resourcemanager.projects.get`/`getIamPolicy`) in **one batch call** against the
project — held permissions are `allowed`, the rest `denied`. Gaps render as
predefined roles (`roles/iam.securityReviewer` + `roles/viewer`) plus a generated
**custom role** of the missing permissions, ready for `gcloud iam roles create
--file`.

**Kubernetes (`--provider k8s`).** Kubernetes' canonical "can-i" API,
`SelfSubjectAccessReview`, is authoritative (it evaluates the full RBAC ruleset)
and every authenticated user may call it. Preflight runs one review per required
action (`list pods`, and `list`/`roles`/`clusterroles`/`rolebindings`/
`clusterrolebindings` in `rbac.authorization.k8s.io`) against the selected
`--context`. Gaps render as a generated **ClusterRole** of exactly the missing
verbs/resources (grouped by API group, ready for `kubectl apply -f`) to bind to
the scan identity with a ClusterRoleBinding — the built-in `view` role covers pods
but deliberately excludes RBAC objects.

The verification engine, readiness model, and report are identical across all
four clouds; only the access source (IAM simulation, RBAC read-probe,
`TestIamPermissions`, `SelfSubjectAccessReview`) and the remediation artifact
(IAM policy, Azure custom role, GCP custom role, K8s ClusterRole) are
provider-specific.

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
  Started with `tui --preflight` (plus a credential), this view also shows a
  **cloud access** group — `p` runs the access preflight and annotates each
  cloud-posture tool (Nubicustos / Prowler / CloudSploit) with its
  `ready`/`partial`/`failed` readiness for the active credential.

Severity is color-coded throughout (critical/high/medium/low/info).

### Web UI (read-only)

`web` serves the embedded single-page UI and a read-only REST API over a stored
scan database — a browse-and-export console for sharing results, including with
non-operators. It performs no cloud calls and spawns no work, and binds a
loopback address by default.

```bash
nubicustos web                              # serve http://127.0.0.1:8088
nubicustos web --db prod.db --addr 127.0.0.1:9000
```

The API is under `/api/v1` (JSON; `scan` ids accept the `latest` alias): `meta`
(version + mode + capabilities), `scans` / `scans/{id}` / `scans/{id}/summary`,
`scans/{id}/findings` (with `severity`/`service`/`provider`/`reachable`/
`has_evidence` filters, `sort`, and `limit`/`offset`), `findings/{id}`,
`services`, `paths` / `paths/{id}`, `export/{cairn|sarif|csv|html}`, and `tools`.
`meta` reports `mode: read-only` with no capabilities; the UI renders action
affordances purely off that, and the server independently mounts only the
read-only routes — so a shared instance exposes nothing live.

**Operator mode** (`web --allow-actions`) enables live actions and gates the
whole API behind a one-time session token printed at startup (open the printed
`http://127.0.0.1:8088/?t=<token>` URL). The token is required on every `/api`
request as `Authorization: Bearer <token>` or, for the event stream that the
browser's EventSource can't add headers to, the `?t=<token>` query parameter —
which also resists cross-site requests, since a forged page can't read the local
token. `meta` then advertises the mounted capabilities.

This release wires the external-tool sweep as the first action:

```bash
nubicustos web --allow-actions             # prints the tokened URL
```

- `POST /api/v1/tools/run` `{tool?, target, concurrency?}` → `202 {job_id}` (omit
  `tool` to run every installed tool).
- `GET /api/v1/jobs/{id}` — job status (`running`/`done`/`error`/`cancelled`,
  phase, `done/total`, resulting `scan_ids`).
- `GET /api/v1/jobs/{id}/events` — **Server-Sent Events**: the buffered backlog
  then live `phase` / `log` / `done` / `error` frames. The progress is the real
  backend signal — a true `done/total` over the installed tools as each
  completes, plus each tool's outcome — never a timer.
- `POST /api/v1/jobs/{id}/cancel` — cancels the run.

Each tool's findings persist as their own `plugin:<tool>` scan, browsable like
any other.

Operator mode also resolves a cloud credential and runs the credentialed
actions:

- `GET /api/v1/auth` — session status; `POST /api/v1/auth/login`
  `{provider:aws, profile?, region?, mfa_serial?, mfa_token?}` resolves a
  read-only AWS session (non-interactive: a TOTP may be supplied, SSO is honored
  only via a valid cached token — an expired SSO session needs an out-of-band
  `aws sso login`, since a handler must not launch a blocking browser login);
  `POST /api/v1/auth/logout` clears it.
- `POST /api/v1/scans/run` `{regions?, validate?}` → a scan **job** whose SSE
  stream carries the engine's real phase progress (enumerate → collect → checks
  → graph → optional validation → persist); the result is persisted and becomes
  the latest scan.
- `POST /api/v1/preflight/run` `{tools?}` → runs the access preflight against the
  session and returns the report (also held in memory so `GET /api/v1/preflight`
  serves it). `409 no_session` until a credential is resolved.

In-app browser/device-code SSO is a documented follow-on; the AWS auth path
resolves non-interactively today.

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
- **Dangling DNS / subdomain takeover** (external vantage) — resolves the
  record's delegation target: an `NXDOMAIN` target is a confirmed claimable
  dangle; otherwise it issues one anonymous GET to the subdomain and matches a
  narrow set of service "unclaimed" fingerprints (e.g. S3 `NoSuchBucket`). A live
  target with no marker is `unconfirmed` (live from this vantage, ownership
  unverified — not a refutation); an unreachable target is `blocked`. Read-only:
  it never registers the target.
- **Exposed-secret liveness** (authenticated vantage, opt-in `--capture-secrets`)
  — for each AWS key pair captured from the control plane, a single
  `sts:GetCallerIdentity` whoami: a key AWS accepts is `confirmed` live and the
  evidence records the ARN it maps to; a rejected (invalid/expired) key leaves
  the finding `unconfirmed`; a probe that cannot complete is `blocked`. It uses
  the key only to ask "who am I" and never for anything else, and emits no raw
  secret material. Inert unless `--capture-secrets` was set (no captured keys →
  the masked finding stands alone).

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

The framework registers validators by check id. A loose-OIDC `AssumeRole` test
is the next candidate, though an honest active confirmation is constrained: STS
validates a web-identity token's signature before evaluating the trust policy, so
a crafted token cannot prove broad trust from the scanner's vantage — the static
trust analysis remains the primary signal there.

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

Internet-exposure paths are gated by a local **reachability solver**:
a public resource in a subnet with no internet-gateway route, or with no
security group admitting inbound traffic, is annotated `not-reachable` and
**downgraded** (not dropped) rather than presented as live exposure.

### IAM trust & privilege findings

The trust analyzer also emits standalone findings, surfaced through
`findings`/`export`: `aws_iam_role_trust_wildcard_principal` (critical),
`aws_iam_role_trust_external_account`, `aws_iam_oidc_trust_no_subject_condition`,
`aws_iam_admin_via_policy`, and `aws_iam_privilege_escalation`.

## Layout

| Package | Role |
|---------|------|
| `cmd/nubicustos` | cobra CLI entrypoint |
| `internal/auth` | up-front credential resolution + MFA (all AWS & Azure paths) |
| `internal/engine` | registry + concurrent collect→check scanner + graph build |
| `internal/state` | normalized collected cloud state |
| `internal/providers/aws` | AWS collectors (read-only API gatherers) |
| `internal/providers/azure` | Azure collectors (storage, NSG, key vault, control-plane secrets) |
| `internal/providers/gcp` | GCP collectors (Cloud Storage, firewall, IAM, project discovery) |
| `internal/providers/k8s` | Kubernetes collectors (pods, RBAC across kubeconfig contexts) |
| `internal/checks/aws` | native AWS posture checks |
| `internal/checks/azure` | native Azure posture checks |
| `internal/checks/gcp` | native GCP posture checks |
| `internal/checks/k8s` | native Kubernetes posture checks |
| `internal/portspec` | shared sensitive-port catalog + range parsing |
| `internal/mcp` | read-only MCP server (LLM integration over stdio) |
| `internal/rules` | policy-as-code engine (CEL/YAML rules + state flattening) |
| `internal/checks/rules` | rules-engine umbrella check |
| `internal/plugins` | optional external-tool runner + parsers (trivy/grype/checkov/terrascan/kube-bench) |
| `internal/trust` | IAM trust & privilege analysis (assume/federation/privesc) |
| `internal/reachability` | network reachability solver for FP reduction |
| `internal/graph` | in-process attack-path graph (nodes, edges, scored paths) |
| `internal/validate` | opt-in read-only active validation + evidence capture |
| `internal/tui` | terminal UI (bubbletea/lipgloss) — dashboard, findings, paths |
| `internal/findings` | normalized domain model |
| `internal/store` | embedded SQLite persistence |
| `internal/export` | Cairn / report serializers |

## Test

```bash
go test ./...
```
