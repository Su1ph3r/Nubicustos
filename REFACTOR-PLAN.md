# Nubicustos v2 — Refactor Plan

> Complete rewrite from a 28-container Docker Compose orchestration platform into a single
> cross-platform Go binary with a native cloud-posture engine, a terminal-first UI, embedded
> storage, and optional tool plugins.

---

## 1. Why we're doing this

The current system works but is heavy by construction:

| Area | Today | Problem |
|------|-------|---------|
| **Runtime** | 28 Docker containers (579-line compose) | Docker-only; ~23 of those are external tool images we shell out to |
| **Stores** | PostgreSQL **and** Neo4j | Two stateful services just to hold findings + a graph |
| **Backend** | FastAPI (~25k LOC, 30 routers) + Python report-processor (~14.5k LOC) | Large surface, container-coupled (`docker_executor.py` orchestrates tool containers) |
| **Frontend** | Vue 3 + **PrimeVue** (~24.8k LOC, 19 views) | Generic component-library theme = the "made by an AI" look |
| **Checks** | Delegated to ScoutSuite / Prowler / CloudSploit / etc. | We don't own the checks; output formats drift; normalization is fragile; hard to embed cleanly in Cairn |
| **Setup** | 5.8KB `.env`, 58 keys, Docker required | High friction to run; not portable |

### Locked design decisions

1. **Language/runtime:** **Go** — single static cross-platform binary, mature AWS/Azure/GCP/K8s SDKs, goroutine concurrency for parallel scanning, `embed` for assets.
2. **Native scope:** **Native posture engine + optional plugins.** Reimplement the high-value cloud checks ourselves (replacing ScoutSuite/Prowler/CloudSploit — these are just API-read + rule-eval). Keep specialized tools (Pacu, trivy/grype/checkov, kube-bench) as **optional** plugins that run only if present.
3. **UI:** **Terminal UI primary** (Charm/bubbletea), web UI optional and deferred.
4. **Storage:** **Embedded SQLite + in-proc attack-path graph.** No external DB. Cairn integration via a stable normalized findings JSON export.

---

## 2. Target architecture

```
                       ┌────────────────────────────────────────────┐
                       │              nubicustos (1 binary)          │
                       │                                             │
   cloud creds ─────▶  │  providers/    checks/        graph/        │
   (~/.aws etc.)       │  (collectors)  (native rules) (attack paths)│
                       │       │            │              │         │
                       │       ▼            ▼              ▼         │
                       │  ┌──────────────────────────────────────┐  │
                       │  │   engine (parallel scan orchestrator) │  │
                       │  └──────────────────────────────────────┘  │
                       │       │                                     │
                       │       ▼                                     │
                       │   store/ (embedded SQLite)  ◀── plugins/    │
                       │       │                       (optional     │
                       │       ▼                        external     │
                       │   ┌─────────┬──────────┐       tools)       │
                       │   │  TUI    │  export   │                   │
                       │   │ (primary)│ cairn/   │   web/ (optional, │
                       │   │         │ sarif/csv │   later phase)    │
                       │   └─────────┴──────────┘                   │
                       └────────────────────────────────────────────┘
```

### Go module layout

```
nubicustos/                         (module: github.com/Su1ph3r/nubicustos)
├── cmd/nubicustos/main.go          # cobra root — the single entrypoint
├── internal/
│   ├── engine/                     # scan orchestration core
│   │   ├── scanner.go              # worker-pool driver (bounded goroutines)
│   │   ├── registry.go             # check + collector registry
│   │   └── context.go              # scan context, provider sessions, account/sub/project scope
│   ├── auth/                       # AUTHENTICATION & MFA (foundational — see §8)
│   │   ├── resolver.go             # up-front credential resolution + whoami validation
│   │   ├── prompter.go             # TokenPrompter interface (TUI modal / stdin / non-interactive)
│   │   ├── cache.go                # 0600 / OS-keyring credential cache; reuse AWS/az CLI caches
│   │   ├── aws.go                  # SSO, AssumeRole+MFA, GetSessionToken, default chain
│   │   └── azure.go                # AzureCLI / InteractiveBrowser / DeviceCode / SP / MI
│   ├── providers/                  # cloud collectors (read-only API calls → normalized state)
│   │   ├── aws/                    # aws-sdk-go-v2; one collector per service
│   │   ├── azure/                  # azure-sdk-for-go
│   │   ├── gcp/                    # google-cloud-go
│   │   └── k8s/                    # client-go
│   ├── state/                      # normalized in-memory cloud-state model (queryable)
│   ├── checks/                     # NATIVE posture rules (the engine)
│   │   ├── aws/                    # s3.go, iam.go, ec2.go, rds.go, cloudtrail.go, kms.go ...
│   │   ├── azure/                  # storage.go, nsg.go, keyvault.go ...
│   │   ├── gcp/                    # storage.go, firewall.go, iam.go ...
│   │   └── spec/                   # CheckSpec: id, title, severity, rationale, compliance refs,
│   │                               #            remediation CLI, PoC template
│   ├── findings/                   # normalized Finding model + dedup + severity scoring
│   ├── graph/                      # in-proc attack-path graph (replaces Neo4j + PMapper + CloudMapper)
│   │   ├── builder.go              # nodes = principals/resources; edges = can-assume / escalate / reach
│   │   ├── edges.go                # edge definitions (privesc, assume-role, public-exposure)
│   │   └── paths.go                # path enumeration + 0-100 risk scoring + chained PoC
│   ├── discovery/                  # org/tenant/project auto-enumeration (AWS Orgs, Azure mgmt groups, GCP hierarchy) — §9.4
│   ├── reachability/               # network reachability solver (SG+NACL+routes+IGW) — FP reduction — §9.5
│   ├── trust/                      # federation & external-trust analysis (OIDC/SAML/cross-account/resource policies) — §9.3
│   ├── secrets/                    # cloud control-plane secret scanning (Lambda env, userdata, SSM, task defs...) — §9.2
│   ├── validate/                   # active safe-exploit confirmation + evidence capture (opt-in, read-only) — §9.1
│   ├── rules/                      # policy-as-code engine (CEL/YAML) for custom + built-in checks — §9.6
│   ├── compliance/                 # framework mappings (CIS, SOC2, PCI, NIST...) as embedded data
│   ├── remediation/                # remediation KB + PoC generator
│   ├── store/                      # modernc.org/sqlite (pure Go, no CGO)
│   │   ├── schema.sql
│   │   ├── migrations/             # embed.FS migrations
│   │   └── queries.go
│   ├── plugins/                    # OPTIONAL external-tool integration
│   │   ├── runner.go               # exec or docker adapter; skips gracefully if absent
│   │   ├── manifest.go             # declarative tool descriptors
│   │   └── parsers/                # trivy / grype / checkov / terrascan / kube-bench / pacu → Finding
│   ├── export/                     # cairn.go (normalized JSON), sarif.go, csv.go, html.go
│   ├── tui/                        # PRIMARY UI — bubbletea
│   │   ├── app.go                  # root model / routing
│   │   ├── views/                  # scan, dashboard, findings, detail, attackpaths, compliance
│   │   └── theme/                  # lipgloss styles (security-ops aesthetic)
│   ├── mcp/                        # Go MCP server (`nubicustos mcp`) — replaces Python MCP service
│   └── web/                        # OPTIONAL embedded SPA + REST (deferred phase)
├── data/                           # embedded: check specs, compliance maps, remediation KB
├── .goreleaser.yaml                # cross-compile + release
└── go.mod
```

### CLI surface (cobra)

```
nubicustos scan      --provider aws --profile prod [--checks iam,s3] [--region ...]
nubicustos tui       # launch the terminal UI (also the default with no args)
nubicustos findings  --severity critical,high --format table|json
nubicustos paths     # list attack paths
nubicustos export    cairn|sarif|csv|html  --out findings.json
nubicustos plugins   list|run trivy|...    # optional external tools
nubicustos web       # optional local web server (later phase)
nubicustos mcp       # MCP server over stdio for LLM integration
```

---

## 3. Key design choices & rationale

### 3.1 Native checks: collectors + Go rule functions

ScoutSuite / Prowler / CloudSploit are all the same shape: **read-only API call → evaluate rule against returned config → emit finding.** We reproduce that natively:

- **Collectors** (`providers/`) call `Describe*/List*/Get*` and populate a normalized **state** model in memory. Heavy parallelism via a bounded worker pool (this is where Go shines vs. sequential Python).
- **Checks** (`checks/`) are registered Go functions that read `state` and emit `Finding`s. Each is paired with a `CheckSpec` carrying all metadata.

> **Why Go functions, not a DSL (v1):** debuggable, type-safe, no embedded interpreter. A declarative YAML/CEL rule layer can be added later for simple config assertions, but the v1 priority is correctness and breadth, not a rule language.

**Check priority (highest signal first — gets us to Cairn-import parity fast):**

1. **IAM** — root MFA, access-key age/rotation, password policy, admin/`*:*` policies, privesc-prone permission sets, unused credentials.
2. **S3** — public buckets, block-public-access, encryption, logging, versioning, ACL/policy exposure.
3. **EC2 / VPC** — security groups open to `0.0.0.0/0`, IMDSv2 enforcement, public IPs, EBS encryption, default-VPC usage.
4. **RDS** — public accessibility, encryption-at-rest, backups, deletion protection.
5. **CloudTrail / Config / GuardDuty** — enabled, multi-region, log-file validation.
6. **KMS / Secrets** — key rotation, exposed secrets in functions/userdata.
7. Then **Azure** (storage public, NSGs, Key Vault) and **GCP** (buckets, firewall, IAM).

**No coverage regression during transition:** until native breadth matches the old tools, the same tools remain available as **plugins**, so nothing is lost while we build.

### 3.2 Attack-path graph, in-process

Replaces **Neo4j + PMapper + CloudMapper** with an in-proc graph (adjacency model; `gonum/graph` optional).

- **Nodes:** IAM principals, resources, internet.
- **Edges:** `can-assume-role`, `can-escalate-via:<action>`, `can-access`, `exposed-to-internet`.
- **Paths:** enumerate principal→admin and internet→sensitive-resource chains; score 0-100 by exploitability × impact.
- **Payoff:** every edge carries a concrete, parameterized **PoC command**, so a path is a runnable, step-by-step exploit narrative — directly addressing "better PoC, better details."

### 3.3 Better PoC + details as a first-class data model

`CheckSpec` and graph edges both carry:

- `Rationale` / `Impact` (why it matters),
- `Remediation` (exact provider CLI to fix),
- `PoC` (template parameterized by the **actual** resource, e.g. `aws s3api get-bucket-acl --bucket <name>` to prove the exposure).

This makes PoCs deterministic and resource-specific instead of generic prose.

### 3.4 Storage: embedded SQLite

- **`modernc.org/sqlite`** (pure Go, **no CGO**) keeps cross-compilation trivial — the right trade for a tool shipped as static binaries. (CGO `mattn/go-sqlite3` is faster but breaks easy cross-builds.)
- Schema: `scans`, `resources`, `findings`, `principals`, `edges`, `attack_paths`, `compliance_results`.
- Migrations embedded via `embed.FS`.
- Graph is built in memory from `principals`/`edges` per scan; persisted for diffing/history.

### 3.5 TUI primary (Charm stack)

- **bubbletea** (framework), **lipgloss** (styling), **bubbles** (table/viewport/list/spinner), **glamour** (render remediation/PoC markdown in-pane).
- **Views:** Scan launcher → live progress; Dashboard (severity counts, trend sparkline); Findings (filter/sort table → detail pane with PoC); Attack Paths (path list → step-by-step with chained PoCs); Compliance (framework coverage matrix).
- This sidesteps the "AI dashboard template" aesthetic entirely and fits the operator/pentest workflow.

### 3.6 Cairn integration

- `nubicustos export cairn` emits the **normalized findings JSON** that Vinculum/Cepheus already consume, plus `nubicustos-containers.json` (container inventory from K8s/ECS collectors) for Cepheus.
- Schema is **versioned** (`schema_version`) so Cairn ingestion is stable across releases.
- Because the engine owns the finding model end-to-end, the export is clean and consistent — no per-tool format drift.

### 3.7 MCP server in Go

- `nubicustos mcp` (e.g. `mark3labs/mcp-go` or the official Go SDK) talks **directly** to the engine/store. Removes the separate Python MCP service while preserving the LLM-integration surface.

---

## 4. Phased delivery

Each phase is independently shippable. Phases 0–2 already beat the current stack for the AWS case (no Docker, no Postgres/Neo4j, clean Cairn export).

| Phase | Scope | Outcome |
|-------|-------|---------|
| **0 — Scaffold** | Go module, cobra CLI, SQLite store + migrations, `Finding`/`CheckSpec` models, embed framework. **Port compliance maps + remediation KB + severity scoring + attack-path edge definitions** from the existing Python `report-processor` (these are mostly **data** — re-encode, don't re-derive). CI cross-compile via goreleaser. | Empty-but-real binary; knowledge base preserved. |
| **1a — Auth & MFA** | `internal/auth`: all 4 AWS paths (SSO, AssumeRole+MFA, GetSessionToken, default chain) + all 3 Azure paths (CLI/browser/device-code, SP/MI). Up-front resolve+validate phase, pluggable prompter, credential cache. **Hard prerequisite for any real scan — see §8.** | MFA-required accounts authenticate reliably; scan fan-out never prompts. |
| **1 — AWS native core** | AWS collectors + top ~40 checks (IAM/S3/EC2/RDS/CloudTrail). **+ org auto-discovery (§9.4)** and **cloud-side secrets (§9.2, AWS surfaces)**. Findings → SQLite. `scan` + `export cairn/json/csv`. Built on 1a. | **MVP**: real native AWS posture scan across the whole org, Cairn-import parity, zero external deps. |
| **2 — Attack-path graph** | In-proc graph: IAM privesc + assume-role + public exposure; risk scoring; chained PoC per edge. **+ reachability solver (§9.5)** gating exposure findings and **federation/external-trust analysis (§9.3)** as graph edges. | Replaces Neo4j + PMapper + CloudMapper; far fewer false positives. |
| **2b — Active validation** | Opt-in read-only confirmation pass (§9.1): anonymously prove public buckets, open ports, dangling DNS, loose OIDC trust, live secrets; capture evidence per finding → Cairn PoC. | Runtime-proven findings, not config assertions. |
| **3 — TUI** | bubbletea app: scan, dashboard, findings+detail, attack paths, compliance. | Primary UI; no more web/Postgres needed to operate. |
| **4 — Azure + GCP + K8s** | Collectors + native checks for the other providers. **Extend secrets (§9.2), federation-trust (§9.3), reachability (§9.5), and discovery (§9.4) to each cloud.** | Multi-cloud parity with old core tools. |
| **5 — Plugins** | Plugin runner + parsers for trivy/grype/checkov/terrascan/kube-bench/pacu (optional). | Specialized coverage without making tools required. |
| **5b — Policy-as-code** | CEL/YAML rule engine (§9.6): built-in simple checks re-expressed as rules + user-supplied custom checks loaded at runtime. `rules list/validate/test`. | Extensible without recompiling; encode field findings instantly. |
| **6 — MCP** | Go MCP server; deprecate Python MCP. | One binary owns LLM integration. |
| **7 — Web (optional)** | Embedded SPA (custom design system — Svelte recommended for small bundle) + REST, served by the binary via `embed.FS`. | Shareable dashboard for non-operators. |
| **8 — Cutover** | goreleaser binaries (linux/macos/windows × amd64/arm64), checksums, SBOM, Homebrew tap + Scoop bucket. Docker becomes a thin optional wrapper. Archive the v1 compose stack. | Single-binary distribution; bloat retired. |

---

## 5. What we reuse vs. rewrite

| Asset (current repo) | Disposition |
|----------------------|-------------|
| Compliance framework mappings (29+) | **Port as data.** High-leverage; do not re-derive. |
| Remediation KB (`remediation_kb.py`) | **Port as data.** |
| Severity scoring (`severity_scoring.py`) | **Port logic** to Go. |
| Attack-path edge definitions (`attack_path_edges.py`, `privesc_path_edges.py`) | **Port as data/logic** — directly informs `graph/edges.go`. |
| Parsers (`report-processor/parsers/`) | **Reference, then reimplement** only for the tools kept as plugins. |
| `docker_executor.py` | **Drop.** Replaced by native collectors + optional plugin runner. |
| FastAPI routers | **Drop.** Logic moves into engine; optional web phase adds a thin REST layer. |
| Vue + PrimeVue frontend | **Drop.** Replaced by TUI (and optional custom-design SPA later). |
| `init.sql` (Postgres schema) | **Reference** for the new SQLite schema; simplify. |
| Python MCP server | **Reimplement** in Go (Phase 6). |

---

## 6. Distribution

- **goreleaser** → static binaries for linux/macos/windows × amd64/arm64.
- GitHub Releases with checksums + optional SBOM.
- Homebrew tap (`brew install su1ph3r/tap/nubicustos`) + Scoop bucket.
- **Docker becomes optional** — a thin image wrapping the binary, not the primary path.
- Run model: `nubicustos scan --profile prod` then `nubicustos tui` — no compose, no DB, no `.env` sprawl (config via flags + a small optional `nubicustos.yaml`).

---

## 7. Risks & mitigations

| Risk | Mitigation |
|------|------------|
| **Breadth of native checks** is the long pole (old tools have hundreds) | Prioritize by signal; keep old tools as **plugins** during transition → no coverage regression. Consider collector code-gen. |
| **aws-sdk-go-v2 verbosity** | Generate collector boilerplate; centralize pagination/retry helpers. |
| **TUI-primary loses the shareable web dashboard** for non-operators | Web stays a planned **optional** phase (7), embedded in the same binary. |
| **Pure-Go SQLite slower than CGO** | Acceptable for this workload; preserves trivial cross-compile. Revisit only if profiling demands it. |
| **Parity anxiety during cutover** | Build v2 in parallel (branch `v2` / separate module tree). v1 compose keeps working until v2 reaches parity, then flip. |
| **Re-encoding the knowledge base** (compliance/remediation) introduces drift | Treat it as a **data migration** with a diff check against the Python source, not a rewrite. |

---

## 8. Authentication & MFA (non-negotiable)

Scanning accounts that **require MFA must work** for both AWS and Azure. This is foundational —
`internal/auth` is a hard prerequisite for the AWS core (Phase 1a, before Phase 1). The strategy:
**lean on the official SDK credential providers** (they already encapsulate the correct flows) and
wrap them in an explicit up-front auth phase so the concurrent scan never blocks on a prompt.

### 9.1 The two-phase rule (this is what makes it reliable under concurrency)

1. **Resolve & validate (single-threaded, interactive):** determine the auth method, perform any
   interactive step **exactly once** (TOTP prompt, browser, device code), then prove it with one
   whoami call (`sts:GetCallerIdentity` / Azure subscription list). Creds are cached after this.
2. **Collect (fan-out, never interactive):** the bounded worker pool uses the cached, validated,
   MFA-satisfied credentials. No collector goroutine is ever allowed to trigger a prompt.

All providers are wrapped in `aws.NewCredentialsCache` (AWS) / azidentity's token cache (Azure) so
concurrent `Retrieve` calls dedupe to a single underlying auth, and a mutex serializes the human
prompt so even simultaneous triggers produce **one** TOTP entry.

### 9.2 AWS — all four paths

| Path | Mechanism | How we handle it |
|------|-----------|------------------|
| **IAM Identity Center / SSO** | `~/.aws/config` profile with `sso_session`; MFA satisfied at the IdP in-browser; token cached in `~/.aws/sso/cache`. | `config.LoadDefaultConfig` resolves it automatically **if** a valid cached SSO token exists. If missing/expired, we run the SSO OIDC device-authorization flow natively (`ssooidc`: RegisterClient → StartDeviceAuthorization → **auto-open browser** → poll CreateToken) and write a CLI-compatible cache entry. Fallback: shell `aws sso login --profile X`. Local workstation → browser opens automatically. |
| **AssumeRole + MFA** | Profile with `role_arn` + `mfa_serial` + `source_profile`; SDK calls `sts:AssumeRole` with a TOTP code. | `config.WithAssumeRoleCredentialOptions` sets `o.TokenProvider = ourPrompter`. The SDK reads `mfa_serial` from shared config and calls our prompter for the code. Result cached to `~/.aws/cli/cache`-compatible store. |
| **Static keys + MFA-condition policy** (no role) | Long-lived keys denied unless `aws:MultiFactorAuthPresent=true`. **The SDK does NOT auto-call `GetSessionToken` here** — this is the case everyone gets wrong. | We detect it (`mfa_serial` present but no `role_arn`, or `--mfa-serial` flag) and call `sts:GetSessionToken` with SerialNumber+TokenCode ourselves → temp creds with MFA present → wrap in a cached static provider. Duration up to 36h. |
| **Static keys / instance role / env** (no MFA) | Default credential chain. | Resolved by `LoadDefaultConfig`; no prompt. |

**Cross-account / org scanning:** MFA is satisfied **once** at the session root (GetSessionToken or
the initial MFA AssumeRole). Chained `AssumeRole` calls into member accounts inherit
`aws:MultiFactorAuthPresent=true` and **do not re-prompt** — we assume per-account roles off the
MFA-present base session.

### 9.3 Azure — all three paths

| Path | Credential | Notes |
|------|-----------|-------|
| **Reuse `az login`** (default) | `AzureCLICredential` | MFA / Conditional Access already satisfied in the browser during `az login`; we reuse the cached token. Lowest friction. |
| **Scanner-initiated sign-in** | `InteractiveBrowserCredential` (local) / `DeviceCodeCredential` (headless fallback) | Entra MFA prompts appear in the auth flow. Local workstation → browser pop-up is primary; device-code prints a URL+code as a bonus for SSH use. |
| **Service principal / managed identity** | `ClientSecretCredential` / `ClientCertificateCredential` / `ManagedIdentityCredential` | Non-interactive; usually MFA-exempt but honors cert-based Conditional Access. |

Selection via `--auth` (default = CLI → interactive-browser chain through `ChainedTokenCredential`).
azidentity handles token refresh and CAE claims challenges; we enable its **persistent token cache**
so an MFA-satisfied session survives across runs.

### 9.4 Pluggable prompter (local-first, but works everywhere)

A `TokenPrompter` interface decouples the auth logic from the UI:

- **TUI modal** (bubbletea) — primary for the TUI; masked TOTP input, browser/device-code instructions rendered inline.
- **Stdin** — plain CLI / `nubicustos scan` without the TUI.
- **Non-interactive** — `--mfa-token <code>` / env var, or service-principal creds. If MFA is required and **no** token source exists, **fail fast with an actionable error — never hang.**

Browser flows auto-open on the local workstation (`pkg/browser`); device-code prints
`microsoft.com/devicelogin` / SSO verification URLs through the same interface.

### 9.5 Credential cache, session lifetime, security

- **Reuse the cloud CLIs' own caches** (`~/.aws/sso/cache`, `~/.aws/cli/cache`, az token cache) so a prior `aws sso login` / `az login` Just Works with zero extra prompts.
- Our own session/assume-role results cached to **`0600` files or the OS keyring** (`zalando/go-keyring`), keyed by identity+serial, honoring expiry. `--no-cache` to bypass.
- **Session TTL ≥ scan duration:** GetSessionToken up to 36h, AssumeRole ≤ role max session, SSO ~8h, Azure ~1h auto-refreshed by azidentity. Pick durations long enough for multi-account scans; surface an "session expires in N min" warning.
- **Security hygiene:** never log token codes or secrets; redact in error output; honor `credential_process`; zero sensitive buffers where practical.

### 9.6 Config surface

```bash
# AWS — SSO (browser opens automatically; MFA at IdP)
nubicustos scan --provider aws --profile prod-sso

# AWS — AssumeRole + MFA (prompts for TOTP once, then fans out)
nubicustos scan --provider aws --profile cross-account

# AWS — static keys + MFA-condition policy (we call GetSessionToken)
nubicustos scan --provider aws --profile dev --mfa-serial arn:aws:iam::123:mfa/me
nubicustos scan --provider aws --profile dev --mfa-serial arn:... --mfa-token 123456  # non-interactive

# Azure — reuse az login (default), or force a flow
nubicustos scan --provider azure
nubicustos scan --provider azure --auth interactive-browser
nubicustos scan --provider azure --auth device-code
```

Per-profile defaults live in optional `nubicustos.yaml` (auth method, mfa_serial, session duration).

### 9.7 Acceptance gate — "it has to work" means we prove it

MFA flows can't be meaningfully mocked, so correctness is gated on a **real-account test matrix**,
run before this is declared done:

- **AWS:** SSO ✓, AssumeRole+MFA ✓, static-keys+MFA-condition (GetSessionToken) ✓, default-chain ✓ — each against a real MFA-required account.
- **Azure:** az-login reuse ✓, interactive-browser ✓, device-code ✓, service-principal ✓.
- **Concurrency:** confirm a fan-out scan triggers **exactly one** TOTP prompt (no per-collector prompts, no hangs).
- **Failure modes:** expired SSO token → clean re-auth; wrong TOTP → clear retry; MFA required + non-interactive + no token → fail fast with a precise message.

Unit tests cover provider wiring with faked STS/token providers; the matrix above is the manual
integration gate against live accounts.

---

## 9. Capability roadmap — Tier 1 additions

Six capabilities that raise the tool from "config-assertion scanner" to "runtime-proven cloud
attack-surface engine," chosen to match the pentest → Cairn → bounty-pipeline workflow. Each stays
true to the anti-bloat goal: native, read-only by default, optional where it adds weight.

| # | Capability | Phase | Net-new package |
|---|------------|-------|-----------------|
| 1 | Active validation / safe exploit confirmation | 2b | `internal/validate` |
| 2 | Cloud-side secrets detection | 1 (AWS), 4 (rest) | `internal/secrets` |
| 3 | Federation & external-trust analysis | 2 (AWS), 4 (rest) | `internal/trust` |
| 4 | Org-wide auto-discovery | 1 (AWS), 4 (rest) | `internal/discovery` |
| 5 | Reachability-based FP reduction | 2 (AWS), 4 (rest) | `internal/reachability` |
| 6 | Custom checks as policy-as-code | 5b | `internal/rules` |

### 9.1 Active validation — safe exploit confirmation

An **opt-in, read-only** pass (`nubicustos scan --validate` / `nubicustos validate`) that runs *after*
findings + reachability, taking confirmable findings and proving exploitability with captured evidence.
This is the flagship differentiator and the embodiment of the runtime-proof methodology.

**Safety contract (hard invariants, enforced in `validate`):**
- Read-only only — never write, modify, delete, or DoS. No state change on the target.
- Stop at the proven primitive (escalation-restraint): confirm the door is open, do not walk through destructively.
- Rate-limited; per-validator declared blast radius = `none`; a strict allowlist of validation actions.
- Two vantage points, each labeled on the evidence: **external** (no credentials, operator's network vantage) and **authenticated** (scan creds, exercised as a low-privilege check).

**Validators (per finding type):**

| Finding | Confirmation (read-only) | Evidence captured |
|---------|--------------------------|-------------------|
| Public S3 bucket/object | Anonymous (unsigned) `GET`/list | HTTP status, first bytes / key listing |
| Public RDS / Redis / Elastic / Mongo port | TCP connect + banner grab (no auth attempts) | Reachable + service banner |
| Public RDS/EBS snapshot or AMI | Describe as anonymous/other principal | Confirmed `Public` share attribute |
| Dangling DNS / subdomain takeover | Resolve + origin-claimable check | Record, target, claimable verdict |
| Loose OIDC/SAML role trust | `AssumeRoleWithWebIdentity` with benign crafted token | Allow/deny + condition that permitted it |
| Exposed secret (from §9.2) | Read-only whoami for that cred type (e.g. STS `GetCallerIdentity`) | Live/expired + identity it maps to |
| IMDSv1 reachable (inside scan) | Metadata endpoint reachability probe | Reachable + role name exposed |

**Evidence object** (request issued, response captured, vantage, timestamp, principal context, verdict
`confirmed|unconfirmed|blocked`) attaches to the `Finding` and flows into the Cairn export as PoC
evidence — turning a posture finding into a Cairn-ready, runtime-proven report item.

### 9.2 Cloud-side secrets detection

trufflehog/gitleaks scan *code*; the control plane is the under-scanned goldmine. Collectors gather
text surfaces; a detector (pattern library + entropy + provider-specific signatures) flags secrets.

- **AWS surfaces:** Lambda env vars, EC2/ASG/launch-template userdata (base64-decoded), SSM Parameter Store, ECS/Batch task-def env, CloudFormation params/outputs, CodeBuild env, Amplify/AppRunner config, Terraform state in S3 (if readable).
- **Azure:** App Service app settings + connection strings, Function app settings, Automation account variables, Logic Apps, ARM template params.
- **GCP:** Cloud Functions / Cloud Run env, instance metadata startup-scripts, Deployment Manager.
- **Detector:** AWS keys, GCP SA JSON, Azure connection strings, private keys, JWTs, DB URLs, generic high-entropy; allowlist/ignore rules.
- **Privacy:** never log/export the full secret — masked + last-4 only; raw kept solely in a `0600` local evidence store under `--capture-secrets`. Each hit feeds §9.1 for liveness validation.

### 9.3 Federation & external-trust analysis

Models the trust dimension of the graph — where the modern critical-severity findings actually live.

- **AWS:** parse IAM role trust policies, resource policies (KMS/S3/SQS/SNS/Secrets/Lambda), SAML/OIDC IdPs, Cognito identity pools. Detect: roles trusting an external account root; OIDC providers with weak `sub`/`aud` conditions (GitHub Actions `repo:org/*` or missing `sub`); `Principal:"*"` without `Condition`; confused-deputy gaps (missing `aws:SourceArn`/`SourceAccount` on service trusts); over-broad `sts:AssumeRole`; anonymous resource policies.
- **Azure:** cross-tenant guest access, app registrations with broad consent, **federated credentials** on app registrations/managed identities (the OIDC-trust equivalent), subscription RBAC granted to external principals.
- **Output:** external→principal edges into the attack-path graph (§3.2) plus standalone high-severity findings; each carries a §9.1 validator where safe (e.g. the OIDC assume test).

### 9.4 Org-wide auto-discovery

Turns "scan one account" into "scan the estate," off the MFA-present base session from §8.

- **AWS:** `organizations:ListAccounts` from the management/delegated-admin account → assume the org access role (`OrganizationAccountAccessRole` or configured) per member via the cross-account chaining in §8.2 (no re-prompt). Skip suspended accounts.
- **Azure:** enumerate management groups + subscriptions via ARM; one credential spans visible subscriptions.
- **GCP:** Cloud Resource Manager org → folders → projects.
- **K8s:** iterate kubeconfig contexts.
- **Controls:** `--accounts` / `--exclude` / `--ou` / `--regions`; per-account concurrency cap; **partial-failure tolerance** (one account's AccessDenied never aborts the run); results attributed per account/subscription/project in the store for filtering and diffing.

### 9.5 Reachability-based false-positive reduction

A security group open to `0.0.0.0/0` on an instance with no public IP in a private subnet is **not**
exposed. Modeling actual reachability is the credibility multiplier.

- **Model:** instances/ENIs ↔ subnets ↔ route tables ↔ IGW/NAT/TGW/peering, combined with effective SG + NACL (ordered) rules, public-IP assignment, and ELB/target-group exposure. Approximates AWS Reachability Analyzer logic **locally** — no API cost, no extra permissions.
- **Azure:** NSG effective rules + user-defined routes + public IP + Azure Firewall/LB.
- **Use:** every exposure finding carries `reachable: true|false|unknown` + the path; severity is adjusted (a non-reachable "open" rule is downgraded/annotated, not dropped). Also gates §9.1 — we only spend validation effort on genuinely reachable targets.

### 9.6 Custom checks as policy-as-code

A declarative rule layer evaluated against the collected `state` model, loaded at runtime — no recompile.

- **Engine:** CEL (`cel-go`) expressions over a documented state schema, wrapped in YAML carrying full rule metadata (id, title, severity, compliance refs, remediation, PoC template, optional `validate` binding).
- **Example:** `resource.type == "aws_s3_bucket" && !resource.public_access_block.block_public_acls`.
- **Unification:** simple built-in checks are themselves authored as rules (Go functions reserved for complex/graph logic), so the built-in pack and user rules share one engine. Built-in rules ship via `embed.FS`.
- **CLI:** `nubicustos rules list|validate|test`; user rules dir via flag/`nubicustos.yaml`.
- **Why:** longevity and field-velocity — encode a freshly discovered finding the moment you see it, without a release.

---

## 10. Immediate next steps (Phase 0)

1. Create `v2` branch (or parallel module tree) so v1 stays runnable.
2. `go mod init`; add cobra, bubbletea/lipgloss/bubbles, aws-sdk-go-v2, modernc.org/sqlite, goreleaser config.
3. Define `Finding`, `CheckSpec`, `Resource`, `Principal`, `Edge` Go types + SQLite schema/migrations.
4. Extract compliance maps, remediation KB, severity scoring, and attack-path edges from the Python `report-processor` into embedded data files + a diff check.
5. Stand up the registry + a single end-to-end vertical slice: one AWS collector (S3) → one check (public-bucket) → SQLite → `export cairn`.
6. Wire goreleaser CI so cross-platform binaries build from day one.

Phase 0 + the S3 vertical slice proves the whole pipeline before scaling check breadth.
