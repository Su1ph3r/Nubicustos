# Security Policy

## Reporting a Vulnerability

The Nubicustos team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### Do NOT Report Security Vulnerabilities Through Public Issues

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

### How to Report

If you believe you have found a security vulnerability in Nubicustos, please report it through one of these channels:

1. **GitHub Private Vulnerability Reporting** (Preferred)
   - Navigate to the Security tab in the repository
   - Click "Report a vulnerability"
   - Provide detailed information about the vulnerability

2. **Direct Contact**
   - Contact the maintainers directly through GitHub

### What to Include

Please include the following information in your report:

- Type of vulnerability (e.g., SQL injection, XSS, authentication bypass)
- Full paths of source file(s) related to the vulnerability
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact assessment of the vulnerability
- Any suggested fixes or mitigations

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Status Update**: Every 14 days until resolution
- **Fix Timeline**: Depends on severity (critical: ASAP, high: 30 days, medium: 60 days)

### Severity Levels

We use the following severity classification:

| Level | Description | Response Time |
|-------|-------------|---------------|
| Critical | Remote code execution, authentication bypass | ASAP |
| High | Privilege escalation, data exposure | 30 days |
| Medium | Limited impact vulnerabilities | 60 days |
| Low | Minimal security impact | 90 days |

### Scope

The following are in scope for security reports:

- Nubicustos core codebase
- REST API security issues
- Docker configuration vulnerabilities
- Authentication and authorization issues
- Data exposure risks
- Credential handling issues

The following are out of scope:

- Vulnerabilities in third-party tools (Prowler, ScoutSuite, etc.) - report to their respective maintainers
- Denial of service attacks
- Social engineering
- Physical attacks

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized and will not pursue legal action
- Conducted in good faith
- Helpful to the security of our users

We ask that you:

- Make a good faith effort to avoid privacy violations and data destruction
- Do not access or modify other users' data
- Act in accordance with local laws
- Report vulnerabilities promptly

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Security Best Practices for Users

When deploying Nubicustos:

1. **Change default passwords** in `.env` before deployment
2. **Use strong API keys** if enabling API authentication
3. **Restrict network access** to administrative ports
4. **Keep the stack updated** using `./scripts/update.sh`
5. **Review permissions** before running scans with `scripts/check-permissions.py`
6. **Secure credentials** in the `credentials/` directory (never commit to Git)
7. **Use read-only mounts** for credential files where possible

## Acknowledgments

We thank all security researchers who help keep Nubicustos and its users safe.
