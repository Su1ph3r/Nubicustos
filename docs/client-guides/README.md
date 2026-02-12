# Nubicustos Client Credential Setup Guides

This directory contains step-by-step instructions for setting up credentials to enable Nubicustos security scanning on your cloud environments.

---

## Available Guides

| Cloud Provider | Guide |
|----------------|-------|
| **Amazon Web Services (AWS)** | [AWS-Credential-Setup-Guide.md](./AWS-Credential-Setup-Guide.md) |
| **Microsoft Azure** | [Azure-Credential-Setup-Guide.md](./Azure-Credential-Setup-Guide.md) |
| **Google Cloud Platform (GCP)** | [GCP-Credential-Setup-Guide.md](./GCP-Credential-Setup-Guide.md) |
| **Kubernetes** | [Kubernetes-Credential-Setup-Guide.md](./Kubernetes-Credential-Setup-Guide.md) |

---

## Quick Reference: What You'll Need

### AWS
- IAM User with `SecurityAudit` policy
- Access Key ID and Secret Access Key

### Azure (4 authentication methods)
- **Service Principal** — Tenant ID, Client ID, Client Secret (best for CI/CD and automation)
- **Azure CLI** — Reuses existing `az login` session (best for developers)
- **Username/Password** — Azure AD email and password, no MFA support (best for testing)
- **Device Code** — Browser-based approval, supports MFA (best for interactive use)
- All methods require `Reader` and `Security Reader` roles

### GCP
- Service Account with `Viewer` role
- JSON key file

### Kubernetes
- Kubeconfig file with read-only cluster access
- Service Account with `view` ClusterRole (or custom)

---

## Security Notes

1. **Read-Only Access**: All guides configure read-only permissions. Nubicustos cannot modify your infrastructure.

2. **Dedicated Credentials**: Always create dedicated credentials for scanning. Never share credentials with other applications.

3. **Secure Transmission**: Never send credentials via email or unsecured channels.

4. **Regular Rotation**: Rotate credentials according to your security policy (recommended: 90 days for production).

---

## Need Help?

If you encounter issues during setup, please contact your Nubicustos administrator with:
- The specific error message
- The cloud provider and step where the error occurred
- Your account/project/subscription ID (never share secrets)
