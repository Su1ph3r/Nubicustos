# Azure Credential Setup Guide for Nubicustos Security Scanning

This guide covers all four Azure authentication methods supported by Nubicustos. Choose the method that fits your environment and security requirements.

---

## Table of Contents

1. [Overview](#overview)
2. [Method 1: Service Principal](#method-1-service-principal)
3. [Method 2: Azure CLI](#method-2-azure-cli)
4. [Method 3: Username/Password](#method-3-usernamepassword)
5. [Method 4: Device Code](#method-4-device-code)
6. [Using Credentials in Nubicustos](#using-credentials-in-nubicustos)
7. [Required Permissions](#required-permissions)
8. [Security Best Practices](#security-best-practices)
9. [Troubleshooting](#troubleshooting)

---

## Overview

Nubicustos supports four authentication methods for Azure security scanning. Each method has different trade-offs in terms of setup complexity, MFA support, and use case.

| Method | Best For | MFA Support | Required Inputs | Setup Effort |
|--------|----------|-------------|-----------------|--------------|
| **Service Principal** | CI/CD, automated scans | N/A (non-interactive) | Tenant ID, Client ID, Client Secret | Medium |
| **Azure CLI** | Developers with existing `az login` | Yes (via CLI) | Host Azure CLI path | Low |
| **Username/Password** | Simple setups without MFA | No | Email, Password | Low |
| **Device Code** | Accounts with MFA, shared machines | Yes | Browser-based approval | Low |

**Note:** If no Subscription ID is provided for any method, Nubicustos will scan all subscriptions accessible to the authenticated identity.

---

## Method 1: Service Principal

Service Principal authentication uses an Azure AD application registration with a client secret. This is the recommended method for automated or unattended scanning.

### When to Use

- Automated/scheduled security scans
- CI/CD pipeline integration
- Dedicated scan service accounts
- Environments where interactive login is not possible

### Option A: Azure Portal Setup

#### Step 1: Sign in to Azure Portal

1. Navigate to [https://portal.azure.com/](https://portal.azure.com/)
2. Sign in with an account that has the following permissions:
   - Azure AD: Application Administrator or Global Administrator
   - Subscription: Owner or User Access Administrator

#### Step 2: Note Your Tenant ID

1. In the search bar, type **Microsoft Entra ID** (formerly Azure Active Directory)
2. Click on **Microsoft Entra ID**
3. On the Overview page, locate and copy the **Tenant ID**
4. Save this value securely

#### Step 3: Register a New Application

1. In Microsoft Entra ID, click **App registrations** in the left sidebar
2. Click **+ New registration**
3. Fill in the registration form:
   - **Name:** `Nubicustos Security Scanner`
   - **Supported account types:** Select "Accounts in this organizational directory only"
   - **Redirect URI:** Leave blank (not required)
4. Click **Register**

#### Step 4: Note the Client ID

1. After registration, you'll be on the application's Overview page
2. Copy the **Application (client) ID**
3. Save this value securely — this is your **Client ID**

#### Step 5: Create a Client Secret

1. In the left sidebar, click **Certificates & secrets**
2. Click **+ New client secret**
3. Fill in the form:
   - **Description:** `Nubicustos Scanner Secret`
   - **Expires:** Select an appropriate expiration (recommended: 12 months or 24 months)
4. Click **Add**
5. **IMPORTANT:** Immediately copy the **Value** column (not the Secret ID)
6. Save this value securely — this is your **Client Secret**

**Warning:** The secret value is only shown once. If you navigate away without copying it, you'll need to create a new secret.

#### Step 6: Note Your Subscription ID

1. In the Azure portal search bar, type **Subscriptions**
2. Click on **Subscriptions**
3. Click on the subscription you want to scan
4. Copy the **Subscription ID**
5. Save this value securely

#### Step 7: Assign Roles to the Service Principal

##### Assign Reader Role

1. In the Subscription page, click **Access control (IAM)** in the left sidebar
2. Click **+ Add** → **Add role assignment**
3. In the Role tab, search for and select **Reader**
4. Click **Next**
5. In the Members tab:
   - Select **User, group, or service principal**
   - Click **+ Select members**
   - Search for `Nubicustos Security Scanner`
   - Select the application and click **Select**
6. Click **Review + assign**
7. Click **Review + assign** again to confirm

##### Assign Security Reader Role (Recommended)

1. Repeat steps 1-7 above, but select **Security Reader** instead of Reader

#### Step 8: (Optional) Grant Azure AD Permissions

For comprehensive identity scanning:

1. Go back to **Microsoft Entra ID** → **App registrations**
2. Click on **Nubicustos Security Scanner**
3. Click **API permissions** in the left sidebar
4. Click **+ Add a permission**
5. Select **Microsoft Graph**
6. Select **Application permissions**
7. Search for and add:
   - `Directory.Read.All`
   - `User.Read.All`
   - `Group.Read.All`
8. Click **Add permissions**
9. Click **Grant admin consent for [Your Organization]**
10. Click **Yes** to confirm

### Option B: Azure CLI Setup

#### Prerequisites

- Azure CLI installed ([Installation Guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli))
- Logged in with appropriate permissions

#### Step 1: Login to Azure

```bash
az login
```

#### Step 2: Get Tenant ID and Subscription ID

```bash
az account show --query '{tenantId:tenantId, subscriptionId:id, subscriptionName:name}' -o table
```

#### Step 3: Create the Service Principal

```bash
az ad sp create-for-rbac \
    --name "Nubicustos Security Scanner" \
    --role "Reader" \
    --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID"
```

Output:
```json
{
    "appId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "displayName": "Nubicustos Security Scanner",
    "password": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "tenant": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

**Save these values:**
- `appId` → **Client ID**
- `password` → **Client Secret** (shown only once!)
- `tenant` → **Tenant ID**

#### Step 4: Add Security Reader Role

```bash
az role assignment create \
    --assignee "CLIENT_ID_FROM_STEP_3" \
    --role "Security Reader" \
    --scope "/subscriptions/YOUR_SUBSCRIPTION_ID"
```

#### Step 5: (Optional) Grant Azure AD Permissions

```bash
# Grant Directory.Read.All
az ad app permission add \
    --id "CLIENT_ID" \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role

# Grant User.Read.All
az ad app permission add \
    --id "CLIENT_ID" \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions df021288-bdef-4463-88db-98f22de89214=Role

# Grant Group.Read.All
az ad app permission add \
    --id "CLIENT_ID" \
    --api 00000003-0000-0000-c000-000000000000 \
    --api-permissions 5b567255-7703-4780-807c-7be8301ae99b=Role

# Grant admin consent (requires Global Administrator)
az ad app permission admin-consent --id "CLIENT_ID"
```

### Enter Credentials in Nubicustos

1. In the Nubicustos UI, go to **Credential Verification**
2. Select the **Azure** tab
3. Select **Service Principal** as the authentication method
4. Enter:
   - **Tenant ID** (required)
   - **Client/App ID** (required)
   - **Client Secret** (required)
   - **Subscription ID** (optional — leave blank to scan all accessible subscriptions)
5. Click **Verify Credentials**

---

## Method 2: Azure CLI

Azure CLI authentication reuses an existing `az login` session from your host machine. Nubicustos mounts your local Azure CLI configuration directory into its container.

### When to Use

- You already have Azure CLI installed and authenticated
- You want the simplest setup with no extra credentials to manage
- Your `az login` session supports MFA (it does by default)

### Prerequisites

1. **Azure CLI installed** on the host machine ([Installation Guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli))
2. **Logged in** via `az login` on the host machine

```bash
az login
```

This opens a browser for authentication. Complete the sign-in process.

3. **Verify** your login:

```bash
az account show --query '{tenantId:tenantId, subscriptionId:id, name:name}' -o table
```

### Configure Nubicustos

Set the `HOST_AZURE_CLI_PATH` environment variable in your `.env` file to point to your local Azure CLI configuration directory:

```env
# Point to your local Azure CLI config directory
# macOS/Linux: typically ~/.azure
# Windows: typically C:\Users\<username>\.azure
HOST_AZURE_CLI_PATH=/Users/yourname/.azure
```

This directory is mounted read-only into the Nubicustos API container at `/root/.azure`.

After setting this variable, restart the API container:

```bash
docker compose up -d api
```

### Enter Credentials in Nubicustos

1. In the Nubicustos UI, go to **Credential Verification**
2. Select the **Azure** tab
3. Select **Azure CLI** as the authentication method
4. Optionally enter a **Subscription ID** to scope the scan
5. Click **Verify Credentials**

The UI displays a note: *"Requires prior `az login` on the host machine. Set `HOST_AZURE_CLI_PATH` in your `.env` file."*

---

## Method 3: Username/Password

Username/Password authentication (Resource Owner Password Credential / ROPC) lets you authenticate directly with an Azure AD email and password.

### When to Use

- Simple environments without MFA requirements
- Testing and development
- Accounts that do not have MFA enabled

### Limitations

- **Does not work with MFA-enabled accounts.** If your account requires MFA, use [Device Code](#method-4-device-code) authentication instead.
- **Does not work if ROPC is disabled** in your Azure AD tenant (error `AADSTS7000218`). Your Azure AD administrator may need to enable it.
- Not recommended for production environments — use Service Principal or Device Code instead.

### Enter Credentials in Nubicustos

1. In the Nubicustos UI, go to **Credential Verification**
2. Select the **Azure** tab
3. Select **Username/Password** as the authentication method
4. The UI displays a warning: *"Does not work with MFA-enabled accounts. If your account requires MFA, use Device Code authentication instead."*
5. Enter:
   - **Username (Email)** (required) — your Azure AD email address
   - **Password** (required) — your Azure AD password
   - **Tenant ID** (optional — defaults to "organizations" if not specified)
   - **Subscription ID** (optional)
6. Click **Verify Credentials**

---

## Method 4: Device Code

Device Code authentication uses a browser-based flow where you approve the login on a separate device or browser. This is the recommended method for accounts with MFA enabled.

### When to Use

- Accounts with MFA enabled
- Environments where you cannot enter a password directly (shared machines, restricted terminals)
- When Username/Password auth fails due to MFA requirements

### How It Works

The device code flow works in three stages:

1. **Initiate** — Nubicustos requests a device code from Azure AD
2. **Authenticate** — You open a URL in your browser, enter the code, and approve the sign-in (including MFA if required)
3. **Complete** — Nubicustos detects your approval and retrieves the authentication tokens

The device code expires after **15 minutes**. If it expires, you can retry.

### Step-by-Step Walkthrough

1. In the Nubicustos UI, go to **Credential Verification**
2. Select the **Azure** tab
3. Select **Device Code** as the authentication method
4. The UI displays a note: *"Opens a browser-based authentication flow. Supports MFA-enabled accounts."*
5. Click **Start Authentication**
6. The UI displays:
   - A **verification URL** (typically `https://microsoft.com/devicelogin`)
   - A **device code** (e.g., `ABC-DEFG-HIJK`)
   - A **Copy** button to copy the code to your clipboard
7. Open the verification URL in your browser (on any device)
8. Enter the device code when prompted
9. Sign in with your Azure AD account and complete MFA if required
10. Approve the authentication request
11. Back in Nubicustos, the UI automatically detects the successful authentication and displays:
    - Your identity
    - Accessible subscriptions
    - A success message
12. Optionally enter a **Subscription ID** to scope the scan
13. Save as a profile (see [Using Credentials in Nubicustos](#using-credentials-in-nubicustos))

**Note:** The Nubicustos UI polls every 5 seconds to check if you've completed authentication. There is no need to click anything — it updates automatically.

---

## Using Credentials in Nubicustos

After verifying credentials with any of the four methods, you can save them as a **profile** for reuse across scans.

### Verifying Credentials

All methods (except Device Code, which has its own button) use the **Verify Credentials** button. On success, the UI shows:

- **Identity** — the authenticated user or service principal
- **Account info** — tenant details
- **Permissions** — accessible subscriptions and roles
- **Raw output** — full verification output for debugging

### Saving as a Profile

After successful verification:

1. A **Save as Profile** section appears below the verification results
2. Nubicustos auto-generates a profile name based on your identity (e.g., subscription name or username)
3. Edit the profile name if desired
4. Click **Save as Profile**
5. The profile appears in the **Azure Profiles** section at the top of the page

### Using Profiles for Scans

Saved profiles appear as clickable cards at the top of the Azure credentials page:

1. Click a profile card to select it — Nubicustos re-verifies the credentials
2. Once verified, the profile shows a green checkmark and a confirmation message: *"Profile [name] is ready for scans"*
3. Navigate to the **Scans** page to create a new scan using the selected profile
4. To deselect, click **Clear**

### Managing Profiles

- **Delete** — hover over a profile card and click the trash icon
- **Re-verify** — click the profile card to re-check that credentials are still valid

---

## Required Permissions

### Azure RBAC Roles

The authenticated identity (service principal, CLI user, or personal account) requires the following roles:

| Role | Purpose | Required |
|------|---------|----------|
| **Reader** | Read access to all Azure resources | Yes |
| **Security Reader** | Read access to Azure Security Center | Recommended |

### Azure AD Graph Permissions (Optional)

For comprehensive identity scanning, request these API permissions:

| Permission | Type | Purpose |
|------------|------|---------|
| `Directory.Read.All` | Application | Read Azure AD directory data |
| `User.Read.All` | Application | Read user profiles |
| `Group.Read.All` | Application | Read group memberships |

**Note:** Azure AD Graph permissions are primarily relevant for Service Principal auth. CLI, Username/Password, and Device Code methods inherit the permissions of the signed-in user's Azure AD roles.

---

## Security Best Practices

### General

1. **Use read-only permissions** — Only grant Reader and Security Reader roles. Never grant write or contributor permissions for scanning.
2. **Scope to specific subscriptions** — Instead of tenant-wide access, scope credentials to only the subscriptions that need scanning.
3. **Use dedicated credentials** — Create credentials specifically for Nubicustos. Do not share credentials with other applications.

### Service Principal

4. **Set appropriate secret expiration** — Production: 12-24 months. Development: 6 months. Set calendar reminders to rotate before expiration.
5. **Rotate secrets regularly:**

```bash
# Create a new secret
az ad app credential reset --id "CLIENT_ID" --append

# Update Nubicustos with new secret

# Remove old secret
az ad app credential list --id "CLIENT_ID"
az ad app credential delete --id "CLIENT_ID" --key-id "OLD_CREDENTIAL_ID"
```

6. **Monitor service principal activity** — Enable Azure AD sign-in logs to audit service principal access (Microsoft Entra ID → Sign-in logs → filter by Service Principal).
7. **Use Conditional Access (Advanced)** — Restrict service principal access by IP address using Conditional Access policies.

### Azure CLI

8. **Keep your CLI session current** — Run `az login` periodically to refresh tokens. Expired CLI sessions will cause scan failures.
9. **The CLI config is mounted read-only** — Nubicustos cannot modify your local Azure CLI configuration.

### Username/Password

10. **Avoid in production** — Use Service Principal or Device Code for production environments. Username/Password is best for development and testing.
11. **Never use with shared or admin accounts** — Only use with dedicated, least-privilege accounts.

### Device Code

12. **Sessions expire after 24 hours** — Device code sessions are cached in-memory and auto-cleaned. Re-authenticate if scans fail after extended periods.
13. **Approve only expected codes** — Always verify the device code displayed in Nubicustos matches the code you enter at `microsoft.com/devicelogin`.

---

## Troubleshooting

### Service Principal Errors

#### "AADSTS7000215: Invalid client secret"
- The client secret has expired or is incorrect
- Create a new client secret in the Azure portal

#### "AADSTS700016: Application not found"
- The Client ID is incorrect
- Verify the Application ID in App registrations

#### "Authorization failed"
- The service principal lacks required roles
- Verify Reader role is assigned at the subscription level

### Azure CLI Errors

#### "Azure CLI credentials not available"
- `HOST_AZURE_CLI_PATH` is not set or points to an invalid directory
- Run `az login` on the host machine and verify the path exists
- Restart the API container after updating `.env`

#### "Azure CLI token expired"
- Run `az login` again on the host machine to refresh the session

### Username/Password Errors

#### "AADSTS50076" or "AADSTS50079" (MFA Required)
- Your account has MFA enabled — Username/Password auth does not support MFA
- Switch to **Device Code** authentication instead

#### "AADSTS7000218" (ROPC Disabled)
- Resource Owner Password Credential flow is disabled in your tenant
- Your Azure AD administrator needs to enable it, or use a different auth method

### Device Code Errors

#### "Code expired. Please try again."
- The device code was not entered within 15 minutes
- Click **Retry** and complete the flow more quickly

#### "Authentication was declined."
- The sign-in was rejected or cancelled in the browser
- Click **Retry** and approve the sign-in request

### General Errors

#### "The subscription is not registered"
- The subscription may be disabled
- Check subscription status in the Azure portal

### Diagnostic Commands

```bash
# Check role assignments for a service principal
az role assignment list --assignee "CLIENT_ID" --all -o table

# Get service principal details
az ad sp show --id "CLIENT_ID"

# Verify secret expiration
az ad app credential list --id "CLIENT_ID" --query '[].{keyId:keyId, endDateTime:endDateTime}' -o table

# List accessible subscriptions (CLI auth)
az account list --query '[].{name:name, id:id, state:state}' -o table
```

---

## Multi-Subscription Setup

To scan multiple subscriptions with Service Principal auth, assign roles to each subscription:

### List All Subscriptions

```bash
az account list --query '[].{name:name, id:id, state:state}' -o table
```

### Assign Roles to Multiple Subscriptions

```bash
# For each subscription you want to scan:
az role assignment create \
    --assignee "CLIENT_ID" \
    --role "Reader" \
    --scope "/subscriptions/SUBSCRIPTION_ID_1"

az role assignment create \
    --assignee "CLIENT_ID" \
    --role "Reader" \
    --scope "/subscriptions/SUBSCRIPTION_ID_2"

# Repeat for Security Reader if needed
```

For CLI, Username/Password, and Device Code methods, the authenticated user automatically has access to all subscriptions their Azure AD account can reach. No additional role assignment is needed beyond what the user already has.

---

## Quick Reference Commands

```bash
# Get all required information at once
echo "=== Tenant ID ==="
az account show --query tenantId -o tsv

echo "=== Subscription ID ==="
az account show --query id -o tsv

echo "=== Create Service Principal (save output!) ==="
az ad sp create-for-rbac --name "Nubicustos Security Scanner" --role "Reader" --scopes "/subscriptions/$(az account show --query id -o tsv)"

echo "=== Add Security Reader Role ==="
# Run after creating the service principal with the appId from above
# az role assignment create --assignee "APP_ID" --role "Security Reader" --scope "/subscriptions/$(az account show --query id -o tsv)"
```

---

## Support

If you encounter issues during setup, please contact your Nubicustos administrator with:
1. The specific error message
2. The authentication method you are using
3. The step where the error occurred
4. Your Tenant ID and Subscription ID (not your credentials)
