# Azure Credential Setup Guide for Nubicustos Security Scanning

This guide provides step-by-step instructions for creating Azure credentials that allow Nubicustos to perform security scans on your Azure environment.

---

## Table of Contents

1. [Overview](#overview)
2. [Required Permissions](#required-permissions)
3. [Option A: Azure Portal Setup](#option-a-azure-portal-setup)
4. [Option B: Azure CLI Setup](#option-b-azure-cli-setup)
5. [Verification](#verification)
6. [Multi-Subscription Setup](#multi-subscription-setup)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

Nubicustos requires **Service Principal** authentication to perform security assessments on your Azure environment. The scanner uses the following credentials:

| Credential | Description | Format | Required |
|------------|-------------|--------|----------|
| Tenant ID | Your Azure AD tenant identifier | UUID (GUID) | Yes |
| Client ID | The application (service principal) ID | UUID (GUID) | Yes |
| Client Secret | Authentication secret for the service principal | String | Yes |
| Subscription ID | Specific subscription to scan | UUID (GUID) | Optional |

**Note:** If no Subscription ID is provided, Nubicustos will scan all subscriptions accessible to the service principal.

---

## Required Permissions

### Azure RBAC Roles

The service principal requires the following roles:

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

---

## Option A: Azure Portal Setup

### Step 1: Sign in to Azure Portal

1. Navigate to [https://portal.azure.com/](https://portal.azure.com/)
2. Sign in with an account that has the following permissions:
   - Azure AD: Application Administrator or Global Administrator
   - Subscription: Owner or User Access Administrator

### Step 2: Note Your Tenant ID

1. In the search bar, type **Microsoft Entra ID** (formerly Azure Active Directory)
2. Click on **Microsoft Entra ID**
3. On the Overview page, locate and copy the **Tenant ID**
4. Save this value securely

### Step 3: Register a New Application

1. In Microsoft Entra ID, click **App registrations** in the left sidebar
2. Click **+ New registration**
3. Fill in the registration form:
   - **Name:** `Nubicustos Security Scanner`
   - **Supported account types:** Select "Accounts in this organizational directory only"
   - **Redirect URI:** Leave blank (not required)
4. Click **Register**

### Step 4: Note the Client ID

1. After registration, you'll be on the application's Overview page
2. Copy the **Application (client) ID**
3. Save this value securely - this is your **Client ID**

### Step 5: Create a Client Secret

1. In the left sidebar, click **Certificates & secrets**
2. Click **+ New client secret**
3. Fill in the form:
   - **Description:** `Nubicustos Scanner Secret`
   - **Expires:** Select an appropriate expiration (recommended: 12 months or 24 months)
4. Click **Add**
5. **IMPORTANT:** Immediately copy the **Value** column (not the Secret ID)
6. Save this value securely - this is your **Client Secret**

**Warning:** The secret value is only shown once. If you navigate away without copying it, you'll need to create a new secret.

### Step 6: Note Your Subscription ID

1. In the Azure portal search bar, type **Subscriptions**
2. Click on **Subscriptions**
3. Click on the subscription you want to scan
4. Copy the **Subscription ID**
5. Save this value securely

### Step 7: Assign Roles to the Service Principal

#### Assign Reader Role

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

#### Assign Security Reader Role (Recommended)

1. Repeat steps 1-7 above, but select **Security Reader** instead of Reader

### Step 8: (Optional) Grant Azure AD Permissions

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

---

## Option B: Azure CLI Setup

### Prerequisites

- Azure CLI installed ([Installation Guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli))
- Logged in with appropriate permissions

### Step 1: Login to Azure

```bash
az login
```

This will open a browser for authentication. Complete the sign-in process.

### Step 2: Get Tenant ID and Subscription ID

```bash
az account show --query '{tenantId:tenantId, subscriptionId:id, subscriptionName:name}' -o table
```

Output:
```
TenantId                              SubscriptionId                        SubscriptionName
------------------------------------  ------------------------------------  ------------------
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy  My Subscription
```

Save the **TenantId** and **SubscriptionId**.

### Step 3: Create the Service Principal

Create a service principal with the Reader role:

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

### Step 4: Add Security Reader Role

```bash
az role assignment create \
    --assignee "CLIENT_ID_FROM_STEP_3" \
    --role "Security Reader" \
    --scope "/subscriptions/YOUR_SUBSCRIPTION_ID"
```

### Step 5: (Optional) Grant Azure AD Permissions

Grant Microsoft Graph API permissions:

```bash
# Get the service principal object ID
SP_OBJECT_ID=$(az ad sp show --id "CLIENT_ID" --query id -o tsv)

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

---

## Verification

### Test Credentials with Azure CLI

```bash
# Login as the service principal
az login --service-principal \
    --username "CLIENT_ID" \
    --password "CLIENT_SECRET" \
    --tenant "TENANT_ID"
```

Expected output:
```json
[
    {
        "cloudName": "AzureCloud",
        "id": "subscription-id",
        "isDefault": true,
        "name": "Subscription Name",
        "state": "Enabled",
        "tenantId": "tenant-id",
        "user": {
            "name": "client-id",
            "type": "servicePrincipal"
        }
    }
]
```

### Test Resource Access

```bash
# List resource groups
az group list --query '[].name' -o tsv

# List virtual machines
az vm list --query '[].name' -o tsv

# List storage accounts
az storage account list --query '[].name' -o tsv
```

### Test Security Center Access

```bash
# List security alerts (requires Security Reader)
az security alert list --query '[0].alertDisplayName' -o tsv
```

---

## Multi-Subscription Setup

To scan multiple subscriptions, assign roles to each subscription:

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

### Verify Multi-Subscription Access

```bash
# Login as service principal
az login --service-principal -u "CLIENT_ID" -p "CLIENT_SECRET" --tenant "TENANT_ID"

# List accessible subscriptions
az account list --query '[].{name:name, id:id}' -o table
```

---

## Security Best Practices

### 1. Use Minimal Permissions
Only grant Reader and Security Reader roles. Avoid granting write or contributor permissions.

### 2. Scope to Specific Subscriptions
Instead of tenant-wide access, scope the service principal to specific subscriptions that need scanning.

### 3. Set Appropriate Secret Expiration
- Production: 12-24 months
- Development/Testing: 6 months
- Set calendar reminders to rotate before expiration

### 4. Rotate Secrets Regularly

```bash
# Create a new secret
az ad app credential reset --id "CLIENT_ID" --append

# Update Nubicustos with new secret

# Remove old secret (get credential ID first)
az ad app credential list --id "CLIENT_ID"
az ad app credential delete --id "CLIENT_ID" --key-id "OLD_CREDENTIAL_ID"
```

### 5. Monitor Service Principal Activity
Enable Azure AD sign-in logs to audit service principal access:
1. Go to Microsoft Entra ID → Sign-in logs
2. Filter by Service Principal name

### 6. Use Conditional Access (Advanced)
Restrict service principal access by IP address using Conditional Access policies.

---

## Troubleshooting

### Error: "AADSTS7000215: Invalid client secret"
- The client secret has expired or is incorrect
- Create a new client secret in the Azure portal

### Error: "AADSTS700016: Application not found"
- The Client ID is incorrect
- Verify the Application ID in App registrations

### Error: "Authorization failed"
- The service principal lacks required roles
- Verify Reader role is assigned at the subscription level

### Error: "The subscription is not registered"
- The subscription may be disabled
- Check subscription status in the Azure portal

### Check Role Assignments

```bash
# List all role assignments for the service principal
az role assignment list --assignee "CLIENT_ID" --all -o table
```

### Check Service Principal Details

```bash
# Get service principal information
az ad sp show --id "CLIENT_ID"
```

### Verify Secret Expiration

```bash
# List credentials and their expiration
az ad app credential list --id "CLIENT_ID" --query '[].{keyId:keyId, endDateTime:endDateTime}' -o table
```

---

## Information to Provide to Nubicustos

After completing the setup, provide the following credentials:

| Field | Example Format |
|-------|----------------|
| Tenant ID | `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| Client ID | `yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy` |
| Client Secret | `abc123...` (variable length string) |
| Subscription ID | `zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz` (optional) |

**Note:** Never share credentials via email or unsecured channels. Use a secure credential sharing method.

---

## Cleanup (If Needed)

To remove the service principal and all associated resources:

```bash
# Get the service principal object ID
SP_OBJECT_ID=$(az ad sp show --id "CLIENT_ID" --query id -o tsv)

# Remove role assignments
az role assignment delete --assignee "CLIENT_ID" --role "Reader"
az role assignment delete --assignee "CLIENT_ID" --role "Security Reader"

# Delete the app registration (also deletes service principal)
az ad app delete --id "CLIENT_ID"
```

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
2. The step where the error occurred
3. Your Tenant ID and Subscription ID (not your credentials)
