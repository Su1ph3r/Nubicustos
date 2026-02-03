# GCP Credential Setup Guide for Nubicustos Security Scanning

This guide provides step-by-step instructions for creating Google Cloud Platform (GCP) credentials that allow Nubicustos to perform security scans on your GCP environment.

---

## Table of Contents

1. [Overview](#overview)
2. [Required Permissions](#required-permissions)
3. [Option A: GCP Console (Portal) Setup](#option-a-gcp-console-portal-setup)
4. [Option B: gcloud CLI Setup](#option-b-gcloud-cli-setup)
5. [Verification](#verification)
6. [Multi-Project Setup](#multi-project-setup)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

Nubicustos requires **Service Account** authentication to perform security assessments on your GCP environment. The scanner uses:

| Credential | Description | Required |
|------------|-------------|----------|
| Project ID | Your GCP project identifier | Yes |
| Service Account JSON Key | Full JSON key file content | Yes |

The service account key is a JSON file that contains all necessary authentication information including the private key.

---

## Required Permissions

### Predefined IAM Roles

The service account requires the following predefined roles:

| Role | Purpose | Required |
|------|---------|----------|
| **roles/viewer** | Read access to all GCP resources | Yes |
| **roles/iam.securityReviewer** | Read IAM policies and service accounts | Recommended |
| **roles/cloudasset.viewer** | Read Cloud Asset Inventory | Recommended |

### Key Permissions Granted

These roles provide access to:
- Compute Engine instances, networks, and firewalls
- Cloud Storage buckets and configurations
- IAM policies, roles, and service accounts
- Cloud SQL databases
- Cloud KMS keys
- Kubernetes Engine clusters
- Cloud Functions
- BigQuery datasets
- Logging and monitoring configurations
- And more security-relevant resources

**Note:** These roles are read-only and cannot make changes to your GCP environment.

---

## Option A: GCP Console (Portal) Setup

### Step 1: Sign in to GCP Console

1. Navigate to [https://console.cloud.google.com/](https://console.cloud.google.com/)
2. Sign in with an account that has:
   - `roles/iam.serviceAccountAdmin` (to create service accounts)
   - `roles/iam.serviceAccountKeyAdmin` (to create keys)
   - `roles/resourcemanager.projectIamAdmin` (to assign roles)

### Step 2: Select Your Project

1. Click the project dropdown at the top of the page
2. Select the project you want to scan
3. Note the **Project ID** (not the project name)

### Step 3: Navigate to Service Accounts

1. In the left navigation menu, click **IAM & Admin**
2. Click **Service Accounts**

### Step 4: Create a New Service Account

1. Click **+ CREATE SERVICE ACCOUNT** at the top
2. Fill in the service account details:
   - **Service account name:** `nubicustos-scanner`
   - **Service account ID:** `nubicustos-scanner` (auto-generated)
   - **Description:** `Service account for Nubicustos security scanning`
3. Click **CREATE AND CONTINUE**

### Step 5: Grant Roles to the Service Account

1. In the "Grant this service account access to project" section:
2. Click **+ ADD ANOTHER ROLE** and add each of these roles:
   - `Viewer` (under Basic)
   - `Security Reviewer` (under IAM)
   - `Cloud Asset Viewer` (under Cloud Asset)
3. Click **CONTINUE**
4. Skip the "Grant users access to this service account" section
5. Click **DONE**

### Step 6: Create a JSON Key

1. In the Service Accounts list, find `nubicustos-scanner`
2. Click on the service account email
3. Go to the **KEYS** tab
4. Click **ADD KEY** → **Create new key**
5. Select **JSON** format
6. Click **CREATE**
7. The key file will automatically download to your computer

**IMPORTANT:**
- Save this JSON file securely
- This is the only time you can download this key
- If lost, you must create a new key

### Step 7: Note Your Project ID

1. Click on the project dropdown at the top
2. Copy the **Project ID** (shown below the project name)
3. Or find it in the JSON key file under `project_id`

---

## Option B: gcloud CLI Setup

### Prerequisites

- gcloud CLI installed ([Installation Guide](https://cloud.google.com/sdk/docs/install))
- Logged in with appropriate permissions

### Step 1: Login to GCP

```bash
gcloud auth login
```

This will open a browser for authentication. Complete the sign-in process.

### Step 2: Set Your Project

```bash
# List available projects
gcloud projects list

# Set the active project
gcloud config set project YOUR_PROJECT_ID

# Verify the project is set
gcloud config get-value project
```

### Step 3: Create the Service Account

```bash
gcloud iam service-accounts create nubicustos-scanner \
    --display-name="Nubicustos Security Scanner" \
    --description="Service account for Nubicustos security scanning"
```

### Step 4: Get the Service Account Email

```bash
# The email format is: SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com
SERVICE_ACCOUNT_EMAIL="nubicustos-scanner@$(gcloud config get-value project).iam.gserviceaccount.com"
echo $SERVICE_ACCOUNT_EMAIL
```

### Step 5: Grant Required Roles

```bash
PROJECT_ID=$(gcloud config get-value project)
SERVICE_ACCOUNT_EMAIL="nubicustos-scanner@${PROJECT_ID}.iam.gserviceaccount.com"

# Grant Viewer role
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/viewer"

# Grant Security Reviewer role
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/iam.securityReviewer"

# Grant Cloud Asset Viewer role
gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/cloudasset.viewer"
```

### Step 6: Create and Download the JSON Key

```bash
# Create the key and save it to a file
gcloud iam service-accounts keys create nubicustos-scanner-key.json \
    --iam-account="${SERVICE_ACCOUNT_EMAIL}"
```

Output:
```
created key [abc123...] of type [json] as [nubicustos-scanner-key.json] for [nubicustos-scanner@project-id.iam.gserviceaccount.com]
```

**IMPORTANT:** The `nubicustos-scanner-key.json` file is now in your current directory. Keep it secure!

### Step 7: Verify the Setup

```bash
# List service account keys
gcloud iam service-accounts keys list \
    --iam-account="${SERVICE_ACCOUNT_EMAIL}"

# View assigned roles
gcloud projects get-iam-policy $PROJECT_ID \
    --flatten="bindings[].members" \
    --filter="bindings.members:${SERVICE_ACCOUNT_EMAIL}" \
    --format="table(bindings.role)"
```

Expected output:
```
ROLE
roles/cloudasset.viewer
roles/iam.securityReviewer
roles/viewer
```

---

## Verification

### Test the Service Account Credentials

```bash
# Activate the service account
gcloud auth activate-service-account --key-file=nubicustos-scanner-key.json

# Verify the identity
gcloud auth list

# Test read access
gcloud compute instances list --limit=1
gcloud storage buckets list --limit=1
gcloud iam service-accounts list --limit=1

# Switch back to your user account
gcloud auth login
```

### Verify Using Service Account Impersonation

Without switching accounts:
```bash
# List VMs using the service account
gcloud compute instances list \
    --impersonate-service-account="${SERVICE_ACCOUNT_EMAIL}" \
    --limit=1

# List Cloud Storage buckets
gcloud storage buckets list \
    --impersonate-service-account="${SERVICE_ACCOUNT_EMAIL}" \
    --limit=1
```

---

## Multi-Project Setup

To scan multiple projects with a single service account:

### Option 1: Grant Roles in Each Project

```bash
# For each additional project
gcloud projects add-iam-policy-binding OTHER_PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/viewer"

gcloud projects add-iam-policy-binding OTHER_PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/iam.securityReviewer"

gcloud projects add-iam-policy-binding OTHER_PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/cloudasset.viewer"
```

### Option 2: Organization-Level Roles (If You Have Organization Admin)

```bash
ORGANIZATION_ID="123456789"  # Your organization ID

gcloud organizations add-iam-policy-binding $ORGANIZATION_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/viewer"
```

### List All Accessible Projects

```bash
gcloud projects list \
    --impersonate-service-account="${SERVICE_ACCOUNT_EMAIL}"
```

---

## Security Best Practices

### 1. Use Minimal Permissions
Only grant the roles listed above. Avoid granting Editor or Owner roles.

### 2. Secure the JSON Key File
- Never commit the key file to version control
- Store in a secure location with restricted access
- Consider using a secrets manager

### 3. Enable Audit Logging
Ensure Cloud Audit Logs are enabled to track service account activity:
```bash
gcloud projects get-iam-policy $PROJECT_ID --format=json | jq '.auditConfigs'
```

### 4. Set Key Expiration (Organizational Policy)
If your organization supports it, enforce key expiration policies.

### 5. Rotate Keys Regularly

```bash
# Create a new key
gcloud iam service-accounts keys create new-key.json \
    --iam-account="${SERVICE_ACCOUNT_EMAIL}"

# Update Nubicustos with new key

# Delete the old key
gcloud iam service-accounts keys list \
    --iam-account="${SERVICE_ACCOUNT_EMAIL}" \
    --format="value(name)"

gcloud iam service-accounts keys delete KEY_ID \
    --iam-account="${SERVICE_ACCOUNT_EMAIL}"
```

### 6. Monitor for Anomalies
Set up alerts in Cloud Monitoring for unusual service account activity.

### 7. Use Workload Identity (Advanced)
For GKE-based deployments, consider using Workload Identity instead of JSON keys.

---

## Troubleshooting

### Error: "Permission denied" or "403"
- Verify all required roles are assigned
- Check if there are organization policies restricting access
- Ensure the service account key is valid

### Error: "Service account not found"
- Verify the service account email is correct
- Check if the service account was deleted

### Error: "Invalid key"
- The JSON key may be corrupted or incomplete
- Create a new key and try again

### Error: "Quota exceeded"
- Your project may have API quotas
- Check quotas in the GCP Console under IAM & Admin → Quotas

### Check Service Account Status

```bash
# List all service accounts
gcloud iam service-accounts list

# Describe the specific service account
gcloud iam service-accounts describe ${SERVICE_ACCOUNT_EMAIL}

# List keys for the service account
gcloud iam service-accounts keys list \
    --iam-account="${SERVICE_ACCOUNT_EMAIL}" \
    --format="table(name,validAfterTime,validBeforeTime)"
```

### Verify API Is Enabled

Some APIs need to be enabled for scanning:
```bash
# Check if required APIs are enabled
gcloud services list --enabled --filter="name:(compute.googleapis.com OR storage.googleapis.com OR iam.googleapis.com)"

# Enable APIs if needed
gcloud services enable compute.googleapis.com
gcloud services enable storage.googleapis.com
gcloud services enable cloudasset.googleapis.com
```

---

## Information to Provide to Nubicustos

After completing the setup, provide the following:

| Field | Description |
|-------|-------------|
| Project ID | Your GCP project ID (e.g., `my-project-123456`) |
| Service Account JSON | The complete contents of the JSON key file |

### JSON Key File Structure

The JSON key file should look like this:
```json
{
  "type": "service_account",
  "project_id": "your-project-id",
  "private_key_id": "key-id",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "client_email": "nubicustos-scanner@your-project-id.iam.gserviceaccount.com",
  "client_id": "123456789",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/..."
}
```

**Note:** Never share credentials via email or unsecured channels. Use a secure credential sharing method.

---

## Cleanup (If Needed)

To remove the service account and all associated resources:

```bash
PROJECT_ID=$(gcloud config get-value project)
SERVICE_ACCOUNT_EMAIL="nubicustos-scanner@${PROJECT_ID}.iam.gserviceaccount.com"

# Remove role bindings
gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/viewer"

gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/iam.securityReviewer"

gcloud projects remove-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
    --role="roles/cloudasset.viewer"

# Delete the service account (also deletes all keys)
gcloud iam service-accounts delete ${SERVICE_ACCOUNT_EMAIL}

# Delete the local key file
rm nubicustos-scanner-key.json
```

---

## Quick Reference Commands

```bash
# Complete setup script
PROJECT_ID=$(gcloud config get-value project)
SERVICE_ACCOUNT_EMAIL="nubicustos-scanner@${PROJECT_ID}.iam.gserviceaccount.com"

# Create service account
gcloud iam service-accounts create nubicustos-scanner \
    --display-name="Nubicustos Security Scanner"

# Assign roles
for role in "roles/viewer" "roles/iam.securityReviewer" "roles/cloudasset.viewer"; do
    gcloud projects add-iam-policy-binding $PROJECT_ID \
        --member="serviceAccount:${SERVICE_ACCOUNT_EMAIL}" \
        --role="$role"
done

# Create key
gcloud iam service-accounts keys create nubicustos-scanner-key.json \
    --iam-account="${SERVICE_ACCOUNT_EMAIL}"

echo "=== Setup Complete ==="
echo "Project ID: $PROJECT_ID"
echo "Service Account: $SERVICE_ACCOUNT_EMAIL"
echo "Key File: nubicustos-scanner-key.json"
```

---

## Support

If you encounter issues during setup, please contact your Nubicustos administrator with:
1. The specific error message
2. The step where the error occurred
3. Your Project ID (not your credentials)
