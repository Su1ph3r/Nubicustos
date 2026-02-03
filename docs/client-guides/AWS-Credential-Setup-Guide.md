# AWS Credential Setup Guide for Nubicustos Security Scanning

This guide provides step-by-step instructions for creating AWS credentials that allow Nubicustos to perform security scans on your AWS environment.

---

## Table of Contents

1. [Overview](#overview)
2. [Required Permissions](#required-permissions)
3. [Option A: AWS Console (Portal) Setup](#option-a-aws-console-portal-setup)
4. [Option B: AWS CLI Setup](#option-b-aws-cli-setup)
5. [Verification](#verification)
6. [Security Best Practices](#security-best-practices)
7. [Troubleshooting](#troubleshooting)

---

## Overview

Nubicustos requires **read-only** access to your AWS account to perform security assessments. The scanner uses the following credentials:

| Credential | Description | Required |
|------------|-------------|----------|
| Access Key ID | Identifies the IAM user or role | Yes |
| Secret Access Key | Authentication secret | Yes |
| Session Token | For temporary credentials (STS) | Optional |
| Region | Default AWS region | Optional (defaults to us-east-1) |

---

## Required Permissions

Nubicustos requires the following AWS managed policies attached to the IAM user or role:

### Minimum Required Policy
- **SecurityAudit** (`arn:aws:iam::aws:policy/SecurityAudit`)

### Recommended for Comprehensive Scans
- **SecurityAudit** (`arn:aws:iam::aws:policy/SecurityAudit`)
- **ReadOnlyAccess** (`arn:aws:iam::aws:policy/ReadOnlyAccess`)

### What These Policies Allow

The `SecurityAudit` policy provides read access to:
- IAM users, roles, policies, and permissions
- EC2 instances, security groups, and VPCs
- S3 bucket configurations and policies
- CloudTrail logs and configurations
- RDS database configurations
- Lambda functions and configurations
- Secrets Manager metadata (not secret values)
- And many more security-relevant resources

**Note:** These policies are read-only and cannot make changes to your AWS environment.

---

## Option A: AWS Console (Portal) Setup

### Step 1: Sign in to AWS Console

1. Navigate to [https://console.aws.amazon.com/](https://console.aws.amazon.com/)
2. Sign in with an account that has IAM administrative permissions

### Step 2: Navigate to IAM

1. In the search bar at the top, type **IAM**
2. Click on **IAM** under Services

### Step 3: Create a New IAM User

1. In the left sidebar, click **Users**
2. Click the **Create user** button
3. Enter a user name: `nubicustos-scanner`
4. Click **Next**

### Step 4: Set Permissions

1. Select **Attach policies directly**
2. In the search box, search for and select:
   - `SecurityAudit`
   - `ReadOnlyAccess` (optional, for comprehensive scans)
3. Click **Next**
4. Review the configuration
5. Click **Create user**

### Step 5: Create Access Keys

1. Click on the newly created user `nubicustos-scanner`
2. Go to the **Security credentials** tab
3. Scroll down to **Access keys**
4. Click **Create access key**
5. Select **Third-party service**
6. Check the confirmation box acknowledging the recommendation
7. Click **Next**
8. Add a description: `Nubicustos Security Scanner`
9. Click **Create access key**

### Step 6: Save Your Credentials

**IMPORTANT:** This is the only time you can view or download the secret access key.

1. Copy the **Access key ID** and save it securely
2. Copy the **Secret access key** and save it securely
3. Optionally, click **Download .csv file** for backup
4. Click **Done**

### Step 7: Note Your Account Information

1. Click on your account name in the top-right corner
2. Note your **Account ID** (12-digit number)

---

## Option B: AWS CLI Setup

### Prerequisites

- AWS CLI installed ([Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html))
- AWS CLI configured with administrative credentials

### Step 1: Verify AWS CLI Configuration

```bash
aws sts get-caller-identity
```

Expected output:
```json
{
    "UserId": "AIDAEXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/admin"
}
```

### Step 2: Create the IAM User

```bash
aws iam create-user --user-name nubicustos-scanner
```

### Step 3: Attach Required Policies

Attach the SecurityAudit policy:
```bash
aws iam attach-user-policy \
    --user-name nubicustos-scanner \
    --policy-arn arn:aws:iam::aws:policy/SecurityAudit
```

(Optional) Attach ReadOnlyAccess for comprehensive scans:
```bash
aws iam attach-user-policy \
    --user-name nubicustos-scanner \
    --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

### Step 4: Create Access Keys

```bash
aws iam create-access-key --user-name nubicustos-scanner
```

Output:
```json
{
    "AccessKey": {
        "UserName": "nubicustos-scanner",
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "Status": "Active",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "CreateDate": "2024-01-15T12:00:00+00:00"
    }
}
```

**IMPORTANT:** Save the `AccessKeyId` and `SecretAccessKey` immediately. The secret access key cannot be retrieved again.

### Step 5: Verify the User Setup

List attached policies:
```bash
aws iam list-attached-user-policies --user-name nubicustos-scanner
```

Expected output:
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "SecurityAudit",
            "PolicyArn": "arn:aws:iam::aws:policy/SecurityAudit"
        },
        {
            "PolicyName": "ReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"
        }
    ]
}
```

---

## Verification

### Test the Credentials

Using AWS CLI with the new credentials:

```bash
# Configure a named profile
aws configure --profile nubicustos-test

# Enter:
# AWS Access Key ID: <your-access-key-id>
# AWS Secret Access Key: <your-secret-access-key>
# Default region name: us-east-1
# Default output format: json

# Test the credentials
aws sts get-caller-identity --profile nubicustos-test
```

Expected output:
```json
{
    "UserId": "AIDAEXAMPLEID",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/nubicustos-scanner"
}
```

### Test Read Permissions

```bash
# Test EC2 access
aws ec2 describe-instances --profile nubicustos-test --query 'Reservations[0].Instances[0].InstanceId'

# Test S3 access
aws s3api list-buckets --profile nubicustos-test --query 'Buckets[0].Name'

# Test IAM access
aws iam list-users --profile nubicustos-test --query 'Users[0].UserName'
```

---

## Security Best Practices

### 1. Use Dedicated Credentials
Create a dedicated IAM user specifically for Nubicustos scanning. Do not share credentials with other applications.

### 2. Enable MFA (Recommended for Console Access)
If the IAM user needs console access, enable Multi-Factor Authentication.

### 3. Rotate Access Keys Regularly
Rotate access keys every 90 days:
```bash
# Create new access key
aws iam create-access-key --user-name nubicustos-scanner

# Update Nubicustos with new credentials

# Delete old access key
aws iam delete-access-key --user-name nubicustos-scanner --access-key-id OLD_KEY_ID
```

### 4. Use Temporary Credentials (Advanced)
For enhanced security, consider using AWS STS to generate temporary credentials:
```bash
aws sts get-session-token --duration-seconds 3600
```

### 5. Restrict by IP (Optional)
Add an IP condition to the IAM user's policy to restrict access to known IP addresses:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "NotIpAddress": {
                    "aws:SourceIp": ["YOUR.SCANNER.IP.ADDRESS/32"]
                }
            }
        }
    ]
}
```

### 6. Enable CloudTrail Logging
Ensure CloudTrail is enabled to audit all API calls made by the scanner.

---

## Troubleshooting

### Error: "Access Denied"
- Verify the SecurityAudit policy is attached
- Check if there are any Service Control Policies (SCPs) blocking access
- Ensure the credentials are correct and active

### Error: "Invalid Access Key"
- Verify the Access Key ID is correct
- Check if the access key has been deactivated or deleted

### Error: "Expired Token"
- If using temporary credentials, generate new ones
- Session tokens typically expire after 1-12 hours

### Error: "Region Not Enabled"
- Some AWS regions require explicit opt-in
- Try a different region or enable the required region in Account Settings

### Check Access Key Status
```bash
aws iam list-access-keys --user-name nubicustos-scanner
```

---

## Information to Provide to Nubicustos

After completing the setup, provide the following to Nubicustos:

| Field | Value |
|-------|-------|
| AWS Access Key ID | `AKIA...` (20 characters) |
| AWS Secret Access Key | `wJal...` (40 characters) |
| AWS Region | `us-east-1` (or your preferred region) |
| AWS Account ID | `123456789012` (12 digits) |

**Note:** Never share credentials via email or unsecured channels. Use a secure credential sharing method.

---

## Cleanup (If Needed)

To remove the IAM user and credentials:

```bash
# Delete access keys
aws iam list-access-keys --user-name nubicustos-scanner --query 'AccessKeyMetadata[].AccessKeyId' --output text | \
    xargs -I {} aws iam delete-access-key --user-name nubicustos-scanner --access-key-id {}

# Detach policies
aws iam detach-user-policy --user-name nubicustos-scanner --policy-arn arn:aws:iam::aws:policy/SecurityAudit
aws iam detach-user-policy --user-name nubicustos-scanner --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Delete user
aws iam delete-user --user-name nubicustos-scanner
```

---

## Support

If you encounter issues during setup, please contact your Nubicustos administrator with:
1. The specific error message
2. The step where the error occurred
3. Your AWS account ID (not your credentials)
