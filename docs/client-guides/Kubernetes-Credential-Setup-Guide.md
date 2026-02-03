# Kubernetes Credential Setup Guide for Nubicustos Security Scanning

This guide provides step-by-step instructions for creating Kubernetes credentials that allow Nubicustos to perform security scans on your Kubernetes clusters.

---

## Table of Contents

1. [Overview](#overview)
2. [Required Permissions](#required-permissions)
3. [Option A: Create Dedicated Service Account (Recommended)](#option-a-create-dedicated-service-account-recommended)
4. [Option B: Use Existing Kubeconfig](#option-b-use-existing-kubeconfig)
5. [Cloud Provider Specific Instructions](#cloud-provider-specific-instructions)
6. [Verification](#verification)
7. [Security Best Practices](#security-best-practices)
8. [Troubleshooting](#troubleshooting)

---

## Overview

Nubicustos requires **kubeconfig** file access to perform security assessments on your Kubernetes clusters. The scanner uses:

| Credential | Description | Required |
|------------|-------------|----------|
| Kubeconfig | YAML configuration file with cluster access | Yes |
| Context | Named context within kubeconfig | Optional (uses default) |

The kubeconfig file contains:
- Cluster endpoint (API server URL)
- Authentication credentials (token, certificate, or cloud provider auth)
- Namespace and context configuration

---

## Required Permissions

### RBAC Permissions Needed

Nubicustos security tools require **read-only** access to cluster resources. The service account needs the following permissions:

| Resource Group | Resources | Verbs |
|----------------|-----------|-------|
| Core (`""`) | pods, services, secrets, configmaps, namespaces, nodes, persistentvolumes, persistentvolumeclaims, serviceaccounts | get, list, watch |
| `apps` | deployments, daemonsets, replicasets, statefulsets | get, list, watch |
| `batch` | jobs, cronjobs | get, list, watch |
| `networking.k8s.io` | networkpolicies, ingresses | get, list, watch |
| `rbac.authorization.k8s.io` | roles, rolebindings, clusterroles, clusterrolebindings | get, list, watch |
| `policy` | podsecuritypolicies, poddisruptionbudgets | get, list, watch |
| `admissionregistration.k8s.io` | mutatingwebhookconfigurations, validatingwebhookconfigurations | get, list, watch |

### Pre-built ClusterRole Option

You can use the built-in `view` ClusterRole which provides read access to most resources:
```bash
kubectl get clusterrole view -o yaml
```

---

## Option A: Create Dedicated Service Account (Recommended)

### Step 1: Create the Namespace (Optional)

Create a dedicated namespace for the scanner:
```bash
kubectl create namespace nubicustos
```

### Step 2: Create the Service Account

```bash
kubectl create serviceaccount nubicustos-scanner -n nubicustos
```

### Step 3: Create ClusterRole with Required Permissions

Create a file named `nubicustos-clusterrole.yaml`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nubicustos-scanner
rules:
  # Core API resources
  - apiGroups: [""]
    resources:
      - pods
      - pods/log
      - services
      - endpoints
      - secrets
      - configmaps
      - namespaces
      - nodes
      - persistentvolumes
      - persistentvolumeclaims
      - serviceaccounts
      - resourcequotas
      - limitranges
      - replicationcontrollers
    verbs: ["get", "list", "watch"]

  # Apps API
  - apiGroups: ["apps"]
    resources:
      - deployments
      - daemonsets
      - replicasets
      - statefulsets
    verbs: ["get", "list", "watch"]

  # Batch API
  - apiGroups: ["batch"]
    resources:
      - jobs
      - cronjobs
    verbs: ["get", "list", "watch"]

  # Networking API
  - apiGroups: ["networking.k8s.io"]
    resources:
      - networkpolicies
      - ingresses
      - ingressclasses
    verbs: ["get", "list", "watch"]

  # RBAC API
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources:
      - roles
      - rolebindings
      - clusterroles
      - clusterrolebindings
    verbs: ["get", "list", "watch"]

  # Policy API
  - apiGroups: ["policy"]
    resources:
      - podsecuritypolicies
      - poddisruptionbudgets
    verbs: ["get", "list", "watch"]

  # Admission Control
  - apiGroups: ["admissionregistration.k8s.io"]
    resources:
      - mutatingwebhookconfigurations
      - validatingwebhookconfigurations
    verbs: ["get", "list", "watch"]

  # Storage API
  - apiGroups: ["storage.k8s.io"]
    resources:
      - storageclasses
      - volumeattachments
    verbs: ["get", "list", "watch"]

  # Autoscaling API
  - apiGroups: ["autoscaling"]
    resources:
      - horizontalpodautoscalers
    verbs: ["get", "list", "watch"]

  # Certificate API
  - apiGroups: ["certificates.k8s.io"]
    resources:
      - certificatesigningrequests
    verbs: ["get", "list", "watch"]
```

Apply the ClusterRole:
```bash
kubectl apply -f nubicustos-clusterrole.yaml
```

### Step 4: Bind the ClusterRole to the Service Account

```bash
kubectl create clusterrolebinding nubicustos-scanner \
    --clusterrole=nubicustos-scanner \
    --serviceaccount=nubicustos:nubicustos-scanner
```

### Step 5: Create a Long-Lived Token (Kubernetes 1.24+)

For Kubernetes 1.24 and later, create a secret for the service account token:

```yaml
# nubicustos-token.yaml
apiVersion: v1
kind: Secret
metadata:
  name: nubicustos-scanner-token
  namespace: nubicustos
  annotations:
    kubernetes.io/service-account.name: nubicustos-scanner
type: kubernetes.io/service-account-token
```

Apply the secret:
```bash
kubectl apply -f nubicustos-token.yaml
```

### Step 6: Generate the Kubeconfig

```bash
# Get cluster information
CLUSTER_NAME=$(kubectl config view --minify -o jsonpath='{.clusters[0].name}')
CLUSTER_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CLUSTER_CA=$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')

# Get the token
TOKEN=$(kubectl get secret nubicustos-scanner-token -n nubicustos -o jsonpath='{.data.token}' | base64 -d)

# Generate kubeconfig
cat > nubicustos-kubeconfig.yaml << EOF
apiVersion: v1
kind: Config
clusters:
  - name: ${CLUSTER_NAME}
    cluster:
      server: ${CLUSTER_SERVER}
      certificate-authority-data: ${CLUSTER_CA}
contexts:
  - name: nubicustos-scanner
    context:
      cluster: ${CLUSTER_NAME}
      user: nubicustos-scanner
      namespace: default
current-context: nubicustos-scanner
users:
  - name: nubicustos-scanner
    user:
      token: ${TOKEN}
EOF

echo "Kubeconfig saved to nubicustos-kubeconfig.yaml"
```

---

## Option B: Use Existing Kubeconfig

If you prefer to use an existing kubeconfig with appropriate permissions:

### Step 1: Export Your Current Kubeconfig

```bash
# View current config
kubectl config view --minify --flatten > nubicustos-kubeconfig.yaml
```

### Step 2: Verify the Context Has Read Permissions

```bash
# Test read access
kubectl auth can-i list pods --all-namespaces
kubectl auth can-i list secrets --all-namespaces
kubectl auth can-i list nodes
```

### Step 3: (Optional) Create a Specific Context

```bash
# If you have multiple contexts, export only the one needed
kubectl config view --minify --flatten --context=YOUR_CONTEXT_NAME > nubicustos-kubeconfig.yaml
```

---

## Cloud Provider Specific Instructions

### Amazon EKS

#### Generate Kubeconfig for EKS

```bash
# Update kubeconfig for your EKS cluster
aws eks update-kubeconfig --name YOUR_CLUSTER_NAME --region YOUR_REGION

# Export the config
kubectl config view --minify --flatten > nubicustos-kubeconfig.yaml
```

#### Create IAM User for EKS Access (Alternative)

1. Create an IAM user with EKS permissions
2. Add the user to the `aws-auth` ConfigMap:

```bash
kubectl edit configmap aws-auth -n kube-system
```

Add:
```yaml
mapUsers: |
  - userarn: arn:aws:iam::ACCOUNT_ID:user/nubicustos-scanner
    username: nubicustos-scanner
    groups:
      - system:masters  # Or create a custom read-only group
```

### Azure AKS

#### Generate Kubeconfig for AKS

```bash
# Get credentials
az aks get-credentials --resource-group YOUR_RG --name YOUR_CLUSTER_NAME --file nubicustos-kubeconfig.yaml

# For read-only access, use --admin flag only if necessary
az aks get-credentials --resource-group YOUR_RG --name YOUR_CLUSTER_NAME --file nubicustos-kubeconfig.yaml
```

#### Create Azure AD Integration (Recommended)

1. Create an Azure AD group for scanner access
2. Assign the group the `Azure Kubernetes Service Cluster User Role`
3. Create RBAC bindings within the cluster

### Google GKE

#### Generate Kubeconfig for GKE

```bash
# Get credentials
gcloud container clusters get-credentials YOUR_CLUSTER_NAME --zone YOUR_ZONE --project YOUR_PROJECT

# Export the config
kubectl config view --minify --flatten > nubicustos-kubeconfig.yaml
```

#### Use GCP Service Account for GKE

1. Create a GCP service account (see GCP guide)
2. Grant `roles/container.clusterViewer` role
3. Use the service account for authentication

---

## Verification

### Test the Kubeconfig

```bash
# Use the generated kubeconfig
export KUBECONFIG=./nubicustos-kubeconfig.yaml

# Verify connection
kubectl cluster-info

# Test read access to various resources
kubectl get nodes
kubectl get namespaces
kubectl get pods --all-namespaces --limit=5
kubectl get secrets --all-namespaces --limit=5
kubectl get deployments --all-namespaces --limit=5
```

### Verify RBAC Permissions

```bash
# Check if the service account can perform required actions
kubectl auth can-i list pods --all-namespaces --as=system:serviceaccount:nubicustos:nubicustos-scanner
kubectl auth can-i list secrets --all-namespaces --as=system:serviceaccount:nubicustos:nubicustos-scanner
kubectl auth can-i list nodes --as=system:serviceaccount:nubicustos:nubicustos-scanner
kubectl auth can-i list clusterroles --as=system:serviceaccount:nubicustos:nubicustos-scanner
```

Expected output for each command: `yes`

### Verify Cannot Modify Resources

```bash
# Ensure the account cannot create or delete resources
kubectl auth can-i create pods --as=system:serviceaccount:nubicustos:nubicustos-scanner
kubectl auth can-i delete secrets --as=system:serviceaccount:nubicustos:nubicustos-scanner
```

Expected output: `no`

---

## Security Best Practices

### 1. Use Dedicated Service Account
Always create a dedicated service account for scanning. Never use `default` or admin service accounts.

### 2. Apply Least Privilege
Only grant the permissions listed in this guide. Avoid using `cluster-admin` or overly broad roles.

### 3. Use Namespace Isolation
Consider creating the scanner service account in a dedicated namespace.

### 4. Enable Audit Logging
Ensure Kubernetes audit logging is enabled to track scanner activity:
```bash
# Check if audit logging is enabled (method varies by platform)
kubectl logs -n kube-system -l component=kube-apiserver | grep audit
```

### 5. Rotate Tokens Regularly
For long-lived tokens, implement a rotation schedule:
```bash
# Delete and recreate the token secret
kubectl delete secret nubicustos-scanner-token -n nubicustos
kubectl apply -f nubicustos-token.yaml

# Regenerate kubeconfig with new token
```

### 6. Restrict API Server Access
If possible, restrict which IP addresses can access the API server.

### 7. Use Short-Lived Tokens (Advanced)
For cloud-managed Kubernetes, consider using cloud IAM integration for automatic token rotation.

---

## Troubleshooting

### Error: "Unauthorized" or "401"
- Token may be expired or invalid
- Regenerate the token and kubeconfig
- Verify the service account exists

### Error: "Forbidden" or "403"
- Missing RBAC permissions
- Verify ClusterRoleBinding exists and is correct
- Check if the service account is bound to the correct role

### Error: "Unable to connect to the server"
- Cluster endpoint may be unreachable
- Check network connectivity
- Verify the cluster URL in kubeconfig

### Error: "Certificate signed by unknown authority"
- CA certificate issue
- Ensure `certificate-authority-data` is correct in kubeconfig
- For testing only: add `insecure-skip-tls-verify: true` to cluster config

### Check Service Account Status

```bash
# Verify service account exists
kubectl get serviceaccount nubicustos-scanner -n nubicustos

# Check token secret
kubectl get secret nubicustos-scanner-token -n nubicustos

# View ClusterRoleBinding
kubectl get clusterrolebinding nubicustos-scanner -o yaml
```

### Debug Authentication

```bash
# Test with verbose output
kubectl get pods --v=8 2>&1 | head -50
```

---

## Information to Provide to Nubicustos

After completing the setup, provide the following:

| Field | Description |
|-------|-------------|
| Kubeconfig | The complete YAML content of the kubeconfig file |
| Context Name | The context to use (if multiple contexts exist) |

### Kubeconfig Structure

The kubeconfig file should look like this:
```yaml
apiVersion: v1
kind: Config
clusters:
  - name: my-cluster
    cluster:
      server: https://kubernetes.example.com:6443
      certificate-authority-data: LS0tLS1CRUdJTi...
contexts:
  - name: nubicustos-scanner
    context:
      cluster: my-cluster
      user: nubicustos-scanner
      namespace: default
current-context: nubicustos-scanner
users:
  - name: nubicustos-scanner
    user:
      token: eyJhbGciOiJSUzI1NiIs...
```

**Note:** Never share credentials via email or unsecured channels. Use a secure credential sharing method.

---

## Cleanup (If Needed)

To remove the scanner service account and associated resources:

```bash
# Delete ClusterRoleBinding
kubectl delete clusterrolebinding nubicustos-scanner

# Delete ClusterRole
kubectl delete clusterrole nubicustos-scanner

# Delete token secret
kubectl delete secret nubicustos-scanner-token -n nubicustos

# Delete service account
kubectl delete serviceaccount nubicustos-scanner -n nubicustos

# Delete namespace (if dedicated)
kubectl delete namespace nubicustos

# Delete local kubeconfig file
rm nubicustos-kubeconfig.yaml
```

---

## Quick Reference: Complete Setup Script

```bash
#!/bin/bash
# Nubicustos Kubernetes Scanner Setup Script

NAMESPACE="nubicustos"
SERVICE_ACCOUNT="nubicustos-scanner"

# Create namespace
kubectl create namespace $NAMESPACE

# Create service account
kubectl create serviceaccount $SERVICE_ACCOUNT -n $NAMESPACE

# Apply ClusterRole (save the YAML from Step 3 above to nubicustos-clusterrole.yaml first)
kubectl apply -f nubicustos-clusterrole.yaml

# Create ClusterRoleBinding
kubectl create clusterrolebinding $SERVICE_ACCOUNT \
    --clusterrole=$SERVICE_ACCOUNT \
    --serviceaccount=$NAMESPACE:$SERVICE_ACCOUNT

# Create token secret
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: ${SERVICE_ACCOUNT}-token
  namespace: ${NAMESPACE}
  annotations:
    kubernetes.io/service-account.name: ${SERVICE_ACCOUNT}
type: kubernetes.io/service-account-token
EOF

# Wait for token to be generated
sleep 5

# Generate kubeconfig
CLUSTER_NAME=$(kubectl config view --minify -o jsonpath='{.clusters[0].name}')
CLUSTER_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CLUSTER_CA=$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
TOKEN=$(kubectl get secret ${SERVICE_ACCOUNT}-token -n $NAMESPACE -o jsonpath='{.data.token}' | base64 -d)

cat > nubicustos-kubeconfig.yaml << EOF
apiVersion: v1
kind: Config
clusters:
  - name: ${CLUSTER_NAME}
    cluster:
      server: ${CLUSTER_SERVER}
      certificate-authority-data: ${CLUSTER_CA}
contexts:
  - name: ${SERVICE_ACCOUNT}
    context:
      cluster: ${CLUSTER_NAME}
      user: ${SERVICE_ACCOUNT}
      namespace: default
current-context: ${SERVICE_ACCOUNT}
users:
  - name: ${SERVICE_ACCOUNT}
    user:
      token: ${TOKEN}
EOF

echo "=== Setup Complete ==="
echo "Kubeconfig saved to: nubicustos-kubeconfig.yaml"
echo "Context: ${SERVICE_ACCOUNT}"
```

---

## Support

If you encounter issues during setup, please contact your Nubicustos administrator with:
1. The specific error message
2. Kubernetes version (`kubectl version`)
3. Cloud provider (EKS, AKS, GKE, self-managed)
4. The step where the error occurred
