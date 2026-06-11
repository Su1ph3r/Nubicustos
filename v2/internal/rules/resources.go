package rules

import "github.com/Su1ph3r/nubicustos/internal/state"

// Resource is a flattened, CEL-evaluable view of one collected resource. Attrs
// is the attribute map a rule's expression sees (keyed by documented snake_case
// names); the other fields populate the emitted finding's Resource.
type Resource struct {
	Type    string
	ID      string
	Name    string
	Region  string
	Account string
	Attrs   map[string]any
}

// Flatten converts the collected state into the typed resources rule expressions
// evaluate against. The set of exposed types/attributes is extended here as more
// of the state model is surfaced to the rule language.
func Flatten(st *state.State) []Resource {
	var out []Resource
	if st == nil {
		return out
	}
	if a := st.AWS; a != nil {
		out = append(out, flattenAWS(a)...)
	}
	if az := st.Azure; az != nil {
		out = append(out, flattenAzure(az)...)
	}
	if g := st.GCP; g != nil {
		out = append(out, flattenGCP(g)...)
	}
	if k := st.K8s; k != nil {
		out = append(out, flattenK8s(k)...)
	}
	return out
}

func res(rtype, id, name, region, account string, attrs map[string]any) Resource {
	attrs["type"] = rtype
	return Resource{Type: rtype, ID: id, Name: name, Region: region, Account: account, Attrs: attrs}
}

func flattenAWS(a *state.AWS) []Resource {
	var out []Resource
	for _, b := range a.S3Buckets {
		out = append(out, res("aws_s3_bucket", b.Name, b.Name, b.Region, a.Account, map[string]any{
			"name": b.Name, "region": b.Region,
			"acl_public": b.ACLPublic, "policy_public": b.PolicyPublic,
			"fully_blocked": b.FullyBlocked(), "has_public_access_block": b.HasPublicAccessBlock,
			"block_public_acls": b.BlockPublicAcls, "block_public_policy": b.BlockPublicPolicy,
			"restrict_public_buckets": b.RestrictPublicBuckets,
		}))
	}
	for _, db := range a.RDSInstances {
		out = append(out, res("aws_rds_instance", db.ID, db.ID, db.Region, a.Account, map[string]any{
			"id": db.ID, "region": db.Region, "engine": db.Engine,
			"public": db.Public, "encrypted": db.Encrypted,
			"backup_retention": int64(db.BackupRetention), "deletion_protection": db.DeletionProtection,
		}))
	}
	for _, u := range a.IAM.Users {
		out = append(out, res("aws_iam_user", u.Name, u.Name, "", a.Account, map[string]any{
			"name": u.Name, "console_access": u.ConsoleAccess,
			"mfa_enabled": u.MFAEnabled, "admin_attached": u.AdminAttached,
		}))
	}
	for _, sg := range a.SecurityGroups {
		out = append(out, res("aws_security_group", sg.ID, sg.Name, sg.Region, a.Account, map[string]any{
			"id": sg.ID, "name": sg.Name, "region": sg.Region, "world_open": sg.WorldOpen(),
		}))
	}
	return out
}

func flattenAzure(a *state.Azure) []Resource {
	var out []Resource
	for _, sa := range a.StorageAccounts {
		out = append(out, res("azure_storage_account", sa.Name, sa.Name, sa.Location, sa.Subscription, map[string]any{
			"name": sa.Name, "location": sa.Location,
			"allow_blob_public_access": sa.AllowBlobPublicAccess, "https_only": sa.HTTPSOnly,
			"min_tls_version": sa.MinTLSVersion, "network_default_allow": sa.NetworkDefaultAllow,
		}))
	}
	for _, kv := range a.KeyVaults {
		out = append(out, res("azure_key_vault", kv.Name, kv.Name, kv.Location, kv.Subscription, map[string]any{
			"name": kv.Name, "location": kv.Location,
			"soft_delete_enabled": kv.SoftDeleteEnabled, "purge_protection": kv.PurgeProtection,
			"network_default_allow": kv.NetworkDefaultAllow,
		}))
	}
	return out
}

func flattenGCP(g *state.GCP) []Resource {
	var out []Resource
	for _, b := range g.Buckets {
		out = append(out, res("gcp_storage_bucket", b.Name, b.Name, b.Location, b.Project, map[string]any{
			"name": b.Name, "location": b.Location,
			"public_iam": b.PublicIAM, "uniform_bucket_level_access": b.UniformBucketLevelAccess,
			"public_access_prevention": b.PublicAccessPrevention,
		}))
	}
	return out
}

func flattenK8s(k *state.K8s) []Resource {
	var out []Resource
	for _, p := range k.Pods {
		privileged, runAsNonRoot := false, true
		for _, c := range p.Containers {
			if c.Privileged {
				privileged = true
			}
			if !c.RunAsNonRoot {
				runAsNonRoot = false
			}
		}
		out = append(out, res("k8s_pod", p.Namespace+"/"+p.Name, p.Name, p.Namespace, p.Context, map[string]any{
			"name": p.Name, "namespace": p.Namespace, "context": p.Context,
			"host_network": p.HostNetwork, "host_pid": p.HostPID, "host_ipc": p.HostIPC,
			"host_namespaces": p.HostNamespaces(), "privileged": privileged,
			"run_as_non_root": runAsNonRoot,
		}))
	}
	return out
}
