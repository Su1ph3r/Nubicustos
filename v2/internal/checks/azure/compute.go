package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(vmEncryptionAtHost{})
	engine.RegisterCheck(redisNonSSLPort{})
}

type vmEncryptionAtHost struct{}

func (vmEncryptionAtHost) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_vm_encryption_at_host_disabled", Title: "VM does not have encryption at host enabled",
		Provider: "azure", Service: "compute", Severity: findings.SeverityLow,
		Rationale:   "Encryption at host encrypts the VM's temp disk and OS/data disk caches at the host, and the data flowing to storage. Without it, that data is not encrypted on the host, leaving a gap beyond at-rest disk encryption.",
		Impact:      "Temp-disk and cache data on the host is not encrypted, a residual exposure if the host is compromised.",
		Remediation: "Enable encryption at host (VM must be deallocated): az vm update --name <name> --resource-group <rg> --set securityProfile.encryptionAtHost=true",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "7.x"}},
	}
}

func (c vmEncryptionAtHost) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, v := range st.Azure.VMs {
		if v.EncryptionAtHost {
			continue
		}
		res := findings.Resource{
			ID: v.Name, Name: v.Name, Type: "azure_virtual_machine", Provider: "azure", Account: v.Subscription, Region: v.Location,
		}
		desc := fmt.Sprintf("VM %q (sub %s) does not have encryption at host enabled.", v.Name, v.Subscription)
		poc := fmt.Sprintf("az vm show --name %s --resource-group %s --query securityProfile.encryptionAtHost", v.Name, v.ResourceGroup)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}

type redisNonSSLPort struct{}

func (redisNonSSLPort) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_redis_non_ssl_port_enabled", Title: "Redis cache has the non-TLS port enabled",
		Provider: "azure", Service: "redis", Severity: findings.SeverityMedium,
		Rationale:   "With the non-TLS port (6379) enabled, clients can connect to Redis without encryption, so cached data and any auth token travel in plaintext and can be intercepted.",
		Impact:      "Redis traffic over the non-TLS port can be observed or tampered with on the network path.",
		Remediation: "Disable the non-TLS port (TLS-only): az redis update --name <name> --resource-group <rg> --set enableNonSslPort=false",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "4.x"}},
	}
}

func (c redisNonSSLPort) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, r := range st.Azure.RedisCaches {
		if !r.NonSSLPortEnabled {
			continue
		}
		res := findings.Resource{
			ID: r.Name, Name: r.Name, Type: "azure_redis_cache", Provider: "azure", Account: r.Subscription, Region: r.Location,
		}
		desc := fmt.Sprintf("Redis cache %q (sub %s) has the non-TLS port enabled.", r.Name, r.Subscription)
		poc := fmt.Sprintf("az redis show --name %s --resource-group %s --query enableNonSslPort", r.Name, r.ResourceGroup)
		out = append(out, findings.New(c.Spec(), res, desc, poc, now))
	}
	return out, nil
}
