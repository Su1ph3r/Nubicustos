package azure

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() {
	engine.RegisterCheck(appServiceNotHTTPSOnly{})
	engine.RegisterCheck(appServiceMinTLS{})
	engine.RegisterCheck(appServiceFTPSInsecure{})
}

// webAppResource builds the normalized resource for a web app.
func webAppResource(w state.WebApp) findings.Resource {
	return findings.Resource{
		ID: w.Name, Name: w.Name, Type: "azure_web_app", Provider: "azure",
		Account: w.Subscription, Region: w.Location,
	}
}

type appServiceNotHTTPSOnly struct{}

func (appServiceNotHTTPSOnly) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_appservice_not_https_only", Title: "Web app does not enforce HTTPS-only traffic",
		Provider: "azure", Service: "appservice", Severity: findings.SeverityMedium,
		Rationale:   "Without HTTPS-only enforcement, the app answers plaintext HTTP requests, so credentials, cookies, and tokens can be intercepted in transit.",
		Impact:      "Session tokens and request data sent over HTTP can be observed or tampered with on the network path.",
		Remediation: "az webapp update --name <name> --resource-group <rg> --set httpsOnly=true",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "9.2"}},
	}
}

func (c appServiceNotHTTPSOnly) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, w := range st.Azure.WebApps {
		if w.HTTPSOnly {
			continue
		}
		desc := fmt.Sprintf("Web app %q (sub %s) does not enforce HTTPS-only traffic.", w.Name, w.Subscription)
		poc := fmt.Sprintf("az webapp show --name %s --resource-group %s --query httpsOnly", w.Name, w.ResourceGroup)
		out = append(out, findings.New(c.Spec(), webAppResource(w), desc, poc, now))
	}
	return out, nil
}

type appServiceMinTLS struct{}

func (appServiceMinTLS) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_appservice_min_tls", Title: "Web app allows TLS below 1.2",
		Provider: "azure", Service: "appservice", Severity: findings.SeverityMedium,
		Rationale:   "A minimum TLS version below 1.2 lets clients negotiate deprecated TLS 1.0/1.1, which carry known cryptographic weaknesses.",
		Impact:      "Connections to the app can be downgraded to weak TLS, exposing traffic to interception.",
		Remediation: "az webapp config set --name <name> --resource-group <rg> --min-tls-version 1.2",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "9.3"}},
	}
}

func (c appServiceMinTLS) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, w := range st.Azure.WebApps {
		// Empty means the config could not be read; only flag a version explicitly
		// below 1.2.
		if w.MinTLSVersion == "" || w.MinTLSVersion == "1.2" || w.MinTLSVersion == "1.3" {
			continue
		}
		desc := fmt.Sprintf("Web app %q sets a minimum TLS version of %s (below 1.2).", w.Name, w.MinTLSVersion)
		poc := fmt.Sprintf("az webapp config show --name %s --resource-group %s --query minTlsVersion", w.Name, w.ResourceGroup)
		out = append(out, findings.New(c.Spec(), webAppResource(w), desc, poc, now))
	}
	return out, nil
}

type appServiceFTPSInsecure struct{}

func (appServiceFTPSInsecure) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "azure_appservice_ftps_insecure", Title: "Web app allows plaintext FTP deployment",
		Provider: "azure", Service: "appservice", Severity: findings.SeverityMedium,
		Rationale:   "An FTPS state of AllAllowed permits unencrypted FTP, so deployment credentials and content are sent in cleartext.",
		Impact:      "Deployment credentials transmitted over plain FTP can be captured and used to push malicious content to the app.",
		Remediation: "Require FTPS or disable FTP: az webapp config set --name <name> --resource-group <rg> --ftps-state FtpsOnly (or Disabled)",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS Azure 2.0", Control: "9.10"}},
	}
}

func (c appServiceFTPSInsecure) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.Azure == nil {
		return nil, nil
	}
	now := time.Now().UTC()
	var out []findings.Finding
	for _, w := range st.Azure.WebApps {
		if w.FtpsState != "AllAllowed" {
			continue
		}
		desc := fmt.Sprintf("Web app %q allows plaintext FTP (FTPS state AllAllowed).", w.Name)
		poc := fmt.Sprintf("az webapp config show --name %s --resource-group %s --query ftpsState", w.Name, w.ResourceGroup)
		out = append(out, findings.New(c.Spec(), webAppResource(w), desc, poc, now))
	}
	return out, nil
}
