package auth

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// armScope is the resource-manager token scope used to validate Azure auth
// without pulling in a heavier management SDK.
const armScope = "https://management.azure.com/.default"

// AzureMethod selects which Entra ID credential flow to use.
type AzureMethod string

const (
	// AzureAuto chains the CLI session then an interactive browser sign-in.
	AzureAuto             AzureMethod = "auto"
	AzureCLI              AzureMethod = "cli"
	AzureInteractive      AzureMethod = "interactive-browser"
	AzureDeviceCode       AzureMethod = "device-code"
	AzureServicePrincipal AzureMethod = "service-principal"
	AzureManagedIdentity  AzureMethod = "managed-identity"
)

// AzureOptions describes how to authenticate to Azure. MFA / Conditional Access
// is satisfied inside the chosen flow (browser, device code, or a prior az login),
// so there is no TOTP for us to handle directly.
type AzureOptions struct {
	Method       AzureMethod
	TenantID     string
	ClientID     string
	ClientSecret string
}

// ResolveAzure builds and validates an Azure credential. Validation acquires an
// ARM token up front so any interactive step (browser/device code) happens here,
// before the scan fans out.
func ResolveAzure(ctx context.Context, o AzureOptions, p Prompter) (azcore.TokenCredential, error) {
	cred, err := buildAzureCredential(o, p)
	if err != nil {
		return nil, err
	}
	if _, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{armScope}}); err != nil {
		return nil, fmt.Errorf("validating azure credentials: %w", err)
	}
	return cred, nil
}

func buildAzureCredential(o AzureOptions, p Prompter) (azcore.TokenCredential, error) {
	method := o.Method
	if method == "" {
		method = AzureAuto
	}

	switch method {
	case AzureCLI:
		return azidentity.NewAzureCLICredential(nil)

	case AzureInteractive:
		return azidentity.NewInteractiveBrowserCredential(&azidentity.InteractiveBrowserCredentialOptions{
			TenantID: o.TenantID,
			ClientID: o.ClientID,
		})

	case AzureDeviceCode:
		return azidentity.NewDeviceCodeCredential(&azidentity.DeviceCodeCredentialOptions{
			TenantID: o.TenantID,
			ClientID: o.ClientID,
			UserPrompt: func(_ context.Context, m azidentity.DeviceCodeMessage) error {
				p.Notify(m.Message)
				return nil
			},
		})

	case AzureServicePrincipal:
		if o.TenantID == "" || o.ClientID == "" || o.ClientSecret == "" {
			return nil, fmt.Errorf("service-principal auth requires tenant, client id, and client secret")
		}
		return azidentity.NewClientSecretCredential(o.TenantID, o.ClientID, o.ClientSecret, nil)

	case AzureManagedIdentity:
		return azidentity.NewManagedIdentityCredential(nil)

	case AzureAuto:
		// Prefer a reusable az login session; fall back to an interactive browser
		// sign-in. Each constructor can fail (e.g. az not installed); skip those
		// and chain whatever is available.
		var creds []azcore.TokenCredential
		if cli, err := azidentity.NewAzureCLICredential(nil); err == nil {
			creds = append(creds, cli)
		}
		if ib, err := azidentity.NewInteractiveBrowserCredential(nil); err == nil {
			creds = append(creds, ib)
		}
		if len(creds) == 0 {
			return nil, fmt.Errorf("no azure credential source available (install the Azure CLI or use --auth device-code)")
		}
		return azidentity.NewChainedTokenCredential(creds, nil)

	default:
		return nil, fmt.Errorf("unknown azure auth method %q", method)
	}
}
