// Package discovery turns "scan one account" into "scan the estate". For AWS it
// enumerates the organization off the MFA-satisfied base session resolved in
// internal/auth, then hands back a ready, validated aws.Config per member
// account — assuming the org access role into each so the concurrent scan never
// re-authenticates (§9.4 of the refactor plan).
//
// MFA is satisfied exactly once at the base session (GetSessionToken or the
// initial MFA AssumeRole). Chained AssumeRole calls into member accounts inherit
// aws:MultiFactorAuthPresent=true and do not re-prompt — so no TokenProvider is
// wired here on purpose.
package discovery

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// DefaultOrgRole is the role AWS Organizations creates in member accounts for
// management-account access; it is the default role assumed per member.
const DefaultOrgRole = "OrganizationAccountAccessRole"

// scanSessionName labels the assumed-role sessions in CloudTrail.
const scanSessionName = "nubicustos-scan"

// AWSOptions controls org enumeration and the per-account session build.
type AWSOptions struct {
	RoleName    string   // role assumed in member accounts; default OrganizationAccountAccessRole
	Accounts    []string // explicit account-id allowlist — skips org enumeration entirely
	Exclude     []string // account ids to skip
	OUs         []string // restrict to accounts under these OU ids (recursive); empty = whole org
	IncludeMgmt bool     // also scan the management/base account itself (uses base creds directly)
	Region      string   // region pinned on each per-account session (regional fan-out happens later)
	Validate    bool     // prove each member session up front (AssumeRole + GetCallerIdentity)
}

// Account is a member account with a ready-to-scan session.
type Account struct {
	ID         string
	Name       string
	Email      string
	Identity   string     // validated caller ARN for the session (empty if not validated)
	Management bool       // base account, scanned with base creds (no assume-role)
	Config     aws.Config // validated, MFA-inheriting session for this account
}

// Skipped records an account that was deliberately not scanned, with the reason
// — surfaced so a partial run never reads as full coverage.
type Skipped struct {
	ID     string
	Name   string
	Reason string
}

// AWSResult is the outcome of org discovery.
type AWSResult struct {
	Management string    // the account id discovery ran from
	Accounts   []Account // ready-to-scan accounts, sorted by id
	Skipped    []Skipped // suspended / excluded / assume-failed accounts, with reasons
}

// orgAccount is the provider-agnostic shape the pure core works over.
type orgAccount struct {
	ID, Name, Email, Status string
}

// orgLister enumerates accounts; the real impl wraps the Organizations client,
// a fake drives the unit tests.
type orgLister interface {
	listAccounts(ctx context.Context) ([]orgAccount, error)
	accountsUnderOUs(ctx context.Context, ous []string) ([]orgAccount, error)
}

// sessionFactory builds (and, when asked, validates) a session for one account,
// returning the session and the validated caller ARN (empty when validation is
// off). The real factory assumes the org role; the fake controls success per account.
type sessionFactory func(ctx context.Context, accountID string, management bool) (aws.Config, string, error)

// AWSAccounts enumerates the organization reachable from base and returns a
// validated session per in-scope member account. base must be the MFA-satisfied
// management or delegated-admin config from auth.ResolveAWS.
func AWSAccounts(ctx context.Context, base aws.Config, o AWSOptions) (*AWSResult, error) {
	who, err := sts.NewFromConfig(base).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("identifying base account (sts:GetCallerIdentity): %w", err)
	}
	mgmt := aws.ToString(who.Account)
	partition := arnPartition(aws.ToString(who.Arn))

	role := o.RoleName
	if role == "" {
		role = DefaultOrgRole
	}

	lister := &orgClientLister{cli: organizations.NewFromConfig(base)}
	factory := realSessionFactory(base, partition, role, o.Region, o.Validate)
	return discoverAccounts(ctx, mgmt, lister, factory, o)
}

// discoverAccounts is the registry- and SDK-independent core: pick the candidate
// set, apply the skip rules, and build a session per surviving account. Errors
// building a single member's session demote it to Skipped — never abort the run.
func discoverAccounts(ctx context.Context, mgmt string, lister orgLister, factory sessionFactory, o AWSOptions) (*AWSResult, error) {
	candidates, err := candidateAccounts(ctx, lister, o)
	if err != nil {
		return nil, err
	}

	res := &AWSResult{Management: mgmt}
	exclude := toSet(o.Exclude)

	for _, a := range candidates {
		isMgmt := a.ID == mgmt

		switch {
		case exclude[a.ID]:
			res.Skipped = append(res.Skipped, Skipped{a.ID, a.Name, "excluded"})
			continue
		case a.Status != "" && !strings.EqualFold(a.Status, string(orgtypes.AccountStatusActive)):
			res.Skipped = append(res.Skipped, Skipped{a.ID, a.Name, "status " + a.Status})
			continue
		case isMgmt && !o.IncludeMgmt:
			res.Skipped = append(res.Skipped, Skipped{a.ID, a.Name, "management account (use --include-mgmt to scan)"})
			continue
		}

		cfg, arn, err := factory(ctx, a.ID, isMgmt)
		if err != nil {
			res.Skipped = append(res.Skipped, Skipped{a.ID, a.Name, assumeReason(isMgmt, err)})
			continue
		}
		res.Accounts = append(res.Accounts, Account{
			ID:         a.ID,
			Name:       a.Name,
			Email:      a.Email,
			Identity:   arn,
			Management: isMgmt,
			Config:     cfg,
		})
	}

	sort.Slice(res.Accounts, func(i, j int) bool { return res.Accounts[i].ID < res.Accounts[j].ID })
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].ID < res.Skipped[j].ID })
	return res, nil
}

// candidateAccounts resolves the raw account set before skip rules: an explicit
// allowlist (no Organizations read needed), an OU-scoped subtree, or the whole org.
func candidateAccounts(ctx context.Context, lister orgLister, o AWSOptions) ([]orgAccount, error) {
	switch {
	case len(o.Accounts) > 0:
		out := make([]orgAccount, 0, len(o.Accounts))
		for _, id := range o.Accounts {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			// Status unknown for an explicit list — trust the operator; the assume
			// step will weed out anything unreachable.
			out = append(out, orgAccount{ID: id, Name: id, Status: string(orgtypes.AccountStatusActive)})
		}
		return out, nil
	case len(o.OUs) > 0:
		return lister.accountsUnderOUs(ctx, o.OUs)
	default:
		return lister.listAccounts(ctx)
	}
}

// assumeReason frames a session-build failure for the skip list.
func assumeReason(management bool, err error) string {
	if management {
		return "base session unusable: " + err.Error()
	}
	return "assume-role denied: " + err.Error()
}

// realSessionFactory assumes the org role into each member (the management
// account uses base creds directly) and, when validate is set, proves the
// session with a single GetCallerIdentity so unreachable accounts are skipped
// cleanly instead of producing a pile of collector errors mid-scan.
func realSessionFactory(base aws.Config, partition, role, region string, validate bool) sessionFactory {
	stsBase := sts.NewFromConfig(base)
	return func(ctx context.Context, accountID string, management bool) (aws.Config, string, error) {
		cfg := base.Copy()
		if region != "" {
			cfg.Region = region
		}
		if !management {
			roleARN := fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, accountID, role)
			provider := stscreds.NewAssumeRoleProvider(stsBase, roleARN, func(ao *stscreds.AssumeRoleOptions) {
				ao.RoleSessionName = scanSessionName
			})
			cfg.Credentials = aws.NewCredentialsCache(provider)
		}
		if validate {
			out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return aws.Config{}, "", err
			}
			return cfg, aws.ToString(out.Arn), nil
		}
		return cfg, "", nil
	}
}

// orgClientLister is the live Organizations-backed lister.
type orgClientLister struct {
	cli *organizations.Client
}

func (l *orgClientLister) listAccounts(ctx context.Context) ([]orgAccount, error) {
	var out []orgAccount
	p := organizations.NewListAccountsPaginator(l.cli, &organizations.ListAccountsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("organizations:ListAccounts (run from the management or a delegated-admin account): %w", err)
		}
		for _, a := range page.Accounts {
			out = append(out, fromSDKAccount(a))
		}
	}
	return out, nil
}

func (l *orgClientLister) accountsUnderOUs(ctx context.Context, ous []string) ([]orgAccount, error) {
	seen := map[string]bool{}
	var out []orgAccount
	for _, ou := range ous {
		ou = strings.TrimSpace(ou)
		if ou == "" {
			continue
		}
		accs, err := l.accountsUnderParent(ctx, ou, seen)
		if err != nil {
			return nil, err
		}
		out = append(out, accs...)
	}
	return out, nil
}

// accountsUnderParent gathers accounts directly under parentID, then recurses
// into its child OUs — so --ou captures a whole subtree, not just its top level.
func (l *orgClientLister) accountsUnderParent(ctx context.Context, parentID string, seen map[string]bool) ([]orgAccount, error) {
	var out []orgAccount

	ap := organizations.NewListAccountsForParentPaginator(l.cli, &organizations.ListAccountsForParentInput{ParentId: &parentID})
	for ap.HasMorePages() {
		page, err := ap.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("organizations:ListAccountsForParent(%s): %w", parentID, err)
		}
		for _, a := range page.Accounts {
			id := aws.ToString(a.Id)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			out = append(out, fromSDKAccount(a))
		}
	}

	op := organizations.NewListOrganizationalUnitsForParentPaginator(l.cli, &organizations.ListOrganizationalUnitsForParentInput{ParentId: &parentID})
	for op.HasMorePages() {
		page, err := op.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("organizations:ListOrganizationalUnitsForParent(%s): %w", parentID, err)
		}
		for _, ou := range page.OrganizationalUnits {
			child, err := l.accountsUnderParent(ctx, aws.ToString(ou.Id), seen)
			if err != nil {
				return nil, err
			}
			out = append(out, child...)
		}
	}
	return out, nil
}

func fromSDKAccount(a orgtypes.Account) orgAccount {
	return orgAccount{
		ID:     aws.ToString(a.Id),
		Name:   aws.ToString(a.Name),
		Email:  aws.ToString(a.Email),
		Status: string(a.Status),
	}
}

// arnPartition pulls the partition (aws / aws-us-gov / aws-cn) out of an ARN so
// member role ARNs are built for the right partition. Defaults to "aws".
func arnPartition(arn string) string {
	parts := strings.SplitN(arn, ":", 3)
	if len(parts) >= 2 && parts[0] == "arn" && parts[1] != "" {
		return parts[1]
	}
	return "aws"
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			m[s] = true
		}
	}
	return m
}
