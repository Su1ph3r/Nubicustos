package aws

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

const adminPolicyARN = "arn:aws:iam::aws:policy/AdministratorAccess"

func init() { engine.RegisterCollector(&iamCollector{}) }

type iamCollector struct{}

func (iamCollector) Name() string { return "aws:iam" }

// Collect gathers account-wide IAM posture: root account summary, the password
// policy, and per-user MFA / access-key / admin posture. IAM is global, so no
// region iteration. Per-item failures are tolerated (best-effort) so one denied
// sub-call does not blank the whole picture.
func (iamCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	client := iam.NewFromConfig(sc.AWS)
	pc := &policyCache{client: client, ctx: sc.Ctx, docs: map[string]state.PolicyDocument{}}
	var iamState state.IAMState

	// Account summary: root MFA + root access keys.
	if sum, err := client.GetAccountSummary(sc.Ctx, &iam.GetAccountSummaryInput{}); err == nil {
		iamState.RootMFAEnabled = sum.SummaryMap[string(iamtypes.SummaryKeyTypeAccountMFAEnabled)] == 1
		iamState.RootAccessKeys = sum.SummaryMap[string(iamtypes.SummaryKeyTypeAccountAccessKeysPresent)] > 0
	}

	// Password policy (absent => NoSuchEntity).
	if pp, err := client.GetAccountPasswordPolicy(sc.Ctx, &iam.GetAccountPasswordPolicyInput{}); err == nil && pp.PasswordPolicy != nil {
		p := pp.PasswordPolicy
		iamState.PasswordPolicy = state.PasswordPolicy{
			Present:        true,
			MinLength:      int(awssdk.ToInt32(p.MinimumPasswordLength)),
			RequireSymbols: p.RequireSymbols,
			RequireNumbers: p.RequireNumbers,
			RequireUpper:   p.RequireUppercaseCharacters,
			RequireLower:   p.RequireLowercaseCharacters,
			MaxAgeDays:     int(awssdk.ToInt32(p.MaxPasswordAge)),
		}
	}

	// Users.
	pager := iam.NewListUsersPaginator(client, &iam.ListUsersInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			// If we cannot even list users, return the error (non-fatal at engine level).
			st.SetIAM(iamState)
			return err
		}
		for _, u := range page.Users {
			iamState.Users = append(iamState.Users, collectUser(sc, client, pc, awssdk.ToString(u.UserName)))
		}
	}

	// Roles (with trust policies + permission policies for the attack-path graph).
	roles, rolesErr := collectRoles(sc, client, pc)
	iamState.Roles = roles

	st.SetIAM(iamState)
	// Surface a role-listing failure (it is non-fatal at the engine level, but
	// must not be silent: an empty role set from a denied ListRoles would
	// otherwise read as a clean, trust-finding-free account).
	return rolesErr
}

// policyCache fetches and memoizes managed-policy documents by ARN within a
// single scan, so a policy attached to many principals is fetched once.
type policyCache struct {
	client *iam.Client
	ctx    context.Context
	docs   map[string]state.PolicyDocument
}

// managed returns the default-version document for a managed policy ARN.
func (pc *policyCache) managed(arn string) (state.PolicyDocument, bool) {
	if d, ok := pc.docs[arn]; ok {
		return d, true
	}
	gp, err := pc.client.GetPolicy(pc.ctx, &iam.GetPolicyInput{PolicyArn: &arn})
	if err != nil || gp.Policy == nil || gp.Policy.DefaultVersionId == nil {
		return state.PolicyDocument{}, false
	}
	gv, err := pc.client.GetPolicyVersion(pc.ctx, &iam.GetPolicyVersionInput{
		PolicyArn: &arn, VersionId: gp.Policy.DefaultVersionId,
	})
	if err != nil || gv.PolicyVersion == nil {
		return state.PolicyDocument{}, false
	}
	doc := parsePolicyDocument(awssdk.ToString(gv.PolicyVersion.Document))
	pc.docs[arn] = doc
	return doc, true
}

// collectRoles enumerates roles with their trust + permission policies. A
// pagination failure returns the roles gathered so far plus the error, so the
// caller can surface partial collection rather than presenting it as complete.
func collectRoles(sc *engine.ScanContext, client *iam.Client, pc *policyCache) ([]state.IAMRole, error) {
	var roles []state.IAMRole
	pager := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(sc.Ctx)
		if err != nil {
			return roles, err
		}
		for _, r := range page.Roles {
			name := awssdk.ToString(r.RoleName)
			role := state.IAMRole{
				Name:        name,
				ARN:         awssdk.ToString(r.Arn),
				TrustPolicy: parsePolicyDocument(awssdk.ToString(r.AssumeRolePolicyDocument)),
			}
			role.AdminAttached, role.Policies = collectRolePolicies(sc, client, pc, name)
			roles = append(roles, role)
		}
	}
	return roles, nil
}

// collectRolePolicies gathers a role's attached + inline permission documents,
// flagging whether AdministratorAccess is attached.
func collectRolePolicies(sc *engine.ScanContext, client *iam.Client, pc *policyCache, role string) (adminAttached bool, docs []state.PolicyDocument) {
	if att, err := client.ListAttachedRolePolicies(sc.Ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &role}); err == nil {
		for _, p := range att.AttachedPolicies {
			arn := awssdk.ToString(p.PolicyArn)
			if arn == adminPolicyARN {
				adminAttached = true
			}
			if doc, ok := pc.managed(arn); ok {
				docs = append(docs, doc)
			}
		}
	}
	if inl, err := client.ListRolePolicies(sc.Ctx, &iam.ListRolePoliciesInput{RoleName: &role}); err == nil {
		for _, name := range inl.PolicyNames {
			if gp, err := client.GetRolePolicy(sc.Ctx, &iam.GetRolePolicyInput{RoleName: &role, PolicyName: &name}); err == nil {
				docs = append(docs, parsePolicyDocument(awssdk.ToString(gp.PolicyDocument)))
			}
		}
	}
	return adminAttached, docs
}

// collectUser gathers one user's console/MFA/key/admin posture and permission
// policies, tolerating per-call failures.
func collectUser(sc *engine.ScanContext, client *iam.Client, pc *policyCache, name string) state.IAMUser {
	u := state.IAMUser{Name: name}

	// Console access = a login profile exists.
	if _, err := client.GetLoginProfile(sc.Ctx, &iam.GetLoginProfileInput{UserName: &name}); err == nil {
		u.ConsoleAccess = true
	}

	// MFA devices.
	if mfa, err := client.ListMFADevices(sc.Ctx, &iam.ListMFADevicesInput{UserName: &name}); err == nil {
		u.MFAEnabled = len(mfa.MFADevices) > 0
	}

	// Access keys + age.
	if keys, err := client.ListAccessKeys(sc.Ctx, &iam.ListAccessKeysInput{UserName: &name}); err == nil {
		for _, k := range keys.AccessKeyMetadata {
			ak := state.AccessKey{
				ID:     awssdk.ToString(k.AccessKeyId),
				Active: k.Status == iamtypes.StatusTypeActive,
			}
			if k.CreateDate != nil {
				ak.AgeDays = int(time.Since(*k.CreateDate).Hours() / 24)
			}
			u.AccessKeys = append(u.AccessKeys, ak)
		}
	}

	// Directly-attached managed policies: flag AdministratorAccess and gather the
	// documents (for privilege-escalation analysis in the attack-path graph).
	if att, err := client.ListAttachedUserPolicies(sc.Ctx, &iam.ListAttachedUserPoliciesInput{UserName: &name}); err == nil {
		for _, p := range att.AttachedPolicies {
			arn := awssdk.ToString(p.PolicyArn)
			if arn == adminPolicyARN {
				u.AdminAttached = true
			}
			if doc, ok := pc.managed(arn); ok {
				u.Policies = append(u.Policies, doc)
			}
		}
	}
	// Inline user policies.
	if inl, err := client.ListUserPolicies(sc.Ctx, &iam.ListUserPoliciesInput{UserName: &name}); err == nil {
		for _, pname := range inl.PolicyNames {
			if gp, err := client.GetUserPolicy(sc.Ctx, &iam.GetUserPolicyInput{UserName: &name, PolicyName: &pname}); err == nil {
				u.Policies = append(u.Policies, parsePolicyDocument(awssdk.ToString(gp.PolicyDocument)))
			}
		}
	}
	return u
}
