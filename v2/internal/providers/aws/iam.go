package aws

import (
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
			iamState.Users = append(iamState.Users, collectUser(sc, client, awssdk.ToString(u.UserName)))
		}
	}

	st.SetIAM(iamState)
	return nil
}

// collectUser gathers one user's console/MFA/key/admin posture, tolerating
// per-call failures.
func collectUser(sc *engine.ScanContext, client *iam.Client, name string) state.IAMUser {
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

	// Directly-attached AdministratorAccess.
	if att, err := client.ListAttachedUserPolicies(sc.Ctx, &iam.ListAttachedUserPoliciesInput{UserName: &name}); err == nil {
		for _, p := range att.AttachedPolicies {
			if awssdk.ToString(p.PolicyArn) == adminPolicyARN {
				u.AdminAttached = true
				break
			}
		}
	}
	return u
}
