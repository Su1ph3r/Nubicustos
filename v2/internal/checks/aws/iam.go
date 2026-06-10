package aws

import (
	"fmt"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

// keyRotationDays is the age past which an active access key is flagged.
const keyRotationDays = 90

// minPasswordLength is the baseline strong minimum (CIS recommends >= 14).
const minPasswordLength = 14

func init() {
	engine.RegisterCheck(iamRootMFA{})
	engine.RegisterCheck(iamRootAccessKeys{})
	engine.RegisterCheck(iamPasswordPolicy{})
	engine.RegisterCheck(iamAccessKeyAge{})
	engine.RegisterCheck(iamConsoleNoMFA{})
	engine.RegisterCheck(iamUserAdmin{})
}

// accountResource builds the synthetic "account" resource used by account-level checks.
func accountResource(account string) findings.Resource {
	return findings.Resource{
		ID:       "account:" + account,
		Name:     account,
		Type:     "aws_account",
		Provider: "aws",
		Account:  account,
		Region:   "global",
	}
}

func userResource(account, user string) findings.Resource {
	return findings.Resource{
		ID:       "user/" + user,
		Name:     user,
		Type:     "aws_iam_user",
		Provider: "aws",
		Account:  account,
		Region:   "global",
		ARN:      fmt.Sprintf("arn:aws:iam::%s:user/%s", account, user),
	}
}

// --- root MFA ---------------------------------------------------------------

type iamRootMFA struct{}

func (iamRootMFA) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_iam_root_mfa_disabled", Title: "Root account does not have MFA enabled",
		Provider: "aws", Service: "iam", Severity: findings.SeverityCritical,
		Rationale:   "The root user has unrestricted access; without MFA a leaked root password is a full account takeover.",
		Impact:      "An attacker with the root password gains complete, unconditional control of the account.",
		Remediation: "Enable a hardware or virtual MFA device on the root user from the IAM console (My Security Credentials).",
		PoC:         "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "1.5"}},
	}
}

func (c iamRootMFA) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || !st.AWS.IAM.Collected || st.AWS.IAM.RootMFAEnabled {
		return nil, nil
	}
	res := accountResource(st.AWS.Account)
	return []findings.Finding{findings.New(c.Spec(), res,
		"The AWS account root user does not have MFA enabled.", c.Spec().PoC, time.Now().UTC())}, nil
}

// --- root access keys -------------------------------------------------------

type iamRootAccessKeys struct{}

func (iamRootAccessKeys) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_iam_root_access_keys", Title: "Root account has active access keys",
		Provider: "aws", Service: "iam", Severity: findings.SeverityCritical,
		Rationale:   "Root access keys grant programmatic unrestricted access and cannot be scoped; they should never exist.",
		Impact:      "A leaked root access key yields full, unconditional API control of the account.",
		Remediation: "Delete the root access keys: aws iam delete-access-key (as root) and use scoped IAM principals instead.",
		PoC:         "aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "1.4"}},
	}
}

func (c iamRootAccessKeys) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || !st.AWS.IAM.Collected || !st.AWS.IAM.RootAccessKeys {
		return nil, nil
	}
	res := accountResource(st.AWS.Account)
	return []findings.Finding{findings.New(c.Spec(), res,
		"The AWS account root user has one or more active access keys.", c.Spec().PoC, time.Now().UTC())}, nil
}

// --- password policy --------------------------------------------------------

type iamPasswordPolicy struct{}

func (iamPasswordPolicy) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_iam_weak_password_policy", Title: "IAM password policy is weak or missing",
		Provider: "aws", Service: "iam", Severity: findings.SeverityMedium,
		Rationale:   "A weak or absent password policy permits short, simple, or non-expiring console passwords.",
		Impact:      "Weak console passwords are easier to brute-force or guess, aiding account compromise.",
		Remediation: "Set a strong policy: aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90",
		PoC:         "aws iam get-account-password-policy",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "1.8"}},
	}
}

func (c iamPasswordPolicy) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || !st.AWS.IAM.Collected {
		return nil, nil
	}
	p := st.AWS.IAM.PasswordPolicy
	reasons := passwordPolicyWeaknesses(p)
	if len(reasons) == 0 {
		return nil, nil
	}
	res := accountResource(st.AWS.Account)
	desc := "IAM password policy is insufficient: " + joinReasons(reasons) + "."
	return []findings.Finding{findings.New(c.Spec(), res, desc, c.Spec().PoC, time.Now().UTC())}, nil
}

func passwordPolicyWeaknesses(p state.PasswordPolicy) []string {
	if !p.Present {
		return []string{"no account password policy is configured"}
	}
	var r []string
	if p.MinLength < minPasswordLength {
		r = append(r, fmt.Sprintf("minimum length %d (< %d)", p.MinLength, minPasswordLength))
	}
	if !p.RequireSymbols {
		r = append(r, "symbols not required")
	}
	if !p.RequireNumbers {
		r = append(r, "numbers not required")
	}
	if !p.RequireUpper {
		r = append(r, "uppercase not required")
	}
	if !p.RequireLower {
		r = append(r, "lowercase not required")
	}
	if p.MaxAgeDays == 0 || p.MaxAgeDays > 90 {
		r = append(r, "passwords do not expire within 90 days")
	}
	return r
}

// --- access key age ---------------------------------------------------------

type iamAccessKeyAge struct{}

func (iamAccessKeyAge) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_iam_access_key_rotation", Title: "IAM access key has not been rotated",
		Provider: "aws", Service: "iam", Severity: findings.SeverityMedium,
		Rationale:   "Long-lived access keys widen the window in which a leaked key remains useful.",
		Impact:      "An old, leaked key may remain valid for years, enabling persistent unauthorized access.",
		Remediation: "Rotate the key: create a new one, update consumers, then deactivate and delete the old key.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "1.14"}},
	}
}

func (c iamAccessKeyAge) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || !st.AWS.IAM.Collected {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, u := range st.AWS.IAM.Users {
		for _, k := range u.AccessKeys {
			if !k.Active || k.AgeDays <= keyRotationDays {
				continue
			}
			res := userResource(st.AWS.Account, u.Name)
			res.ID = "access-key/" + k.ID
			desc := fmt.Sprintf("Access key %s for user %q is %d days old (> %d).", k.ID, u.Name, k.AgeDays, keyRotationDays)
			poc := fmt.Sprintf("aws iam list-access-keys --user-name %s", u.Name)
			out = append(out, findings.New(spec, res, desc, poc, now))
		}
	}
	return out, nil
}

// --- console access without MFA --------------------------------------------

type iamConsoleNoMFA struct{}

func (iamConsoleNoMFA) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_iam_console_user_no_mfa", Title: "Console-enabled IAM user has no MFA",
		Provider: "aws", Service: "iam", Severity: findings.SeverityHigh,
		Rationale:   "A user with a console password but no MFA can be accessed with a single stolen credential.",
		Impact:      "A phished or leaked console password grants interactive access with no second factor.",
		Remediation: "Enable an MFA device for the user, or remove console access if it is not needed.",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "1.10"}},
	}
}

func (c iamConsoleNoMFA) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || !st.AWS.IAM.Collected {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, u := range st.AWS.IAM.Users {
		if !u.ConsoleAccess || u.MFAEnabled {
			continue
		}
		res := userResource(st.AWS.Account, u.Name)
		desc := fmt.Sprintf("User %q has console access (a login profile) but no MFA device.", u.Name)
		poc := fmt.Sprintf("aws iam list-mfa-devices --user-name %s", u.Name)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// --- directly-attached admin ------------------------------------------------

type iamUserAdmin struct{}

func (iamUserAdmin) Spec() findings.CheckSpec {
	return findings.CheckSpec{
		ID: "aws_iam_user_admin_policy", Title: "IAM user has AdministratorAccess attached directly",
		Provider: "aws", Service: "iam", Severity: findings.SeverityHigh,
		Rationale:   "Directly attaching AdministratorAccess to a user bypasses group-based least privilege and is hard to audit.",
		Impact:      "Compromise of this user yields full administrative control of the account.",
		Remediation: "Detach AdministratorAccess and grant scoped permissions via groups/roles following least privilege.",
		PoC:         "aws iam list-attached-user-policies --user-name <user>",
		Compliance:  []findings.ComplianceRef{{Framework: "CIS AWS 3.0", Control: "1.16"}},
	}
}

func (c iamUserAdmin) Evaluate(_ *engine.ScanContext, st *state.State) ([]findings.Finding, error) {
	if st.AWS == nil || !st.AWS.IAM.Collected {
		return nil, nil
	}
	spec := c.Spec()
	now := time.Now().UTC()
	var out []findings.Finding
	for _, u := range st.AWS.IAM.Users {
		if !u.AdminAttached {
			continue
		}
		res := userResource(st.AWS.Account, u.Name)
		desc := fmt.Sprintf("User %q has the AdministratorAccess managed policy attached directly.", u.Name)
		poc := fmt.Sprintf("aws iam list-attached-user-policies --user-name %s", u.Name)
		out = append(out, findings.New(spec, res, desc, poc, now))
	}
	return out, nil
}

// joinReasons renders a human list of policy weaknesses.
func joinReasons(reasons []string) string {
	out := ""
	for i, r := range reasons {
		if i > 0 {
			out += "; "
		}
		out += r
	}
	return out
}
