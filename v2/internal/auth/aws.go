package auth

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// defaultRegion is used only when neither the profile nor the flags specify one;
// STS/S3 clients require a region even for global calls.
const defaultRegion = "us-east-1"

// AWSOptions describes how to authenticate to AWS for a scan.
type AWSOptions struct {
	Profile         string
	Region          string
	MFASerial       string        // overrides profile mfa_serial; required for the static-keys + MFA-condition path
	MFAToken        string        // optional pre-supplied TOTP (non-interactive)
	SessionDuration time.Duration // GetSessionToken/AssumeRole lifetime; 0 => 12h
	AllowSSOLogin   bool          // shell out to `aws sso login` when the SSO token is missing/expired
}

// Identity is the validated caller identity returned by sts:GetCallerIdentity.
type Identity struct {
	Account string
	ARN     string
	UserID  string
}

// authPath records which credential strategy was selected, for logging.
type authPath string

const (
	pathSSO       authPath = "sso"
	pathAssumeMFA authPath = "assume-role"
	pathSession   authPath = "get-session-token"
	pathDefault   authPath = "default-chain"
)

// ResolveAWS performs the up-front credential resolution for AWS, covering all
// four paths (SSO, AssumeRole+MFA, static-keys+MFA-condition via GetSessionToken,
// and the default chain). It returns a ready aws.Config whose credentials are
// cached and already validated with a single GetCallerIdentity call — so the
// concurrent scan never re-authenticates or re-prompts.
func ResolveAWS(ctx context.Context, o AWSOptions, p Prompter) (aws.Config, Identity, authPath, error) {
	profileName := o.Profile
	if profileName == "" {
		profileName = "default"
	}

	// Inspect the shared profile to decide the path. A missing profile is fine
	// (env creds / instance role) — we fall back to the default chain.
	shared, sharedErr := config.LoadSharedConfigProfile(ctx, profileName)

	mfaSerial := o.MFASerial
	if mfaSerial == "" && sharedErr == nil {
		mfaSerial = shared.MFASerial
	}

	switch {
	case sharedErr == nil && isSSOProfile(shared):
		cfg, ident, err := resolveSSO(ctx, o)
		return cfg, ident, pathSSO, err

	case sharedErr == nil && shared.RoleARN != "":
		cfg, ident, err := resolveAssumeRole(ctx, o, mfaSerial, p)
		return cfg, ident, pathAssumeMFA, err

	case mfaSerial != "":
		// Static long-term keys with an MFA-condition policy and no role. The
		// SDK does NOT auto-call GetSessionToken here — we must do it ourselves.
		cfg, ident, err := resolveSessionToken(ctx, o, mfaSerial, p)
		return cfg, ident, pathSession, err

	default:
		cfg, ident, err := resolveDefault(ctx, o)
		return cfg, ident, pathDefault, err
	}
}

// isSSOProfile reports whether a shared profile is configured for IAM Identity
// Center / SSO (either the modern sso_session form or the legacy inline form).
func isSSOProfile(sc config.SharedConfig) bool {
	return sc.SSOSession != nil || sc.SSOAccountID != "" || sc.SSOStartURL != ""
}

// baseLoadOptions builds the common LoadDefaultConfig options (profile + region).
func baseLoadOptions(o AWSOptions) []func(*config.LoadOptions) error {
	opts := []func(*config.LoadOptions) error{}
	if o.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(o.Profile))
	}
	if o.Region != "" {
		opts = append(opts, config.WithRegion(o.Region))
	}
	return opts
}

// resolveDefault uses the standard credential chain (env, profile static keys,
// instance role, etc.) with no interactive step.
func resolveDefault(ctx context.Context, o AWSOptions) (aws.Config, Identity, error) {
	cfg, err := config.LoadDefaultConfig(ctx, baseLoadOptions(o)...)
	if err != nil {
		return cfg, Identity{}, fmt.Errorf("loading aws config: %w", err)
	}
	ensureRegion(&cfg)
	ident, err := validate(ctx, cfg)
	return cfg, ident, err
}

// resolveAssumeRole loads a profile that assumes a role, wiring an MFA token
// provider when a serial is present so the SDK can satisfy mfa_serial.
func resolveAssumeRole(ctx context.Context, o AWSOptions, mfaSerial string, p Prompter) (aws.Config, Identity, error) {
	opts := baseLoadOptions(o)
	opts = append(opts, config.WithAssumeRoleCredentialOptions(func(ao *stscreds.AssumeRoleOptions) {
		if mfaSerial != "" {
			ao.SerialNumber = aws.String(mfaSerial)
			ao.TokenProvider = func() (string, error) { return p.TOTP(ctx, mfaSerial) }
		}
		if o.SessionDuration > 0 {
			ao.Duration = o.SessionDuration
		}
	}))
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return cfg, Identity{}, fmt.Errorf("loading assume-role config: %w", err)
	}
	ensureRegion(&cfg)
	ident, err := validate(ctx, cfg)
	return cfg, ident, err
}

// resolveSessionToken handles the static-keys + MFA-condition case: take the
// profile's long-term credentials, exchange them via sts:GetSessionToken for a
// short-lived MFA-present session, and wrap the result in a cached static provider.
func resolveSessionToken(ctx context.Context, o AWSOptions, mfaSerial string, p Prompter) (aws.Config, Identity, error) {
	base, err := config.LoadDefaultConfig(ctx, baseLoadOptions(o)...)
	if err != nil {
		return base, Identity{}, fmt.Errorf("loading base config: %w", err)
	}
	ensureRegion(&base)

	code, err := p.TOTP(ctx, mfaSerial)
	if err != nil {
		return base, Identity{}, err
	}

	dur := o.SessionDuration
	if dur <= 0 {
		dur = 12 * time.Hour
	}
	durSecs := int32(dur.Seconds())

	out, err := sts.NewFromConfig(base).GetSessionToken(ctx, &sts.GetSessionTokenInput{
		SerialNumber:    aws.String(mfaSerial),
		TokenCode:       aws.String(code),
		DurationSeconds: aws.Int32(durSecs),
	})
	if err != nil {
		return base, Identity{}, fmt.Errorf("sts:GetSessionToken (check MFA code/serial): %w", err)
	}
	c := out.Credentials

	cfg := base
	cfg.Credentials = aws.NewCredentialsCache(
		credentials.NewStaticCredentialsProvider(*c.AccessKeyId, *c.SecretAccessKey, *c.SessionToken),
	)
	ident, err := validate(ctx, cfg)
	return cfg, ident, err
}

// resolveSSO loads an SSO profile. If the cached SSO token is missing/expired
// the first validation fails; when permitted we shell out to `aws sso login`
// (browser-based, MFA handled by the IdP) and retry once. Native ssooidc device
// flow is a planned follow-up; the CLI fallback works on a local workstation.
func resolveSSO(ctx context.Context, o AWSOptions) (aws.Config, Identity, error) {
	load := func() (aws.Config, error) {
		return config.LoadDefaultConfig(ctx, baseLoadOptions(o)...)
	}
	cfg, err := load()
	if err != nil {
		return cfg, Identity{}, fmt.Errorf("loading sso config: %w", err)
	}
	ensureRegion(&cfg)

	ident, err := validate(ctx, cfg)
	if err == nil {
		return cfg, ident, nil
	}
	if !o.AllowSSOLogin {
		return cfg, Identity{}, fmt.Errorf("SSO session invalid or expired (run `aws sso login --profile %s`): %w", o.Profile, err)
	}
	if err := ssoLogin(ctx, o.Profile); err != nil {
		return cfg, Identity{}, err
	}
	cfg, err = load()
	if err != nil {
		return cfg, Identity{}, fmt.Errorf("reloading sso config after login: %w", err)
	}
	ensureRegion(&cfg)
	ident, err = validate(ctx, cfg)
	return cfg, ident, err
}

// ssoLogin shells out to the AWS CLI to perform an interactive SSO login.
func ssoLogin(ctx context.Context, profile string) error {
	args := []string{"sso", "login"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	cmd := exec.CommandContext(ctx, "aws", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.Error
		if errors.As(err, &ee) {
			return fmt.Errorf("`aws sso login` failed (is the AWS CLI installed?): %w", err)
		}
		return fmt.Errorf("`aws sso login` failed: %w", err)
	}
	return nil
}

// ensureRegion guarantees a region is set so global service calls succeed.
func ensureRegion(cfg *aws.Config) {
	if cfg.Region == "" {
		cfg.Region = defaultRegion
	}
}

// validate proves the credentials work (and forces a single up-front Retrieve)
// by calling sts:GetCallerIdentity.
func validate(ctx context.Context, cfg aws.Config) (Identity, error) {
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, fmt.Errorf("validating credentials (sts:GetCallerIdentity): %w", err)
	}
	return Identity{
		Account: aws.ToString(out.Account),
		ARN:     aws.ToString(out.Arn),
		UserID:  aws.ToString(out.UserId),
	}, nil
}
