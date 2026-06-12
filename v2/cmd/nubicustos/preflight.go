package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/auth"
	"github.com/Su1ph3r/nubicustos/internal/preflight"
)

type preflightFlags struct {
	provider      string
	profile       string
	region        string
	mfaSerial     string
	mfaToken      string
	ssoLogin      bool
	nonInteract   bool
	tools         []string
	format        string
	noProbe       bool
	writePolicies string
}

func newPreflightCmd() *cobra.Command {
	f := &preflightFlags{}
	cmd := &cobra.Command{
		Use:   "preflight",
		Short: "Check whether a credential has the access each scanning tool needs",
		Long: "Verify, read-only and before any scan, that the identity behind a\n" +
			"credential holds the permissions Nubicustos's own checks and the optional\n" +
			"external tools (Prowler, ScoutSuite, CloudSploit) require. Leads with IAM\n" +
			"policy simulation for exact per-action allow/deny and cross-checks with a\n" +
			"thin live read-probe (catching SCP/boundary denials simulation cannot see).\n" +
			"Reports exactly what is missing and emits an attachable least-privilege\n" +
			"policy to grant it — suitable to hand to a client team.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPreflight(cmd.Context(), f)
		},
	}
	pf := cmd.Flags()
	pf.StringVar(&f.provider, "provider", "aws", "cloud provider (aws)")
	pf.StringVar(&f.profile, "profile", "", "AWS named profile")
	pf.StringVar(&f.region, "region", "", "AWS region for the session")
	pf.StringVar(&f.mfaSerial, "mfa-serial", "", "AWS MFA device ARN")
	pf.StringVar(&f.mfaToken, "mfa-token", "", "pre-supplied TOTP code (non-interactive MFA)")
	pf.BoolVar(&f.ssoLogin, "sso-login", false, "run `aws sso login` automatically if the SSO session is expired")
	pf.BoolVar(&f.nonInteract, "non-interactive", false, "never prompt; fail fast if MFA input is required")
	pf.StringSliceVar(&f.tools, "tools", nil, "tools to check by key (default: all; e.g. nubicustos,prowler)")
	pf.StringVar(&f.format, "format", "text", "output format: text | json")
	pf.BoolVar(&f.noProbe, "no-probe", false, "skip the live read-probe cross-check (simulation only)")
	pf.StringVar(&f.writePolicies, "write-policies", "", "directory to write a remediation policy JSON per non-ready tool")
	return cmd
}

func runPreflight(ctx context.Context, f *preflightFlags) error {
	if strings.ToLower(f.provider) != "aws" {
		return fmt.Errorf("preflight currently supports --provider aws")
	}

	// Validate the tool selection before authenticating, so a typo fails fast
	// without resolving credentials.
	tools, err := selectTools(f.tools)
	if err != nil {
		return err
	}

	prompter := auth.NewCLIPrompter(f.mfaToken, !f.nonInteract)
	cfg, ident, path, err := auth.ResolveAWS(ctx, auth.AWSOptions{
		Profile:       f.profile,
		Region:        f.region,
		MFASerial:     f.mfaSerial,
		MFAToken:      f.mfaToken,
		AllowSSOLogin: f.ssoLogin,
	}, prompter)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "authenticated to AWS account %s as %s (via %s)\n", ident.Account, ident.ARN, path)

	opts := preflight.Options{
		Provider:  "aws",
		Identity:  ident.ARN,
		Account:   ident.Account,
		Tools:     tools,
		Simulator: iam.NewFromConfig(cfg),
	}
	if !f.noProbe {
		opts.Prober = &awsProber{cfg: cfg}
	}

	rep := preflight.Evaluate(ctx, opts)

	if f.writePolicies != "" {
		if err := writeRemediationPolicies(f.writePolicies, rep); err != nil {
			return err
		}
	}

	if f.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		printPreflight(os.Stdout, rep)
	}

	// Non-zero exit when access is not fully ready, so the check can gate a pipeline.
	if rep.Overall != preflight.ReadinessReady {
		return fmt.Errorf("preflight: overall access is %s (see report above)", rep.Overall)
	}
	return nil
}

// selectTools returns the requested catalog tools (all if keys is empty).
func selectTools(keys []string) ([]preflight.Tool, error) {
	if len(keys) == 0 {
		return preflight.AWSTools, nil
	}
	var out []preflight.Tool
	for _, k := range keys {
		t, ok := preflight.AWSToolByKey(strings.TrimSpace(k))
		if !ok {
			return nil, fmt.Errorf("unknown tool %q (known: nubicustos, prowler, scoutsuite, cloudsploit)", k)
		}
		out = append(out, t)
	}
	return out, nil
}

func printPreflight(w *os.File, rep preflight.Report) {
	fmt.Fprintf(w, "PREFLIGHT — %s · account %s · %s\n", rep.Provider, rep.Account, rep.Identity)
	fmt.Fprintf(w, "method: %s\n\n", rep.Method)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, t := range rep.Tools {
		fmt.Fprintf(tw, "[%s]\t%s\t%d/%d permission(s)\n",
			strings.ToUpper(string(t.Readiness)), t.Name, len(t.Allowed), len(t.Actions))
	}
	tw.Flush()
	fmt.Fprintf(w, "\nOVERALL: %s\n", strings.ToUpper(string(rep.Overall)))

	for _, t := range rep.Tools {
		if t.Readiness == preflight.ReadinessReady {
			continue
		}
		fmt.Fprintf(w, "\n%s — %s\n", t.Name, t.Remediate.Summary)
		if len(t.Denied) > 0 {
			fmt.Fprintf(w, "  missing: %s\n", strings.Join(t.Denied, ", "))
		}
		if len(t.Conflicts) > 0 {
			fmt.Fprintf(w, "  runtime-blocked (SCP/boundary): %s\n", strings.Join(t.Conflicts, ", "))
		}
		if len(t.Unknown) > 0 {
			fmt.Fprintf(w, "  undetermined: %s\n", strings.Join(t.Unknown, ", "))
		}
	}
}

// writeRemediationPolicies writes one <key>.policy.json per non-ready tool.
func writeRemediationPolicies(dir string, rep preflight.Report) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating policy dir: %w", err)
	}
	for _, t := range rep.Tools {
		if t.Remediate.PolicyDocument == "" {
			continue
		}
		p := filepath.Join(dir, t.Key+".policy.json")
		if err := os.WriteFile(p, []byte(t.Remediate.PolicyDocument), 0o600); err != nil {
			return fmt.Errorf("writing %s: %w", p, err)
		}
		fmt.Fprintf(os.Stderr, "wrote remediation policy for %s → %s\n", t.Name, p)
	}
	return nil
}

// awsProber implements preflight.Prober with one representative read call per
// service. Access-denied (including via SCP) → denied; success → allowed; any
// other error or an action it does not probe → unknown (simulation covers it).
type awsProber struct {
	cfg awssdk.Config
}

func (p *awsProber) Probe(ctx context.Context, action string) preflight.Decision {
	var err error
	switch action {
	case "sts:GetCallerIdentity":
		_, err = sts.NewFromConfig(p.cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	case "s3:ListAllMyBuckets":
		_, err = s3.NewFromConfig(p.cfg).ListBuckets(ctx, &s3.ListBucketsInput{})
	case "iam:ListUsers":
		_, err = iam.NewFromConfig(p.cfg).ListUsers(ctx, &iam.ListUsersInput{MaxItems: awssdk.Int32(1)})
	case "ec2:DescribeInstances":
		_, err = ec2.NewFromConfig(p.cfg).DescribeInstances(ctx, &ec2.DescribeInstancesInput{MaxResults: awssdk.Int32(5)})
	case "rds:DescribeDBInstances":
		_, err = rds.NewFromConfig(p.cfg).DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{MaxRecords: awssdk.Int32(20)})
	case "cloudtrail:DescribeTrails":
		_, err = cloudtrail.NewFromConfig(p.cfg).DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
	case "kms:ListKeys":
		_, err = kms.NewFromConfig(p.cfg).ListKeys(ctx, &kms.ListKeysInput{Limit: awssdk.Int32(1)})
	case "guardduty:ListDetectors":
		_, err = guardduty.NewFromConfig(p.cfg).ListDetectors(ctx, &guardduty.ListDetectorsInput{MaxResults: awssdk.Int32(1)})
	case "acm:ListCertificates":
		_, err = acm.NewFromConfig(p.cfg).ListCertificates(ctx, &acm.ListCertificatesInput{MaxItems: awssdk.Int32(1)})
	case "secretsmanager:ListSecrets":
		_, err = secretsmanager.NewFromConfig(p.cfg).ListSecrets(ctx, &secretsmanager.ListSecretsInput{MaxResults: awssdk.Int32(1)})
	case "elasticloadbalancing:DescribeLoadBalancers":
		_, err = elbv2.NewFromConfig(p.cfg).DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{PageSize: awssdk.Int32(1)})
	case "config:DescribeConfigurationRecorders":
		_, err = configservice.NewFromConfig(p.cfg).DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{})
	default:
		return preflight.DecisionUnknown // not probed; simulation decides
	}
	switch {
	case err == nil:
		return preflight.DecisionAllowed
	case isAccessDenied(err):
		return preflight.DecisionDenied
	default:
		return preflight.DecisionUnknown // reachable-but-other-error; don't penalize
	}
}

func isAccessDenied(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError", "Client.UnauthorizedOperation":
			return true
		}
	}
	return false
}
