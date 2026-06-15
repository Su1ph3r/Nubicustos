package aws

import (
	"encoding/base64"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/Su1ph3r/nubicustos/internal/engine"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func init() { engine.RegisterCollector(&secretsScanCollector{}) }

// secretsScanCollector scans the AWS control plane for embedded credentials (plan
// §9.2) — the under-scanned surface where secrets actually hide. It gathers
// three high-signal text surfaces per region and runs each through the
// provider-agnostic detector:
//
//   - Lambda environment variables
//   - EC2 instance userdata (base64-decoded)
//   - SSM Parameter Store plaintext (String/StringList) parameters
//
// SecureString SSM parameters are skipped: they are encrypted by design (reading
// them would need kms:Decrypt and flagging an intentionally-stored secret is
// noise). Only the masked detection — never the raw value — is recorded in state.
//
// The collector is self-contained (it enumerates its own instances rather than
// reading shared state) because collectors run concurrently and cannot depend on
// each other's ordering. Per-region failures are tolerated so one denied region
// or service never blanks the rest.
type secretsScanCollector struct{}

func (secretsScanCollector) Name() string { return "aws:secrets-scan" }

func (secretsScanCollector) Collect(sc *engine.ScanContext, st *state.State) error {
	if sc.Provider != "aws" {
		return nil
	}
	for _, region := range sc.Regions {
		scanLambdaEnv(sc, region, st)
		scanEC2Userdata(sc, region, st)
		scanSSMParameters(sc, region, st)
	}
	return nil
}

// scanLambdaEnv flags secrets in Lambda function environment variables.
func scanLambdaEnv(sc *engine.ScanContext, region string, st *state.State) {
	client := lambda.NewFromConfig(sc.AWS, func(o *lambda.Options) { o.Region = region })
	p := lambda.NewListFunctionsPaginator(client, &lambda.ListFunctionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, fn := range page.Functions {
			if fn.Environment == nil {
				continue
			}
			name := awssdk.ToString(fn.FunctionName)
			for k, v := range fn.Environment.Variables {
				for _, m := range secrets.ScanKeyValue(k, v, k) {
					st.AddSecretHit(secretHit(m, "lambda_env", name, region, k))
				}
			}
			captureAWSKeysKV(sc, fn.Environment.Variables, "lambda_env", name, region)
		}
	}
}

// scanEC2Userdata flags secrets in EC2 instance userdata (the classic place
// bootstrap scripts hardcode credentials). It enumerates instances itself and
// fetches userdata per instance.
func scanEC2Userdata(sc *engine.ScanContext, region string, st *state.State) {
	client := ec2.NewFromConfig(sc.AWS, func(o *ec2.Options) { o.Region = region })
	p := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, r := range page.Reservations {
			for _, inst := range r.Instances {
				id := awssdk.ToString(inst.InstanceId)
				if id == "" {
					continue
				}
				attr, err := client.DescribeInstanceAttribute(sc.Ctx, &ec2.DescribeInstanceAttributeInput{
					InstanceId: inst.InstanceId,
					Attribute:  ec2types.InstanceAttributeNameUserData,
				})
				if err != nil || attr.UserData == nil {
					continue
				}
				decoded := decodeUserData(awssdk.ToString(attr.UserData.Value))
				if decoded == "" {
					continue
				}
				for _, m := range secrets.Scan(decoded, "userdata") {
					st.AddSecretHit(secretHit(m, "ec2_userdata", id, region, m.Context))
				}
				captureAWSKeysText(sc, decoded, "ec2_userdata", id, region)
			}
		}
	}
}

// scanSSMParameters flags secrets in plaintext SSM parameters. SecureString
// parameters are intentionally encrypted and excluded.
func scanSSMParameters(sc *engine.ScanContext, region string, st *state.State) {
	client := ssm.NewFromConfig(sc.AWS, func(o *ssm.Options) { o.Region = region })

	var plaintext []string
	dp := ssm.NewDescribeParametersPaginator(client, &ssm.DescribeParametersInput{})
	for dp.HasMorePages() {
		page, err := dp.NextPage(sc.Ctx)
		if err != nil {
			return
		}
		for _, meta := range page.Parameters {
			if meta.Type == ssmtypes.ParameterTypeSecureString {
				continue
			}
			if n := awssdk.ToString(meta.Name); n != "" {
				plaintext = append(plaintext, n)
			}
		}
	}

	// GetParameters accepts up to 10 names per call; no decryption needed for
	// String/StringList values.
	for _, chunk := range chunk(plaintext, 10) {
		out, err := client.GetParameters(sc.Ctx, &ssm.GetParametersInput{
			Names:          chunk,
			WithDecryption: awssdk.Bool(false),
		})
		if err != nil {
			continue
		}
		for _, prm := range out.Parameters {
			name := awssdk.ToString(prm.Name)
			value := awssdk.ToString(prm.Value)
			for _, m := range secrets.ScanKeyValue(name, value, name) {
				st.AddSecretHit(secretHit(m, "ssm_parameter", name, region, name))
			}
		}
	}
}

// captureAWSKeysKV pairs an access-key-id with its secret inside one key/value
// surface and hands the raw pair to the capture sink (only when --capture-secrets
// wired a sink). SSM is intentionally not paired: a single-value parameter cannot
// hold both halves, and pairing across parameters would be a guess.
func captureAWSKeysKV(sc *engine.ScanContext, kv map[string]string, surface, resource, region string) {
	if sc.SecretSink == nil {
		return
	}
	for _, c := range secrets.PairAWSKeysKV(kv) {
		sc.SecretSink.AddAWSKey(c.AccessKeyID, c.SecretAccessKey, c.SessionToken, surface, resource, region)
	}
}

// captureAWSKeysText pairs an access-key-id with a nearby secret in free text
// (decoded userdata) and feeds the capture sink.
func captureAWSKeysText(sc *engine.ScanContext, text, surface, resource, region string) {
	if sc.SecretSink == nil {
		return
	}
	for _, c := range secrets.PairAWSKeysText(text) {
		sc.SecretSink.AddAWSKey(c.AccessKeyID, c.SecretAccessKey, c.SessionToken, surface, resource, region)
	}
}

// secretHit folds a detector Match plus its source into a state record.
func secretHit(m secrets.Match, surface, resource, region, locator string) state.SecretHit {
	return state.SecretHit{
		Detector: m.Detector,
		Kind:     m.Kind,
		Surface:  surface,
		Resource: resource,
		Region:   region,
		Locator:  locator,
		Masked:   m.Masked,
		LastFour: m.LastFour,
		Entropy:  m.Entropy,
	}
}

// decodeUserData base64-decodes EC2 userdata; if it is not valid base64 it is
// returned as-is (some callers store plaintext).
func decodeUserData(s string) string {
	if s == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return string(b)
	}
	return s
}

// chunk splits ss into slices of at most n.
func chunk(ss []string, n int) [][]string {
	var out [][]string
	for i := 0; i < len(ss); i += n {
		end := i + n
		if end > len(ss) {
			end = len(ss)
		}
		out = append(out, ss[i:end])
	}
	return out
}
