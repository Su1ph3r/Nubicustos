package secrets

import (
	"regexp"
	"strings"
	"sync"
)

// AWSKeyCredential is a raw AWS access-key pair lifted from a control-plane
// surface, retained only under the opt-in --capture-secrets so the active-
// validation pass (§9.1) can confirm liveness with sts:GetCallerIdentity. This
// is the one place raw secret material is kept; it never enters state, findings,
// the store, or any export.
type AWSKeyCredential struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // required for ASIA (STS temporary) keys; empty for AKIA
	Surface         string // lambda_env | ec2_userdata | ssm_parameter
	Resource        string // owning function / instance / parameter
	Region          string
}

// Masked renders the access key id with only its last four characters, for
// secret-safe display in evidence.
func (c AWSKeyCredential) Masked() string { return Mask(c.AccessKeyID) }

// Capture is the opt-in in-process raw-secret sink. It holds the material the
// detector drops so the validation pass can prove liveness, then is discarded
// when the scan command returns — raw secrets are never persisted. A nil
// *Capture means capture is disabled (the default); all methods are nil-safe.
type Capture struct {
	mu      sync.Mutex
	awsKeys []AWSKeyCredential
}

// NewCapture returns an enabled in-process capture sink.
func NewCapture() *Capture { return &Capture{} }

// AddAWSKey records a captured AWS key pair. Implements engine.SecretSink. Safe
// on a nil receiver (capture disabled) and ignores entries with no access key id.
func (c *Capture) AddAWSKey(accessKeyID, secretAccessKey, sessionToken, surface, resource, region string) {
	if c == nil || accessKeyID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.awsKeys = append(c.awsKeys, AWSKeyCredential{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Surface:         surface,
		Resource:        resource,
		Region:          region,
	})
}

// AWSKeys returns a copy of the captured AWS key pairs.
func (c *Capture) AWSKeys() []AWSKeyCredential {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AWSKeyCredential(nil), c.awsKeys...)
}

// awsKeyID matches a usable AWS access key id (AKIA long-term, ASIA temporary).
// AIDA/AROA are unique-id prefixes, not credentials, so they are excluded here.
var awsKeyID = regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`)

// awsSecretShape matches a value shaped like an AWS secret access key: 40
// characters of base64 alphabet. Used only to find the secret half of a pair.
var awsSecretShape = regexp.MustCompile(`(?:^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+=]|=|$)`)

// sessionTokenName / secretKeyName recognize the conventional field names so a
// key/value surface pairs the right value to the right slot.
var (
	sessionTokenName = regexp.MustCompile(`(?i)(session[_-]?token|security[_-]?token|aws_session)`)
	secretKeyName    = regexp.MustCompile(`(?i)(secret[_-]?access[_-]?key|aws_secret|secret_key)`)
)

// PairAWSKeysKV pairs an AWS access key id with its secret (and session token,
// for ASIA) inside one key/value surface — a Lambda env map. It is deliberately
// conservative: it pairs only when the surface holds exactly one access key id,
// so it never guesses which secret belongs to which of several keys.
func PairAWSKeysKV(kv map[string]string) []AWSKeyCredential {
	var ids []string
	var secretByName, sessionByName string
	var secretCandidates []string

	for name, v := range kv {
		v = strings.TrimSpace(v)
		if m := awsKeyID.FindString(v); m != "" {
			ids = append(ids, m)
			continue
		}
		if secretKeyName.MatchString(name) && looksLikeSecret(v) {
			secretByName = v
		}
		if sessionTokenName.MatchString(name) && len(v) >= 100 {
			sessionByName = v
		}
		if shape := awsSecretShape.FindStringSubmatch(v); shape != nil && v == shape[1] {
			secretCandidates = append(secretCandidates, v)
		}
	}

	if len(ids) != 1 {
		return nil // zero, or ambiguous — do not guess pairings
	}
	secret := secretByName
	if secret == "" && len(secretCandidates) == 1 {
		secret = secretCandidates[0]
	}
	if secret == "" {
		return nil // an id with no recoverable secret cannot be liveness-checked
	}
	return []AWSKeyCredential{{
		AccessKeyID:     ids[0],
		SecretAccessKey: secret,
		SessionToken:    sessionByName,
	}}
}

// PairAWSKeysText pairs an access key id with a nearby secret in free text
// (decoded EC2 userdata). Conservative in the same way: exactly one id, and it
// takes the first 40-char secret-shaped token that is not the id itself.
func PairAWSKeysText(text string) []AWSKeyCredential {
	idMatches := awsKeyID.FindAllString(text, -1)
	if len(uniqueStrings(idMatches)) != 1 {
		return nil
	}
	id := idMatches[0]

	for _, m := range awsSecretShape.FindAllStringSubmatch(text, -1) {
		cand := m[1]
		if cand == id || strings.HasPrefix(cand, "AKIA") || strings.HasPrefix(cand, "ASIA") {
			continue
		}
		return []AWSKeyCredential{{AccessKeyID: id, SecretAccessKey: cand}}
	}
	return nil
}

// looksLikeSecret accepts a value as a plausible secret access key: 40 base64
// characters (the canonical shape) or, failing that, a long high-entropy token.
func looksLikeSecret(v string) bool {
	if len(v) == 40 && awsSecretShape.MatchString(v+" ") {
		return true
	}
	return len(v) >= 20 && Entropy(v) >= genericEntropyMin
}

func uniqueStrings(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
