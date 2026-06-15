// Package secrets is the provider-agnostic cloud-side secrets detector (plan
// §9.2). trufflehog/gitleaks scan source code; the cloud control plane — Lambda
// env vars, EC2 userdata, SSM parameters, app settings — is the under-scanned
// goldmine. Collectors gather text surfaces and hand them here; the detector
// flags credential material with a pattern library plus an entropy-gated
// keyed-assignment heuristic.
//
// Privacy is a hard invariant: a Match never carries the raw secret. It records
// a masked rendering (last four characters only), the length, and a secret-safe
// context label. The raw value is deliberately dropped here so nothing
// downstream — findings, the store, the Cairn export, logs — can leak it. (A
// future opt-in --capture-secrets evidence store, plan §9.2, is the only place
// raw material is ever retained, under 0600.)
package secrets

import (
	"math"
	"regexp"
	"strings"
)

// Match is one detected secret, scrubbed for safe storage and export.
type Match struct {
	Detector string  // stable id, e.g. "aws_access_key_id", "private_key", "generic_secret"
	Kind     string  // human label, e.g. "AWS access key id"
	Masked   string  // masked rendering (last 4 chars only) — safe to log/store/export
	LastFour string  // last four characters, for correlation without exposure
	Length   int     // length of the matched secret
	Entropy  float64 // Shannon entropy (bits/char) of the matched value
	Context  string  // secret-safe locator (env var name, parameter name, "userdata") — never the value
}

// signature is one high-confidence regex detector. group selects the capture
// group holding the secret (0 = whole match).
type signature struct {
	detector string
	kind     string
	re       *regexp.Regexp
	group    int
}

// signatures are the high-confidence patterns. Order is irrelevant — every
// surface is swept by all of them and results deduped by (detector,last4,context).
var signatures = []signature{
	// AWS key ids: AKIA (long-term), ASIA (STS temp), AIDA (user unique id),
	// AROA (role unique id). 16 base32 chars after the 4-char prefix.
	{"aws_access_key_id", "AWS access key id",
		regexp.MustCompile(`\b((?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16})\b`), 1},
	// Private key PEM blocks (RSA/EC/DSA/OpenSSH/PGP/generic).
	{"private_key", "Private key",
		regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`), 0},
	// GitHub fine-grained / classic tokens.
	{"github_token", "GitHub token",
		regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255})\b`), 1},
	// Slack tokens.
	{"slack_token", "Slack token",
		regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9-]{10,})\b`), 1},
	// Google API keys.
	{"google_api_key", "Google API key",
		regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), 1},
	// Stripe live secret keys.
	{"stripe_secret_key", "Stripe live secret key",
		regexp.MustCompile(`\b(sk_live_[0-9A-Za-z]{24,})\b`), 1},
	// JWTs (three base64url segments). High-signal when sitting in config.
	{"jwt", "JSON Web Token",
		regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`), 1},
	// Connection strings carrying inline credentials (proto://user:pass@host).
	{"connection_string", "Connection string with inline credentials",
		regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9+.\-]*://[^:@/\s]+:[^@/\s]+@[^\s/'"]+)`), 1},
}

// secretNameHint matches assignment keys / env-var names that name a credential,
// driving the entropy-gated generic detector.
var secretNameHint = regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth|credential|session[_-]?key|encryption[_-]?key)`)

// assignment captures KEY = VALUE / KEY: VALUE pairs out of free text (userdata,
// scripts) so the generic detector can judge the value with its key as context.
var assignment = regexp.MustCompile(`(?im)^[\s>#-]*["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']?([^"'\r\n]{6,})["']?\s*$`)

// placeholder recognizes obvious non-secrets so the generic detector does not
// flag templated, redacted, or example values.
var placeholder = regexp.MustCompile(`(?i)^(\$|\$\{|\{\{|<|%|@@|null|none|true|false|example|changeme|change-me|your[_-]|placeholder|redacted|xxx+|\*\*+|test|dummy|sample|\.\.\.|arn:aws|https?://(?:[^:@]*@)?[^@]*$)`)

// genericEntropyMin is the Shannon-entropy floor (bits/char) for the keyed
// generic detector — high enough to skip prose and short tokens, low enough to
// catch real random secrets.
const genericEntropyMin = 3.5

// Scan sweeps free text (e.g. decoded EC2 userdata) for secrets, tagging each
// hit with the supplied context label. Safe on empty input.
func Scan(text, context string) []Match {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var out []Match
	seen := map[string]bool{}
	add := func(m Match) {
		k := m.Detector + "|" + m.LastFour + "|" + m.Context
		if m.LastFour == "" {
			k = m.Detector + "|" + m.Masked + "|" + m.Context
		}
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, m)
	}

	for _, m := range scanSignatures(text, context) {
		add(m)
	}
	// Keyed assignments in the body: KEY=VALUE where KEY names a secret.
	for _, a := range assignment.FindAllStringSubmatch(text, -1) {
		if m, ok := evalKeyValue(a[1], a[2], context); ok {
			add(m)
		}
	}
	return out
}

// ScanKeyValue evaluates a structured name/value pair (a Lambda env var, an SSM
// parameter). It runs the value through the high-confidence signatures and,
// failing those, the entropy-gated keyed heuristic on (name,value). The context
// defaults to the name when caller passes none.
func ScanKeyValue(name, value, context string) []Match {
	if context == "" {
		context = name
	}
	var out []Match
	out = append(out, scanSignatures(value, context)...)
	if len(out) > 0 {
		return out
	}
	if m, ok := evalKeyValue(name, value, context); ok {
		out = append(out, m)
	}
	return out
}

// scanSignatures runs every high-confidence pattern over text.
func scanSignatures(text, context string) []Match {
	var out []Match
	for _, s := range signatures {
		for _, g := range s.re.FindAllStringSubmatch(text, -1) {
			val := g[s.group]
			if val == "" {
				continue
			}
			out = append(out, newMatch(s.detector, s.kind, val, context))
		}
	}
	return out
}

// evalKeyValue applies the generic heuristic: the key must name a secret, and
// the value must be a high-entropy, non-placeholder token.
func evalKeyValue(name, value, context string) (Match, bool) {
	value = strings.TrimSpace(value)
	if len(value) < 8 || !secretNameHint.MatchString(name) {
		return Match{}, false
	}
	if placeholder.MatchString(value) {
		return Match{}, false
	}
	if strings.ContainsAny(value, " \t") {
		return Match{}, false // a phrase, not a token
	}
	if Entropy(value) < genericEntropyMin {
		return Match{}, false
	}
	if context == "" {
		context = name
	}
	return newMatch("generic_secret", "High-entropy secret in a credential-named field", value, context), true
}

// newMatch builds a scrubbed Match — the raw value is used only to derive the
// mask, length, entropy, and last four, then dropped.
func newMatch(detector, kind, value, context string) Match {
	return Match{
		Detector: detector,
		Kind:     kind,
		Masked:   Mask(value),
		LastFour: lastFour(value),
		Length:   len(value),
		Entropy:  round2(Entropy(value)),
		Context:  context,
	}
}

// Mask renders a secret safe to store: only the last four characters survive,
// behind a fixed-width prefix so the length is not leaked either.
func Mask(s string) string {
	if len(s) <= 4 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}

func lastFour(s string) string {
	if len(s) <= 4 {
		return ""
	}
	return s[len(s)-4:]
}

// Entropy returns the Shannon entropy of s in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]float64
	n := 0
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
		n++
	}
	h := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := c / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
