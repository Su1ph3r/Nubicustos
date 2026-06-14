package secrets

import (
	"strings"
	"testing"
)

func hasDetector(ms []Match, detector string) *Match {
	for i := range ms {
		if ms[i].Detector == detector {
			return &ms[i]
		}
	}
	return nil
}

func TestScanSignatures(t *testing.T) {
	cases := []struct {
		name     string
		text     string
		detector string
	}{
		{"aws access key", "config AKIAIOSFODNN7EXAMPLE here", "aws_access_key_id"},
		{"sts temp key", "ASIAIOSFODNN7EXAMPLE", "aws_access_key_id"},
		{"github token", "token=ghp_" + strings.Repeat("a", 36), "github_token"},
		{"slack token", "xoxb-1234567890-" + "abcdefghijklmno", "slack_token"},
		{"google api key", "AIza" + strings.Repeat("b", 35), "google_api_key"},
		{"stripe key", "sk_live_" + strings.Repeat("c", 24), "stripe_secret_key"},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "private_key"},
		{"connection string", "DATABASE_URL postgres://admin:s3cr3tP4ss@db.internal:5432/app", "connection_string"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Scan(c.text, "test")
			if hasDetector(got, c.detector) == nil {
				t.Fatalf("expected detector %q in %+v", c.detector, got)
			}
		})
	}
}

func TestScanMasksAndNeverLeaksRaw(t *testing.T) {
	raw := "AKIAIOSFODNN7EXAMPLE"
	got := Scan("key="+raw, "env")
	m := hasDetector(got, "aws_access_key_id")
	if m == nil {
		t.Fatal("expected an aws_access_key_id match")
	}
	if strings.Contains(m.Masked, raw) || m.Masked != "****"+raw[len(raw)-4:] {
		t.Errorf("masked value leaks or is malformed: %q", m.Masked)
	}
	if m.LastFour != "MPLE" {
		t.Errorf("last four = %q, want MPLE", m.LastFour)
	}
	// The whole Match, rendered, must not contain the raw secret.
	for _, field := range []string{m.Masked, m.LastFour, m.Context, m.Kind, m.Detector} {
		if strings.Contains(field, raw) {
			t.Errorf("raw secret leaked in field %q", field)
		}
	}
}

func TestScanKeyValueGenericHeuristic(t *testing.T) {
	// Secret-named key + high-entropy value => flagged.
	got := ScanKeyValue("DB_PASSWORD", "f3Q8zL1pX7vK0mNw2 Td", "")
	if hasDetector(got, "generic_secret") != nil {
		t.Fatal("value with a space is a phrase, must not be flagged")
	}
	got = ScanKeyValue("DB_PASSWORD", "f3Q8zL1pX7vK0mNw2RtY", "")
	if hasDetector(got, "generic_secret") == nil {
		t.Fatalf("expected generic_secret for high-entropy password, got %+v", got)
	}
}

func TestGenericHeuristicSkipsNonSecrets(t *testing.T) {
	skip := []struct{ name, value string }{
		{"BUILD_REVISION", "f3Q8zL1pX7vK0mNw2RtY"}, // key not secret-named
		{"API_KEY", "changeme"},                    // placeholder
		{"PASSWORD", "${DB_PASSWORD}"},             // templated reference
		{"SECRET", "your-secret-here"},             // example
		{"TOKEN", "aaaaaaaaaaaa"},                  // low entropy
		{"PASSWORD", "short"},                      // too short
		{"CLIENT_SECRET", "<redacted>"},            // redacted
	}
	for _, s := range skip {
		t.Run(s.name+"="+s.value, func(t *testing.T) {
			if got := ScanKeyValue(s.name, s.value, ""); len(got) != 0 {
				t.Errorf("expected no match for %s=%s, got %+v", s.name, s.value, got)
			}
		})
	}
}

func TestScanDedupes(t *testing.T) {
	raw := "AKIAIOSFODNN7EXAMPLE"
	got := Scan(raw+" and again "+raw, "ctx")
	n := 0
	for _, m := range got {
		if m.Detector == "aws_access_key_id" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("expected the repeated key deduped to 1, got %d", n)
	}
}

func TestScanEmpty(t *testing.T) {
	if got := Scan("   \n\t ", "x"); got != nil {
		t.Errorf("expected nil on blank input, got %+v", got)
	}
}

func TestEntropy(t *testing.T) {
	if Entropy("aaaa") != 0 {
		t.Errorf("uniform string entropy should be 0, got %v", Entropy("aaaa"))
	}
	if Entropy("ab") != 1 {
		t.Errorf("two-symbol balanced entropy should be 1 bit, got %v", Entropy("ab"))
	}
	if h := Entropy("f3Q8zL1pX7vK0mNw2RtY"); h < 3.5 {
		t.Errorf("random-looking string should exceed 3.5 bits/char, got %v", h)
	}
}
