package secrets

import "testing"

const (
	exampleAKIA   = "AKIAIOSFODNN7EXAMPLE"
	exampleSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" // 40 chars, canonical shape
)

func TestPairAWSKeysKVConventionalNames(t *testing.T) {
	got := PairAWSKeysKV(map[string]string{
		"AWS_ACCESS_KEY_ID":     exampleAKIA,
		"AWS_SECRET_ACCESS_KEY": exampleSecret,
		"LOG_LEVEL":             "debug",
	})
	if len(got) != 1 {
		t.Fatalf("expected one pair, got %d (%+v)", len(got), got)
	}
	if got[0].AccessKeyID != exampleAKIA || got[0].SecretAccessKey != exampleSecret {
		t.Errorf("mispaired: %+v", got[0])
	}
}

func TestPairAWSKeysKVAmbiguousIsSkipped(t *testing.T) {
	// Two access key ids — we must not guess which secret belongs to which.
	got := PairAWSKeysKV(map[string]string{
		"KEY_A":                 exampleAKIA,
		"KEY_B":                 "AKIAI44QH8DHBEXAMPLE", // AKIA + 16 chars, a valid second id
		"AWS_SECRET_ACCESS_KEY": exampleSecret,
	})
	if got != nil {
		t.Errorf("ambiguous surface must not pair, got %+v", got)
	}
}

func TestPairAWSKeysKVIdWithoutSecret(t *testing.T) {
	got := PairAWSKeysKV(map[string]string{"AWS_ACCESS_KEY_ID": exampleAKIA})
	if got != nil {
		t.Errorf("an id with no secret cannot be paired, got %+v", got)
	}
}

func TestPairAWSKeysKVSessionToken(t *testing.T) {
	got := PairAWSKeysKV(map[string]string{
		"AWS_ACCESS_KEY_ID":     "ASIAIOSFODNN7EXAMPLE",
		"AWS_SECRET_ACCESS_KEY": exampleSecret,
		"AWS_SESSION_TOKEN":     "FwoGZXIvYXdzEA" + "0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789",
	})
	if len(got) != 1 || got[0].SessionToken == "" {
		t.Fatalf("expected a paired credential with a session token, got %+v", got)
	}
}

func TestPairAWSKeysText(t *testing.T) {
	ud := "#!/bin/bash\nexport AWS_ACCESS_KEY_ID=" + exampleAKIA +
		"\nexport AWS_SECRET_ACCESS_KEY=" + exampleSecret + "\n"
	got := PairAWSKeysText(ud)
	if len(got) != 1 || got[0].AccessKeyID != exampleAKIA || got[0].SecretAccessKey != exampleSecret {
		t.Fatalf("expected one paired credential from userdata, got %+v", got)
	}
}

func TestCaptureRoundTripAndNilSafe(t *testing.T) {
	var nilCap *Capture
	nilCap.AddAWSKey("x", "y", "", "s", "r", "z") // must not panic
	if nilCap.AWSKeys() != nil {
		t.Error("nil capture must return no keys")
	}

	c := NewCapture()
	c.AddAWSKey(exampleAKIA, exampleSecret, "", "lambda_env", "fn", "us-east-1")
	c.AddAWSKey("", "ignored", "", "", "", "") // empty id ignored
	keys := c.AWSKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 captured key, got %d", len(keys))
	}
	if keys[0].Masked() != "****MPLE" {
		t.Errorf("masked id = %q, want ****MPLE", keys[0].Masked())
	}
}
