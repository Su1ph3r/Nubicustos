package validate

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/secrets"
)

func init() { Register(&exposedSecretLiveness{}) }

// WhoAmIResult is the outcome of probing a captured AWS credential.
type WhoAmIResult struct {
	ARN     string // identity the credential maps to (when live)
	Account string
	Live    bool // true when AWS accepted the credential; false when it was rejected (invalid/expired)
}

// AWSKeyProber confirms a captured static AWS credential read-only via
// sts:GetCallerIdentity — the canonical "is this key live, and whose is it"
// whoami. Implemented over the SDK in NewAWSKeyProber; faked in tests. A nil
// error with Live=false means AWS authoritatively rejected the key (expired or
// invalid); a non-nil error means the probe itself could not complete (network /
// timeout), which the validator reports as blocked.
type AWSKeyProber interface {
	WhoAmI(ctx context.Context, cred secrets.AWSKeyCredential) (WhoAmIResult, error)
}

// KeyLiveness is the structured outcome of probing one captured AWS key: whether
// AWS accepted it (Live), the identity it maps to (ARN/Account, set only when
// live), or whether the probe could not complete (Blocked). It is the join key
// the attack-chain synthesis uses to correlate an exposed credential with the
// privileges of the identity it unlocks.
type KeyLiveness struct {
	Cred    secrets.AWSKeyCredential
	Live    bool
	Blocked bool
	ARN     string
	Account string
}

// ProbeCapturedKeys confirms each captured key read-only via the prober and
// returns one KeyLiveness per key (same order). A transport/timeout failure on a
// key marks it Blocked rather than aborting the batch; only context cancellation
// stops the run and returns the partial results with the cancellation error.
// This is the single place captured-key whoami probing happens — both the
// exposed-secret evidence and the attack-chain synthesis consume its output, so
// a key is probed exactly once per scan.
func ProbeCapturedKeys(ctx context.Context, keys []secrets.AWSKeyCredential, prober AWSKeyProber) ([]KeyLiveness, error) {
	if prober == nil {
		return nil, nil
	}
	out := make([]KeyLiveness, 0, len(keys))
	for _, c := range keys {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		res, err := prober.WhoAmI(ctx, c)
		kl := KeyLiveness{Cred: c}
		switch {
		case err != nil:
			kl.Blocked = true
		case res.Live:
			kl.Live = true
			kl.ARN = res.ARN
			kl.Account = res.Account
		}
		out = append(out, kl)
	}
	return out, nil
}

// exposedSecretLiveness is the §9.2→§9.1 cross-link: it takes the AWS key pairs
// the secrets collector captured from the control plane (only under
// --capture-secrets) and proves, read-only, whether each is still live by
// calling sts:GetCallerIdentity. A masked posture finding ("a secret is in this
// Lambda env") becomes a runtime-proven one ("that key is live and maps to
// arn:aws:iam::…:user/deploy").
//
// Safety: read-only (a whoami changes nothing), stops at the proven primitive
// (identity disclosure — it never uses the key for anything else), and never
// emits raw secret material — evidence carries only the masked key id and the
// ARN the key resolves to.
type exposedSecretLiveness struct{}

func (*exposedSecretLiveness) CheckID() string     { return "aws_exposed_secret" }
func (*exposedSecretLiveness) BlastRadius() string { return BlastRadiusNone }

// Vantage reports VantageExternal here for one specific reason: this method only
// governs whether the standalone `validate` command resolves a *scan session*
// before running. This validator never uses the scan session — it needs the
// captured key material, which exists only during an inline --capture-secrets
// scan and is never reconstructable from a stored scan. So the standalone command
// must not resolve a session on its behalf. (The proof itself is obtained by
// presenting a credential; the emitted Evidence is correctly labelled
// VantageAuthenticated.)
func (*exposedSecretLiveness) Vantage() findings.Vantage { return findings.VantageExternal }

func (v *exposedSecretLiveness) Validate(ctx context.Context, env Env, f findings.Finding) (*findings.Evidence, error) {
	// Reuse pre-probed liveness when the caller supplied it (the scan path probes
	// once and feeds it here); otherwise probe on demand. Capture is opt-in: with
	// no captured keys (or no prober) there is nothing to confirm and the masked
	// finding stands on its own.
	results := env.CapturedKeyLiveness
	if results == nil {
		if len(env.CapturedAWSKeys) == 0 || env.AWSKeyProber == nil {
			return nil, nil
		}
		var err error
		if results, err = ProbeCapturedKeys(ctx, env.CapturedAWSKeys, env.AWSKeyProber); err != nil {
			return nil, err
		}
	}
	if len(results) == 0 {
		return nil, nil
	}

	type line struct {
		masked, surface, resource, arn string
		live, blocked                  bool
	}
	var lines []line
	live, blocked := 0, 0

	for _, kl := range results {
		l := line{masked: kl.Cred.Masked(), surface: kl.Cred.Surface, resource: kl.Cred.Resource}
		switch {
		case kl.Blocked:
			l.blocked = true
			blocked++
		case kl.Live:
			l.live = true
			l.arn = kl.ARN
			live++
		}
		lines = append(lines, l)
	}

	// Stable ordering for deterministic evidence regardless of capture order.
	sort.Slice(lines, func(i, j int) bool {
		if lines[i].surface != lines[j].surface {
			return lines[i].surface < lines[j].surface
		}
		return lines[i].masked < lines[j].masked
	})

	var req, resp strings.Builder
	for i, l := range lines {
		if i > 0 {
			req.WriteString("; ")
			resp.WriteString("; ")
		}
		fmt.Fprintf(&req, "sts:GetCallerIdentity(captured key %s from %s %q)", l.masked, l.surface, l.resource)
		switch {
		case l.blocked:
			resp.WriteString(l.masked + ": blocked (probe could not complete)")
		case l.live:
			fmt.Fprintf(&resp, "%s: LIVE → %s", l.masked, l.arn)
		default:
			resp.WriteString(l.masked + ": rejected (invalid/expired)")
		}
	}

	verdict := VerdictUnconfirmed
	switch {
	case live > 0:
		verdict = VerdictConfirmed
	case blocked > 0 && blocked == len(lines):
		verdict = VerdictBlocked
	}

	ev := &findings.Evidence{
		Vantage:    findings.VantageAuthenticated,
		Request:    req.String(),
		Response:   summarize(live, blocked, len(lines)) + " — " + resp.String(),
		Verdict:    verdict,
		CapturedAt: time.Now().UTC(),
	}
	return ev, nil
}

// summarize heads the evidence response with the tally.
func summarize(live, blocked, total int) string {
	return fmt.Sprintf("%d/%d captured AWS key(s) live, %d blocked", live, total, blocked)
}
