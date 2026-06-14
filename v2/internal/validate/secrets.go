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
	// Capture is opt-in: with no captured keys (or no prober), there is nothing
	// to confirm and the masked finding stands on its own.
	if len(env.CapturedAWSKeys) == 0 || env.AWSKeyProber == nil {
		return nil, nil
	}

	type line struct {
		masked, surface, resource, arn string
		live, blocked                  bool
	}
	var lines []line
	live, blocked := 0, 0

	for _, c := range env.CapturedAWSKeys {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := env.AWSKeyProber.WhoAmI(ctx, c)
		l := line{masked: c.Masked(), surface: c.Surface, resource: c.Resource}
		switch {
		case err != nil:
			l.blocked = true
			blocked++
		case res.Live:
			l.live = true
			l.arn = res.ARN
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
