// Package validate is the opt-in active-validation pass (plan §9.1): it takes
// confirmable findings and proves exploitability with captured evidence, turning
// a config-assertion finding into a runtime-proven report item.
//
// Safety contract (hard invariants — this is the only part of the tool that
// touches targets rather than reading their config):
//   - Read-only only. Validators never write, modify, delete, or DoS.
//   - Stop at the proven primitive: confirm the door is open, do not walk through.
//   - Opt-in. Nothing here runs unless the operator passes --validate; the
//     default scan performs zero validation network activity.
//   - Every validator declares a blast radius; the runner refuses to execute any
//     validator that does not declare BlastRadiusNone (fail closed).
//   - Rate-limited, with a per-action timeout.
//   - Evidence records the vantage (external / authenticated), the exact request
//     issued, the captured response (truncated, secret-safe), and a verdict.
package validate

import (
	"context"
	"sync"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// BlastRadiusNone is the only blast radius the runner will execute. It encodes
// the read-only/no-state-change contract as a value the runner can enforce.
const BlastRadiusNone = "none"

// Validator confirms a single finding read-only and returns captured evidence.
// Implementations must be side-effect free on the target.
type Validator interface {
	// CheckID is the finding CheckID this validator confirms.
	CheckID() string
	// BlastRadius declares the impact of running this validator. The runner only
	// executes validators that return BlastRadiusNone.
	BlastRadius() string
	// Validate attempts read-only confirmation of f and returns evidence, or nil
	// if the finding offers nothing to confirm. ctx carries the per-action timeout.
	Validate(ctx context.Context, f findings.Finding) (*findings.Evidence, error)
}

var (
	regMu      sync.Mutex
	validators = map[string]Validator{}
)

// Register adds a validator to the registry (call from init). A validator that
// does not declare BlastRadiusNone is rejected at registration — the unsafe
// contract can never be wired in by accident.
func Register(v Validator) {
	if v.BlastRadius() != BlastRadiusNone {
		return
	}
	regMu.Lock()
	defer regMu.Unlock()
	validators[v.CheckID()] = v
}

// Options configures a validation run.
type Options struct {
	Timeout   time.Duration // per-action timeout (default 5s)
	RateLimit time.Duration // minimum interval between validation actions (default 200ms)
	clock     func() time.Time
	sleep     func(time.Duration)
}

func (o *Options) withDefaults() {
	if o.Timeout <= 0 {
		o.Timeout = 5 * time.Second
	}
	if o.RateLimit < 0 {
		o.RateLimit = 0
	} else if o.RateLimit == 0 {
		o.RateLimit = 200 * time.Millisecond
	}
	if o.clock == nil {
		o.clock = time.Now
	}
	if o.sleep == nil {
		o.sleep = time.Sleep
	}
}

// Report summarizes a validation run.
type Report struct {
	Attempted int
	Confirmed int
	Errors    []error
}

// Run executes the registered validators over fs, attaching evidence in place
// (fs[i].Evidence). It is read-only by contract and rate-limited. Findings with
// no matching validator are left untouched. ctx bounds the whole run; each
// action additionally gets Options.Timeout.
func Run(ctx context.Context, fs []findings.Finding, opts Options) Report {
	opts.withDefaults()

	regMu.Lock()
	reg := make(map[string]Validator, len(validators))
	for k, v := range validators {
		reg[k] = v
	}
	regMu.Unlock()

	var rep Report
	var last time.Time
	for i := range fs {
		v, ok := reg[fs[i].CheckID]
		if !ok {
			continue
		}
		if v.BlastRadius() != BlastRadiusNone { // defense in depth; Register already guards
			continue
		}
		if err := ctx.Err(); err != nil {
			rep.Errors = append(rep.Errors, err)
			break
		}

		// Rate limit between actions.
		if !last.IsZero() && opts.RateLimit > 0 {
			if wait := opts.RateLimit - opts.clock().Sub(last); wait > 0 {
				opts.sleep(wait)
			}
		}
		last = opts.clock()

		actx, cancel := context.WithTimeout(ctx, opts.Timeout)
		ev, err := v.Validate(actx, fs[i])
		cancel()

		rep.Attempted++
		if err != nil {
			rep.Errors = append(rep.Errors, err)
			continue
		}
		if ev == nil {
			continue
		}
		fs[i].Evidence = append(fs[i].Evidence, *ev)
		if ev.Verdict == VerdictConfirmed {
			rep.Confirmed++
		}
	}
	return rep
}

// Verdict values for captured evidence.
const (
	VerdictConfirmed   = "confirmed"
	VerdictUnconfirmed = "unconfirmed"
	VerdictBlocked     = "blocked"
)

// registeredCount is a test/inspection helper.
func registeredCount() int {
	regMu.Lock()
	defer regMu.Unlock()
	return len(validators)
}
