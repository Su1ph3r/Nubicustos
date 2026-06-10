// Package auth resolves cloud credentials up front — including every MFA path —
// so that the concurrent scan phase never blocks on a human. See plan §8.
//
// The design rule that makes MFA reliable under concurrency: resolve and
// validate credentials in a single-threaded phase (prompting at most once),
// then hand the cached, MFA-satisfied session to the engine. A mutex on the
// prompter guarantees a single TOTP entry even if multiple providers trigger.
package auth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Prompter supplies interactive input (TOTP codes) and surfaces instructions
// (device-code URLs, browser hints) to the operator. Implementations must be
// safe for concurrent use; the CLI implementation serializes on a mutex.
type Prompter interface {
	// TOTP returns a one-time MFA code for the given device serial/ARN.
	TOTP(ctx context.Context, serial string) (string, error)
	// Notify surfaces a non-interactive instruction or status line.
	Notify(msg string)
}

// CLIPrompter prompts on stdin/stderr. A preset code (from --mfa-token) is
// returned exactly once before falling back to an interactive prompt. With
// interactive disabled and no preset left, TOTP fails fast rather than hanging.
type CLIPrompter struct {
	mu          sync.Mutex
	preset      string
	presetUsed  bool
	interactive bool
}

// NewCLIPrompter builds a prompter. preset is an optional pre-supplied TOTP
// code; interactive enables stdin prompting when no preset is available.
func NewCLIPrompter(preset string, interactive bool) *CLIPrompter {
	return &CLIPrompter{preset: preset, interactive: interactive}
}

// Notify writes an instruction line to stderr (kept off stdout so it never
// pollutes machine-readable output).
func (p *CLIPrompter) Notify(msg string) {
	fmt.Fprintln(os.Stderr, msg)
}

// TOTP returns the next MFA code, serializing so concurrent callers produce a
// single prompt.
func (p *CLIPrompter) TOTP(ctx context.Context, serial string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.preset != "" && !p.presetUsed {
		p.presetUsed = true
		return p.preset, nil
	}
	if !p.interactive {
		return "", errors.New("MFA required but no --mfa-token supplied and session is non-interactive")
	}

	fmt.Fprintf(os.Stderr, "Enter MFA code for %s: ", serial)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading MFA code: %w", err)
	}
	code := strings.TrimSpace(line)
	if code == "" {
		return "", errors.New("empty MFA code")
	}
	return code, nil
}
