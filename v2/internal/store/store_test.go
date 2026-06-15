package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

func TestSaveAndCountFindings(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	st, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()

	now := time.Now().UTC()
	if err := st.CreateScan(ctx, "s1", "aws", "123456789012", "arn:aws:iam::123456789012:user/me", now); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	fs := []findings.Finding{
		{ID: "a", CheckID: "c", Title: "t", Severity: findings.SeverityHigh, Status: findings.StatusOpen, Provider: "aws", Service: "s3", FirstSeen: now, LastSeen: now},
		{ID: "b", CheckID: "c", Title: "t", Severity: findings.SeverityLow, Status: findings.StatusOpen, Provider: "aws", Service: "s3", FirstSeen: now, LastSeen: now},
	}
	if err := st.SaveFindings(ctx, "s1", fs, now); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}

	// Reopen to prove durability across handles.
	st2, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()

	n, err := st2.CountFindings(ctx, "s1")
	if err != nil {
		t.Fatalf("CountFindings: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 findings, got %d", n)
	}
}
