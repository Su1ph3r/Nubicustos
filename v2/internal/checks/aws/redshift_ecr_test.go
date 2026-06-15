package aws

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/findings"
	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestRedshiftChecks(t *testing.T) {
	st := state.New()
	st.AddRedshiftCluster(state.RedshiftCluster{ID: "warehouse", Region: "us-east-1", Public: true, Encrypted: false})
	st.AddRedshiftCluster(state.RedshiftCluster{ID: "private", Region: "us-east-1", Public: false, Encrypted: true})

	if fs, _ := (redshiftPublic{}).Evaluate(nil, st); len(fs) != 1 || fs[0].Resource.ID != "warehouse" || fs[0].Severity != findings.SeverityHigh {
		t.Fatalf("only the public cluster should be flagged (high), got %+v", fs)
	}
	if fs, _ := (redshiftUnencrypted{}).Evaluate(nil, st); len(fs) != 1 || fs[0].Resource.ID != "warehouse" {
		t.Fatalf("only the unencrypted cluster should be flagged, got %+v", fs)
	}
}

func TestECRChecks(t *testing.T) {
	st := state.New()
	st.AddECRRepository(state.ECRRepository{Name: "open", Region: "us-east-1", ScanOnPush: false, PublicPolicy: true})
	st.AddECRRepository(state.ECRRepository{Name: "good", Region: "us-east-1", ScanOnPush: true, PublicPolicy: false})

	if fs, _ := (ecrPublicPolicy{}).Evaluate(nil, st); len(fs) != 1 || fs[0].Resource.Name != "open" {
		t.Fatalf("only the public-policy repo should be flagged, got %+v", fs)
	}
	if fs, _ := (ecrScanOnPushDisabled{}).Evaluate(nil, st); len(fs) != 1 || fs[0].Resource.Name != "open" {
		t.Fatalf("only the no-scan repo should be flagged, got %+v", fs)
	}
}

func TestRedshiftECRNilState(t *testing.T) {
	st := state.New()
	st.AWS = nil
	if fs, _ := (redshiftPublic{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("nil AWS state should yield nothing, got %d", len(fs))
	}
	if fs, _ := (ecrPublicPolicy{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("nil AWS state should yield nothing, got %d", len(fs))
	}
}
