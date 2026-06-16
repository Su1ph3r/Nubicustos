package aws

import (
	"testing"

	"github.com/Su1ph3r/nubicustos/internal/state"
)

func TestClassicELBInsecureListener(t *testing.T) {
	st := state.New()
	st.AddClassicELB(state.ClassicELB{Name: "web", Region: "us-east-1", InternetFacing: true, InsecurePorts: []int32{80}})
	st.AddClassicELB(state.ClassicELB{Name: "secure", Region: "us-east-1", InternetFacing: true}) // HTTPS-only

	fs, _ := classicELBInsecureListener{}.Evaluate(nil, st)
	if len(fs) != 1 || fs[0].Resource.ID != "web" {
		t.Fatalf("only the cleartext-listener LB should be flagged, got %+v", fs)
	}
}

func TestClassicELBNilState(t *testing.T) {
	st := state.New()
	st.AWS = nil
	if fs, _ := (classicELBInsecureListener{}).Evaluate(nil, st); len(fs) != 0 {
		t.Fatalf("nil AWS state should yield nothing, got %d", len(fs))
	}
}
