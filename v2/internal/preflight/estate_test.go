package preflight

import "testing"

func rep(overall Readiness) Report { return Report{Overall: overall} }

func acct(overall Readiness) AccountReport { return AccountReport{Report: rep(overall)} }

func TestEstateOverallEmptyIsUnknown(t *testing.T) {
	// Nothing checked at all must not certify as ready.
	if got := EstateOverall(nil, nil); got != ReadinessUnknown {
		t.Fatalf("empty estate should be unknown, got %s", got)
	}
}

func TestEstateOverallWorstCaseAcrossMembers(t *testing.T) {
	got := EstateOverall(nil, []AccountReport{
		acct(ReadinessReady), acct(ReadinessPartial), acct(ReadinessReady),
	})
	if got != ReadinessPartial {
		t.Fatalf("one partial member should make the estate partial, got %s", got)
	}
}

func TestEstateOverallAllReadyIsReady(t *testing.T) {
	base := rep(ReadinessReady)
	got := EstateOverall(&base, []AccountReport{acct(ReadinessReady), acct(ReadinessReady)})
	if got != ReadinessReady {
		t.Fatalf("a fully-ready estate should be ready, got %s", got)
	}
}

func TestEstateOverallBaseFailureGatesEstate(t *testing.T) {
	// The base cannot enumerate/assume → the estate scan cannot run even though
	// the (unreachable, so unchecked-here) members look fine.
	base := rep(ReadinessFailed)
	got := EstateOverall(&base, []AccountReport{acct(ReadinessReady)})
	if got != ReadinessFailed {
		t.Fatalf("a failed base must gate the whole estate, got %s", got)
	}
}

func TestEstateOverallUnverifiedOutranksReady(t *testing.T) {
	got := EstateOverall(nil, []AccountReport{acct(ReadinessReady), acct(ReadinessUnverified)})
	if got == ReadinessReady {
		t.Fatal("an unverified member must keep the estate from reading as ready")
	}
}

func TestWorstReadinessOrdering(t *testing.T) {
	cases := []struct {
		in   []Readiness
		want Readiness
	}{
		{[]Readiness{}, ReadinessReady}, // empty → ready (callers handle "nothing checked")
		{[]Readiness{ReadinessReady, ReadinessReady}, ReadinessReady},
		{[]Readiness{ReadinessReady, ReadinessUnverified}, ReadinessUnverified},
		{[]Readiness{ReadinessUnverified, ReadinessUnknown}, ReadinessUnknown},
		{[]Readiness{ReadinessUnknown, ReadinessPartial}, ReadinessPartial},
		{[]Readiness{ReadinessPartial, ReadinessFailed}, ReadinessFailed},
	}
	for _, c := range cases {
		if got := worstReadiness(c.in...); got != c.want {
			t.Errorf("worstReadiness(%v) = %s, want %s", c.in, got, c.want)
		}
	}
}

func TestAWSToolWithMemberAssume(t *testing.T) {
	base, _ := AWSToolByKey("nubicustos")
	before := len(base.RequiredActions)

	got := AWSToolWithMemberAssume(base)
	if !hasAction(got.RequiredActions, "sts:AssumeRole") {
		t.Error("member-assume tool must include sts:AssumeRole")
	}
	if hasAction(got.RequiredActions, "organizations:ListAccounts") {
		t.Error("member-assume must NOT add Organizations enumeration actions (explicit --accounts skips it)")
	}
	if len(got.RequiredActions) != before+1 {
		t.Fatalf("member-assume should add exactly one action, got %d (was %d)", len(got.RequiredActions), before)
	}
	if len(base.RequiredActions) != before {
		t.Error("AWSToolWithMemberAssume mutated the shared base action slice")
	}

	// Non-native tools are returned unchanged.
	prowler, _ := AWSToolByKey("prowler")
	if got := AWSToolWithMemberAssume(prowler); len(got.RequiredActions) != len(prowler.RequiredActions) {
		t.Error("member-assume must only augment the native nubicustos tool")
	}
}
