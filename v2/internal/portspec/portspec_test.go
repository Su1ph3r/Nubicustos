package portspec

import "testing"

func TestParseRange(t *testing.T) {
	cases := []struct {
		spec   string
		lo, hi int
		ok     bool
	}{
		{"22", 22, 22, true},
		{"20-30", 20, 30, true},
		{" 80 ", 80, 80, true},
		{"*", 0, 0, false},
		{"", 0, 0, false},
		{"a-b", 0, 0, false},
	}
	for _, c := range cases {
		lo, hi, ok := ParseRange(c.spec)
		if ok != c.ok || (ok && (lo != c.lo || hi != c.hi)) {
			t.Errorf("ParseRange(%q) = %d,%d,%v want %d,%d,%v", c.spec, lo, hi, ok, c.lo, c.hi, c.ok)
		}
	}
}

func TestCovers(t *testing.T) {
	if !Covers(3389, "3380-3400") {
		t.Error("3389 should be covered by 3380-3400")
	}
	if Covers(22, "80") {
		t.Error("22 is not covered by 80")
	}
	if Covers(22, "*") {
		t.Error("* is not a Covers spec (handled by IsAllPorts)")
	}
}

func TestIsAllPorts(t *testing.T) {
	for _, s := range []string{"*", "0-65535", "1-65535", " * "} {
		if !IsAllPorts(s) {
			t.Errorf("%q should be all-ports", s)
		}
	}
	for _, s := range []string{"22", "80-90", "1-1000"} {
		if IsAllPorts(s) {
			t.Errorf("%q should not be all-ports", s)
		}
	}
}

func TestSensitiveCatalogShared(t *testing.T) {
	// Memcached was the port that had drifted; assert it is present so the shared
	// catalog stays the single source of truth.
	if Sensitive[11211] == "" || Sensitive[22] == "" {
		t.Fatal("sensitive catalog missing expected ports")
	}
}
