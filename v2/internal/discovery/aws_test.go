package discovery

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// fakeLister returns canned account sets so the skip/scope logic is testable
// without a live organization.
type fakeLister struct {
	all   []orgAccount
	byOU  map[string][]orgAccount
	calls struct{ list, ou int }
}

func (f *fakeLister) listAccounts(context.Context) ([]orgAccount, error) {
	f.calls.list++
	return f.all, nil
}

func (f *fakeLister) accountsUnderOUs(_ context.Context, ous []string) ([]orgAccount, error) {
	f.calls.ou++
	var out []orgAccount
	for _, ou := range ous {
		out = append(out, f.byOU[ou]...)
	}
	return out, nil
}

// fakeFactory records which accounts a session was built for and fails the
// accounts named in failFor (to exercise the assume-failure → skipped path).
func fakeFactory(failFor map[string]bool, built *[]string) sessionFactory {
	return func(_ context.Context, id string, _ bool) (aws.Config, string, error) {
		if failFor[id] {
			return aws.Config{}, "", errors.New("AccessDenied")
		}
		*built = append(*built, id)
		return aws.Config{Region: "us-east-1"}, "arn:aws:sts::" + id + ":assumed-role/Org/sess", nil
	}
}

const mgmt = "111111111111"

func acct(id, status string) orgAccount {
	return orgAccount{ID: id, Name: "acct-" + id, Status: status}
}

func ids(accs []Account) []string {
	out := make([]string, len(accs))
	for i, a := range accs {
		out[i] = a.ID
	}
	return out
}

func skipReason(res *AWSResult, id string) (string, bool) {
	for _, s := range res.Skipped {
		if s.ID == id {
			return s.Reason, true
		}
	}
	return "", false
}

func TestDiscoverAccounts(t *testing.T) {
	tests := []struct {
		name        string
		all         []orgAccount
		byOU        map[string][]orgAccount
		opts        AWSOptions
		failFor     map[string]bool
		wantScanned []string          // sorted account ids that produced a session
		wantSkipped map[string]string // id -> substring expected in the skip reason
	}{
		{
			name: "whole org skips suspended and the management account by default",
			all: []orgAccount{
				acct(mgmt, "ACTIVE"),
				acct("222222222222", "ACTIVE"),
				acct("333333333333", "SUSPENDED"),
			},
			wantScanned: []string{"222222222222"},
			wantSkipped: map[string]string{
				mgmt:           "management account",
				"333333333333": "status SUSPENDED",
			},
		},
		{
			name: "include-mgmt scans the base account with base creds",
			all: []orgAccount{
				acct(mgmt, "ACTIVE"),
				acct("222222222222", "ACTIVE"),
			},
			opts:        AWSOptions{IncludeMgmt: true},
			wantScanned: []string{"222222222222", mgmt},
		},
		{
			name: "exclude removes an otherwise-active account",
			all: []orgAccount{
				acct("222222222222", "ACTIVE"),
				acct("444444444444", "ACTIVE"),
			},
			opts:        AWSOptions{Exclude: []string{"444444444444"}},
			wantScanned: []string{"222222222222"},
			wantSkipped: map[string]string{"444444444444": "excluded"},
		},
		{
			name:        "explicit accounts bypass org enumeration",
			opts:        AWSOptions{Accounts: []string{"555555555555", " ", "666666666666"}},
			wantScanned: []string{"555555555555", "666666666666"},
		},
		{
			name: "ou scope only pulls accounts under the named OU",
			byOU: map[string][]orgAccount{
				"ou-prod": {acct("222222222222", "ACTIVE"), acct("777777777777", "ACTIVE")},
				"ou-dev":  {acct("888888888888", "ACTIVE")},
			},
			opts:        AWSOptions{OUs: []string{"ou-prod"}},
			wantScanned: []string{"222222222222", "777777777777"},
		},
		{
			name: "assume-role failure demotes a member to skipped, not fatal",
			all: []orgAccount{
				acct("222222222222", "ACTIVE"),
				acct("999999999999", "ACTIVE"),
			},
			failFor:     map[string]bool{"999999999999": true},
			wantScanned: []string{"222222222222"},
			wantSkipped: map[string]string{"999999999999": "assume-role denied"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lister := &fakeLister{all: tc.all, byOU: tc.byOU}
			var built []string
			factory := fakeFactory(tc.failFor, &built)

			res, err := discoverAccounts(context.Background(), mgmt, lister, factory, tc.opts)
			if err != nil {
				t.Fatalf("discoverAccounts: %v", err)
			}

			if got := ids(res.Accounts); !equalUnordered(got, tc.wantScanned) {
				t.Errorf("scanned accounts = %v, want %v", got, tc.wantScanned)
			}
			// A skipped account must never have had a session built for it.
			for id := range tc.wantSkipped {
				if contains(built, id) {
					t.Errorf("built a session for %s but it should be skipped", id)
				}
			}
			for id, want := range tc.wantSkipped {
				got, ok := skipReason(res, id)
				if !ok {
					t.Errorf("expected %s in skipped, not found", id)
					continue
				}
				if !containsSubstr(got, want) {
					t.Errorf("skip reason for %s = %q, want substring %q", id, got, want)
				}
			}

			// Explicit/OU paths must not hit ListAccounts, and vice versa.
			switch {
			case len(tc.opts.Accounts) > 0:
				if lister.calls.list != 0 || lister.calls.ou != 0 {
					t.Errorf("explicit accounts should not enumerate the org (list=%d ou=%d)", lister.calls.list, lister.calls.ou)
				}
			case len(tc.opts.OUs) > 0:
				if lister.calls.ou != 1 || lister.calls.list != 0 {
					t.Errorf("OU scope should call accountsUnderOUs only (list=%d ou=%d)", lister.calls.list, lister.calls.ou)
				}
			default:
				if lister.calls.list != 1 {
					t.Errorf("whole-org scope should call listAccounts once (list=%d)", lister.calls.list)
				}
			}
		})
	}
}

func TestArnPartition(t *testing.T) {
	cases := map[string]string{
		"arn:aws:sts::111122223333:assumed-role/Admin/sess":   "aws",
		"arn:aws-us-gov:iam::111122223333:user/me":            "aws-us-gov",
		"arn:aws-cn:sts::111122223333:assumed-role/Admin/ses": "aws-cn",
		"":                  "aws",
		"not-an-arn":        "aws",
		"arn::sts::111:foo": "aws",
	}
	for in, want := range cases {
		if got := arnPartition(in); got != want {
			t.Errorf("arnPartition(%q) = %q, want %q", in, got, want)
		}
	}
}

func equalUnordered(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func containsSubstr(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
