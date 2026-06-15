package k8s

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func ptrBool(b bool) *bool    { return &b }
func ptrInt64(i int64) *int64 { return &i }

func TestEffectiveRunAsNonRoot(t *testing.T) {
	cases := []struct {
		name            string
		sec             *corev1.SecurityContext
		podRunAsNonRoot *bool
		podRunAsUser    *int64
		want            bool
	}{
		{"nothing set -> root permitted", nil, nil, nil, false},
		{"container runAsNonRoot true", &corev1.SecurityContext{RunAsNonRoot: ptrBool(true)}, nil, nil, true},
		{"container runAsUser non-zero (no bool)", &corev1.SecurityContext{RunAsUser: ptrInt64(1000)}, nil, nil, true},
		{"container runAsUser zero is root", &corev1.SecurityContext{RunAsUser: ptrInt64(0)}, nil, nil, false},
		{"pod runAsNonRoot true inherited", nil, ptrBool(true), nil, true},
		{"pod runAsUser non-zero inherited", nil, nil, ptrInt64(2000), true},
		{"container false overrides pod user non-zero? still non-root via uid", &corev1.SecurityContext{RunAsNonRoot: ptrBool(false)}, nil, ptrInt64(1000), true},
		{"container runAsUser zero overrides pod non-zero -> root", &corev1.SecurityContext{RunAsUser: ptrInt64(0)}, nil, ptrInt64(1000), false},
	}
	for _, c := range cases {
		if got := effectiveRunAsNonRoot(c.sec, c.podRunAsNonRoot, c.podRunAsUser); got != c.want {
			t.Errorf("%s: effectiveRunAsNonRoot = %v, want %v", c.name, got, c.want)
		}
	}
}
