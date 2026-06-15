package preflight

import (
	"context"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// k8sReviewer answers "can I perform this verb on this resource" via a
// SelfSubjectAccessReview. It returns (allowed, err); a non-nil err means the
// review itself could not run. The live impl posts an SSAR; tests inject a fake.
type k8sReviewer func(ctx context.Context, verb, group, resource string) (bool, error)

// NewK8sProber returns a Prober backed by SelfSubjectAccessReview — Kubernetes'
// canonical "can-i" API. Every authenticated user may self-review, and the answer
// is authoritative (it evaluates the full RBAC ruleset), so K8s preflight needs no
// separate read attempt. It checks one cluster (one REST config); callers pick the
// context.
func NewK8sProber(cfg *rest.Config) (Prober, error) {
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	review := func(ctx context.Context, verb, group, resource string) (bool, error) {
		ssar := &authzv1.SelfSubjectAccessReview{
			Spec: authzv1.SelfSubjectAccessReviewSpec{
				ResourceAttributes: &authzv1.ResourceAttributes{Verb: verb, Group: group, Resource: resource},
			},
		}
		out, err := cs.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
		if err != nil {
			return false, err
		}
		return out.Status.Allowed, nil
	}
	return &k8sProber{review: review}, nil
}

// k8sProber maps each catalog action to a SelfSubjectAccessReview.
type k8sProber struct {
	review k8sReviewer
}

func (p *k8sProber) Probe(ctx context.Context, action string) Decision {
	attr, ok := k8sActionByDisplay(action)
	if !ok {
		return DecisionUnknown // not a known Kubernetes action
	}
	allowed, err := p.review(ctx, attr.Verb, attr.Group, attr.Resource)
	switch {
	case err != nil:
		return DecisionUnknown // the review could not run — do not penalize
	case allowed:
		return DecisionAllowed
	default:
		return DecisionDenied // not allowed (explicit deny or no matching rule)
	}
}
