package rules

import "github.com/Su1ph3r/nubicustos/internal/state"

// SampleState returns a small synthetic state containing one deliberately-bad
// resource of each supported type, so `rules test` can show which rules fire
// against known-misconfigured input without collecting a real environment.
func SampleState() *state.State {
	st := state.New()
	st.AWS.Account = "111122223333"
	st.AWS.S3Buckets = []state.S3Bucket{
		{Name: "sample-public-bucket", Region: "us-east-1", PolicyPublic: true},
	}
	st.AWS.RDSInstances = []state.RDSInstance{
		{ID: "sample-public-db", Region: "us-east-1", Engine: "postgres", Public: true},
	}
	st.Azure.StorageAccounts = []state.StorageAccount{
		{Name: "samplestorage", Subscription: "sub-1", AllowBlobPublicAccess: true},
	}
	st.K8s.Pods = []state.K8sPod{
		{Name: "sample-pod", Namespace: "default", Context: "sample", Containers: []state.K8sContainer{
			{Name: "app", Privileged: true},
		}},
	}
	return st
}
