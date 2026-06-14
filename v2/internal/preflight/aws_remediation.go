package preflight

// awsRemediator renders access gaps as an AWS IAM fix: managed-policy ARNs to
// attach plus a least-privilege inline policy granting exactly the missing
// actions. It is the default Remediator, so every existing AWS caller keeps its
// behavior unchanged; the logic lives in buildRemediation/inlinePolicy.
type awsRemediator struct{}

func (awsRemediator) Build(t Tool, tr ToolReport) Remediation { return buildRemediation(t, tr) }
