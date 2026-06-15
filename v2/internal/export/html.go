package export

import (
	"html/template"
	"io"
	"time"

	"github.com/Su1ph3r/nubicustos/internal/findings"
)

// HTML writes a single self-contained report page (inline CSS, no external
// assets) — a shareable artifact for non-operators without standing up the
// optional web phase.
func HTML(w io.Writer, provider, account string, fs []findings.Finding, generatedAt time.Time) error {
	counts := map[findings.Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	data := htmlData{
		Provider:    provider,
		Account:     account,
		GeneratedAt: generatedAt.UTC().Format(time.RFC1123),
		Total:       len(fs),
		Counts: []sevCount{
			{"critical", counts[findings.SeverityCritical]},
			{"high", counts[findings.SeverityHigh]},
			{"medium", counts[findings.SeverityMedium]},
			{"low", counts[findings.SeverityLow]},
			{"info", counts[findings.SeverityInfo]},
		},
		Findings: fs,
	}
	return htmlTmpl.Execute(w, data)
}

type htmlData struct {
	Provider    string
	Account     string
	GeneratedAt string
	Total       int
	Counts      []sevCount
	Findings    []findings.Finding
}

type sevCount struct {
	Severity string
	Count    int
}

var htmlTmpl = template.Must(template.New("report").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nubicustos report{{if .Account}} — {{.Account}}{{end}}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0d1117; color: #c9d1d9;
         font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  header { padding: 28px 32px; border-bottom: 1px solid #21262d; }
  h1 { margin: 0 0 4px; font-size: 18px; letter-spacing: .5px; }
  .meta { color: #8b949e; font-size: 12px; }
  .summary { display: flex; gap: 10px; flex-wrap: wrap; padding: 20px 32px; }
  .chip { padding: 6px 12px; border-radius: 6px; border: 1px solid #30363d;
          background: #161b22; font-size: 12px; }
  .chip b { font-size: 16px; display: block; }
  main { padding: 0 32px 48px; }
  .f { border: 1px solid #21262d; border-radius: 8px; margin: 14px 0; overflow: hidden; }
  .f-head { display: flex; align-items: center; gap: 12px; padding: 12px 16px;
            background: #161b22; cursor: pointer; }
  .f-head:hover { background: #1c2128; }
  .sev { font-size: 11px; font-weight: 700; text-transform: uppercase;
         padding: 3px 8px; border-radius: 4px; letter-spacing: .5px; }
  .sev-critical { background: #67060c; color: #ffdcd7; }
  .sev-high     { background: #8a2424; color: #ffd9cc; }
  .sev-medium   { background: #6c4400; color: #ffe0a3; }
  .sev-low      { background: #1f3a5f; color: #cce3ff; }
  .sev-info     { background: #30363d; color: #c9d1d9; }
  .f-title { flex: 1; font-weight: 600; }
  .f-svc { color: #8b949e; font-size: 12px; }
  .f-body { padding: 6px 16px 16px; display: none; }
  .f[open] .f-body { display: block; }
  .row { margin: 8px 0; }
  .k { color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: .5px; }
  pre { background: #010409; border: 1px solid #21262d; border-radius: 6px;
        padding: 10px 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-word; margin: 4px 0 0; }
  ul.affected { margin: 4px 0 0; padding-left: 18px; color: #adbac7; }
  .reach { font-size: 11px; color: #8b949e; }
  .empty { color: #8b949e; padding: 40px 0; text-align: center; }
  a { color: #58a6ff; }
</style>
</head>
<body>
<header>
  <h1>Nubicustos cloud posture report</h1>
  <div class="meta">
    {{if .Provider}}provider: {{.Provider}} · {{end}}{{if .Account}}account: {{.Account}} · {{end}}generated: {{.GeneratedAt}}
  </div>
</header>
<section class="summary">
  <div class="chip"><b>{{.Total}}</b>total</div>
  {{range .Counts}}<div class="chip sev-{{.Severity}}"><b>{{.Count}}</b>{{.Severity}}</div>{{end}}
</section>
<main>
{{if not .Findings}}<div class="empty">No findings.</div>{{end}}
{{range .Findings}}
  <details class="f">
    <summary class="f-head">
      <span class="sev sev-{{.Severity}}">{{.Severity}}</span>
      <span class="f-title">{{.Title}}</span>
      <span class="f-svc">{{.Service}}{{if .Resource.Region}} · {{.Resource.Region}}{{end}}</span>
    </summary>
    <div class="f-body">
      <div class="row">{{.Description}}</div>
      {{if .Resource.ID}}<div class="row"><span class="k">resource</span><br>{{if .Resource.ARN}}{{.Resource.ARN}}{{else}}{{.Resource.ID}}{{end}}</div>{{end}}
      {{if .Affected}}<div class="row"><span class="k">affected ({{len .Affected}})</span>
        <ul class="affected">{{range .Affected}}<li>{{if .ID}}{{.ID}}{{end}}{{if .Region}} ({{.Region}}){{end}}{{if .Detail}} — {{.Detail}}{{end}}</li>{{end}}</ul></div>{{end}}
      {{if .Impact}}<div class="row"><span class="k">impact</span><br>{{.Impact}}</div>{{end}}
      {{if .Remediation}}<div class="row"><span class="k">remediation</span><pre>{{.Remediation}}</pre></div>{{end}}
      {{if .PoC}}<div class="row"><span class="k">proof of concept</span><pre>{{.PoC}}</pre></div>{{end}}
      {{if .Compliance}}<div class="row"><span class="k">compliance</span><br>{{range $i, $c := .Compliance}}{{if $i}} · {{end}}{{$c.Framework}} {{$c.Control}}{{end}}</div>{{end}}
      {{if .References}}<div class="row"><span class="k">references</span><br>{{range .References}}<a href="{{.}}">{{.}}</a><br>{{end}}</div>{{end}}
      <div class="reach">reachable: {{.Reachable}}</div>
    </div>
  </details>
{{end}}
</main>
</body>
</html>
`))
