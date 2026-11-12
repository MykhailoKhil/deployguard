package web

import (
	_ "embed"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/deployguard/deployguard/assets"
	"github.com/deployguard/deployguard/internal/domain"
)

// contentSecurityPolicy is sent with every page. Images (the brand SVGs) may only come from this
// site; scripts and styles are limited to the site's own files, and nothing may frame a page.
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

//go:embed app.css
var appCSS string

//go:embed theme.js
var themeJS string

func serveStyles(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/css; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=300")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write([]byte(appCSS))
}

// brandAssetName returns the file name when path is /assets/brand/<name> for one of the brand files.
// It is a fixed allow-list: no directory listing, no other name, and no path tricks (a name that
// contains a slash or dots is not in the list, so it is a 404).
func brandAssetName(path string) (string, bool) {
	name, found := strings.CutPrefix(path, "/assets/brand/")
	if !found || !brandAssets[name] {
		return "", false
	}
	return name, true
}

var brandAssets = map[string]bool{"mark.svg": true, "wordmark-light.svg": true, "wordmark-dark.svg": true, "social-banner.svg": true}

func serveBrandAsset(writer http.ResponseWriter, name string) {
	content, err := assets.Brand.ReadFile("brand/" + name)
	if err != nil { // the allow-list and the embedded files disagree: a build mistake
		http.NotFound(writer, nil)
		return
	}
	writer.Header().Set("Content-Type", "image/svg+xml")
	writer.Header().Set("Cache-Control", "public, max-age=300")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write(content)
}

// serveSiteAsset handles the static routes shared by both modes. It reports whether it answered.
func serveSiteAsset(writer http.ResponseWriter, request *http.Request) bool {
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		return false
	}
	if name, ok := brandAssetName(request.URL.Path); ok {
		serveBrandAsset(writer, name)
		return true
	}
	if request.URL.Path == "/favicon.ico" {
		// Browsers ask for this by default. The pages declare an SVG icon, so send the rest here
		// instead of answering 404 on every page load.
		http.Redirect(writer, request, "/assets/brand/mark.svg", http.StatusFound)
		return true
	}
	return false
}

func serveThemeScript(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	writer.Header().Set("Cache-Control", "public, max-age=300")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = writer.Write([]byte(themeJS))
}

type errorData struct {
	Status    int
	Message   string
	BackHref  string
	BackLabel string
	Local     bool
	Mode      string
}

// writeError renders the shared error page. The status line is written before
// the body so clients and tests still see the real HTTP status.
func writeError(writer http.ResponseWriter, tmpl *template.Template, data errorData) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(data.Status)
	if err := tmpl.ExecuteTemplate(writer, "error", data); err != nil {
		_, _ = writer.Write([]byte("Something went wrong."))
	}
}

// sentence turns the terse internal messages into a readable sentence.
func sentence(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return "Something went wrong."
	}
	runes := []rune(message)
	runes[0] = unicode.ToUpper(runes[0])
	message = string(runes)
	if !strings.HasSuffix(message, ".") && !strings.HasSuffix(message, "!") && !strings.HasSuffix(message, "?") {
		message += "."
	}
	return message
}

// severityOrder ranks findings so the most urgent are read first.
var severityOrder = []domain.Severity{
	domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow, domain.SeverityInfo,
}

type severityCount struct {
	Severity domain.Severity
	Count    int
}

func severityRank(severity domain.Severity) int {
	for index, candidate := range severityOrder {
		if candidate == severity {
			return index
		}
	}
	return len(severityOrder)
}

var templateFuncs = template.FuncMap{
	"formatTime": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"shortSHA": func(sha string) string {
		if len(sha) > 7 {
			return sha[:7]
		}
		return sha
	},
	"sortFindings": func(findings []domain.Finding) []domain.Finding {
		sorted := append([]domain.Finding(nil), findings...)
		sort.SliceStable(sorted, func(i, j int) bool { return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity) })
		return sorted
	},
	"severityCounts": func(findings []domain.Finding) []severityCount {
		counts := make(map[domain.Severity]int)
		for _, finding := range findings {
			counts[finding.Severity]++
		}
		var result []severityCount
		for _, severity := range severityOrder {
			if counts[severity] > 0 {
				result = append(result, severityCount{Severity: severity, Count: counts[severity]})
			}
		}
		return result
	},
	"verdictTitle": func(recommendation domain.Recommendation) string {
		switch recommendation {
		case domain.RecommendationSafe:
			return "Looks safe to proceed"
		case domain.RecommendationBlock:
			return "Do not apply yet"
		default:
			return "Review before applying"
		}
	},
	"verdictIcon": func(recommendation domain.Recommendation) string {
		switch recommendation {
		case domain.RecommendationSafe:
			return "✓"
		case domain.RecommendationBlock:
			return "✕"
		default:
			return "!"
		}
	},
	"statusTitle": func(status int) string {
		switch status {
		case http.StatusForbidden:
			return "You can't do that"
		case http.StatusNotFound:
			return "Page not found"
		case http.StatusTooManyRequests:
			return "Slow down a moment"
		case http.StatusServiceUnavailable:
			return "Temporarily unavailable"
		case http.StatusRequestEntityTooLarge:
			return "That file is too large"
		case http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
			return "We couldn't read that plan"
		case http.StatusConflict:
			return "The pull request changed"
		}
		if status >= 500 {
			return "Something went wrong"
		}
		return "That request didn't work"
	},
}

// sharedTemplates holds the pieces used by every page in both modes.
const sharedTemplates = `
{{define "head"}}<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="dark light"><title>{{.}} · DeployGuard</title><link rel="icon" type="image/svg+xml" href="/assets/brand/mark.svg"><script src="/assets/theme.js"></script><link rel="stylesheet" href="/assets/app.css">{{end}}
{{define "brand"}}<a class="brand" href="/"><img class="brand-mark" src="/assets/brand/mark.svg" width="34" height="34" alt=""><span>DeployGuard</span></a>{{end}}
{{define "theme-toggle"}}<button class="theme-toggle" type="button" aria-label="Switch to light theme" hidden>☀ <span>Light</span></button>{{end}}
{{define "foot"}}<footer><div class="container footer-inner"><span>DeployGuard <span class="footer-dot">·</span> Infrastructure risk, made clearer.</span><span>{{.}}</span></div></footer>{{end}}
{{define "error"}}<!doctype html>
<html lang="en"><head>{{template "head" "Something went wrong"}}</head>
<body>
<header class="topbar"><div class="topbar-inner">{{template "brand"}}<div class="header-actions">{{if .Local}}<span class="mode"><span class="mode-dot"></span>Local workspace</span>{{end}}{{template "nav"}}{{template "theme-toggle"}}</div></div></header>
<main class="container">
  <section class="error-card" role="alert" aria-labelledby="error-title">
    <span class="error-code">{{.Status}}</span>
    <h1 id="error-title">{{statusTitle .Status}}</h1>
    <p class="intro">{{.Message}}</p>
    <div class="error-actions"><a class="button primary" href="{{.BackHref}}">{{.BackLabel}} <span aria-hidden="true">→</span></a></div>
  </section>
</main>
{{template "foot" .Mode}}
</body></html>{{end}}
{{define "signed-out"}}<!doctype html>
<html lang="en"><head>{{template "head" "Signed out"}}</head>
<body>
<header class="topbar"><div class="topbar-inner">{{template "brand"}}<div class="header-actions">{{template "nav"}}{{template "theme-toggle"}}</div></div></header>
<main class="container">
  <section class="error-card" aria-labelledby="signed-out-title">
    <span class="error-code ok" aria-hidden="true">✓</span>
    <h1 id="signed-out-title">You're signed out.</h1>
    <p class="intro">Your session and GitHub token were removed from this server.</p>
    <div class="error-actions"><a class="button primary" href="/auth/github">Sign in with GitHub <span aria-hidden="true">→</span></a></div>
  </section>
</main>
{{template "foot" "GITHUB MODE"}}
</body></html>{{end}}
`

const localPage = `
<!doctype html>
<html lang="en"><head>{{template "head" "Local analysis"}}</head>
<body>
<header class="topbar"><div class="topbar-inner">{{template "brand"}}<div class="header-actions"><span class="mode"><span class="mode-dot"></span>Local workspace</span>{{template "nav"}}{{template "theme-toggle"}}</div></div></header>
<main class="container">
  <div class="page-heading"><div><p class="breadcrumb">WORKSPACE <span>/</span> PLAN ANALYSIS</p><h1>Know before you apply.</h1><p class="intro">Understand the potential impact of your Terraform changes before they reach production.</p></div><div class="heading-detail"><span class="detail-number">01</span><span>PLAN REVIEW<br>WORKSPACE</span></div></div>
  {{if .}}{{template "analysis" .}}{{end}}
  <section class="upload-layout" aria-labelledby="upload-title">
    <div class="panel upload-panel"><div class="section-heading"><div><span class="section-index">01 / INPUT</span><h2 id="upload-title">Analyze a plan</h2><p>Upload an existing Terraform JSON plan to get a deterministic risk assessment.</p></div><span class="outline-icon" aria-hidden="true">↗</span></div>
      <form method="post" action="/analyze" enctype="multipart/form-data" class="upload-form" data-busy-label="Analyzing…"><label for="plan">Terraform plan JSON</label><input id="plan" type="file" name="plan" accept="application/json,.json" required aria-describedby="plan-hint"><p class="field-hint" id="plan-hint">JSON files only · Maximum 10 MiB</p><button class="button primary" type="submit"><span class="button-label">Analyze plan</span> <span aria-hidden="true">→</span></button></form>
    </div>
    <aside class="guide"><span class="section-index">BEFORE YOU START</span><h2>Have a binary plan?</h2><p>Convert a plan created in your trusted environment to JSON first.</p><div class="code-block"><span>TERMINAL</span><code>terraform show -json tfplan &gt; tfplan.json</code></div><p>Upload the resulting <code>tfplan.json</code>. Binary plans are not supported.</p><div class="guide-divider"></div><h3>Keep your plan private</h3><p>Plan files can contain secrets. Local mode is unauthenticated and is not connected to GitHub; other users on this machine can access it.</p><div class="guide-divider"></div><h3>AI hint</h3><p>Fix CRITICAL and HIGH findings first, then check what depends on each changed resource. Rules decide the verdict; the AI summary only explains it.</p></aside>
  </section>
  <div class="footnote"><span aria-hidden="true">✳</span> Findings are based on available deterministic rules, not a comprehensive security or cost assessment.</div>
</main>
{{template "foot" "LOCAL MODE"}}
</body></html>`

const resultTemplate = `
{{define "analysis"}}
<section class="results" aria-labelledby="analysis-title">
  <div class="verdict verdict-{{.Recommendation}}" role="status">
    <span class="verdict-icon" aria-hidden="true">{{verdictIcon .Recommendation}}</span>
    <div class="verdict-main"><span class="metric-label">Recommendation: {{.Recommendation}}</span><h2 id="analysis-title">{{verdictTitle .Recommendation}}</h2><p>{{.Explanation}}</p>{{if .Provenance.Checked}}<div class="notice"><strong>Plan provenance {{if .Provenance.Verified}}verified{{else}}not verified{{end}}.</strong> {{.Provenance.Detail}}</div>{{end}}{{if .AIExplanation}}<div class="ai-note"><strong>AI summary (generated, not authoritative)</strong><p>{{.AIExplanation}}</p></div>{{end}}</div>
    <div class="verdict-score"><div class="score">{{.Score}}<span>/ 100</span></div><span class="risk-label risk-{{.Level}}">{{.Level}} RISK</span></div>
  </div>
  <details class="how-scored"><summary>How is this scored?</summary><p>Each finding adds points by severity: low 5, medium 15, high 35, critical 60. The total is capped at 100. Recommendations are SAFE below 20, REVIEW from 20–59, and BLOCK from 60. Results come from deterministic rules, not a model's opinion.</p></details>
  <div class="metrics" aria-label="Risk dimensions">
    <div class="metric"><span class="metric-label">COST RISK</span><strong>{{.Cost.Score}}<small> / 100</small></strong><meter class="meter" min="0" max="100" low="34" high="66" optimum="0" value="{{.Cost.Score}}">{{.Cost.Score}} out of 100</meter><p>{{.Cost.Summary}}</p>{{if .Cost.EstimatedMonthlyDeltaUSD}}<p>Estimated monthly change: ${{.Cost.EstimatedMonthlyDeltaUSD}}</p>{{else}}<p>Monthly cost change not estimated.</p>{{end}}</div>
    <div class="metric"><span class="metric-label">RELIABILITY</span><strong>{{.Reliability.Score}}<small> / 100</small></strong><meter class="meter" min="0" max="100" low="34" high="66" optimum="0" value="{{.Reliability.Score}}">{{.Reliability.Score}} out of 100</meter><p>{{.Reliability.Summary}}</p></div>
    <div class="metric"><span class="metric-label">SECURITY</span><strong>{{.Security.Score}}<small> / 100</small></strong><meter class="meter" min="0" max="100" low="34" high="66" optimum="0" value="{{.Security.Score}}">{{.Security.Score}} out of 100</meter><p>{{.Security.Summary}}</p></div>
    <div class="metric"><span class="metric-label">BLAST RADIUS</span><strong>{{.BlastRadius.ChangedResources}}<small> changed</small></strong><p>{{.BlastRadius.CriticalResources}} critical resources affected</p></div>
  </div>
  <div class="findings"><div class="findings-heading"><div><span class="section-index">WHAT WE FOUND</span><h3>Findings</h3></div><div class="chips" aria-label="Findings by severity">{{range severityCounts .Findings}}<span class="chip risk-{{.Severity}}">{{.Count}} {{.Severity}}</span>{{else}}<span class="chip">0 TOTAL</span>{{end}}</div></div>
  {{range sortFindings .Findings}}<article class="finding"><span class="risk-label risk-{{.Severity}}">{{.Severity}}</span><div><h4>{{.Summary}}</h4>{{if .Resources}}<div class="resource-list"><span class="metric-label">AFFECTED RESOURCES</span>{{range .Resources}}<code>{{.}}</code>{{end}}</div>{{end}}{{range .Evidence}}{{if .AttributePath}}<p class="evidence">Plan attribute: <code>{{.AttributePath}}</code>{{if .ResourceAddress}} on <code>{{.ResourceAddress}}</code>{{end}}</p>{{end}}{{end}}<p class="next-step"><strong>Next step:</strong> {{.Remediation}}</p></div></article>{{else}}<p class="empty-state">No deterministic risk findings. Review the plan and its provenance before applying.</p>{{end}}</div>
</section>
{{end}}`

const pageTemplates = `
{{define "home"}}<!doctype html><html lang="en"><head>{{template "head" "Repositories"}}</head><body>
<header class="topbar"><div class="topbar-inner">{{template "brand"}}<div class="header-actions"><div class="account"><span>Signed in as <strong>{{.User}}</strong></span><form method="post" action="/auth/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button class="text-button">Sign out</button></form></div>{{template "nav"}}{{template "theme-toggle"}}</div></div></header>
<main class="container"><div class="page-heading"><div><p class="breadcrumb">WORKSPACE <span>/</span> REPOSITORIES</p><h1>Choose a repository.</h1><p class="intro">Select an installed repository to review its open pull requests.</p></div><div class="heading-detail"><span class="detail-number">01</span><span>GITHUB REVIEW<br>WORKSPACE</span></div></div>
<section class="panel list-panel"><div class="list-title"><div><span class="section-index">YOUR WORKSPACE</span><h2>Repositories</h2></div><span>{{len .Repositories}} AVAILABLE</span></div><div class="item-list">{{range .Repositories}}<a class="repo-row" href="/repositories/{{.ID}}/pull-requests"><span class="repo-icon" aria-hidden="true">▤</span><span><strong>{{.FullName}}</strong><small>View open pull requests</small></span><span class="row-arrow" aria-hidden="true">↗</span></a>{{else}}<p class="empty-state">No installed repositories available for <strong>{{.User}}</strong>. Install the DeployGuard GitHub App on a repository this account can access (a private App only works for its owner), then reload this page.</p>{{end}}</div></section><div class="footnote"><span aria-hidden="true">✳</span> DeployGuard analyzes plans; it never applies infrastructure changes.</div></main>
{{template "foot" "GITHUB MODE"}}</body></html>{{end}}
{{define "pull-requests"}}<!doctype html><html lang="en"><head>{{template "head" .Repository.FullName}}</head><body>
<header class="topbar"><div class="topbar-inner">{{template "brand"}}<div class="header-actions"><span class="mode">{{.User}}</span>{{template "nav"}}{{template "theme-toggle"}}</div></div></header>
<main class="container"><div class="page-heading"><div><p class="breadcrumb"><a href="/">REPOSITORIES</a> <span>/</span> PULL REQUESTS</p><h1>{{.Repository.FullName}}</h1><p class="intro">Choose a pull request and a Terraform JSON plan to analyze.</p></div></div>
<div class="notice"><strong>Verify your plan source.</strong> Uploaded plans are associated with the selected PR head, but their source commit is not cryptographically attested unless plan provenance verification is enabled; the result page says whether it passed.</div>
<section aria-labelledby="prs-title"><div class="list-title list-title-outside"><div><span class="section-index">GITHUB REVIEW</span><h2 id="prs-title">Open pull requests</h2></div><span>{{len .PullRequests}} OPEN</span></div><div class="pr-list">{{range .PullRequests}}<article class="panel pr-panel"><div class="pr-heading"><div><span class="section-index">PULL REQUEST #{{.Number}}</span><h3>{{.Title}}</h3><p class="pr-meta">Head <code title="{{.HeadSHA}}">{{shortSHA .HeadSHA}}</code>{{if .Fork}} <span class="badge badge-warn">Fork · upload only</span>{{end}}</p></div><span class="outline-icon" aria-hidden="true">↗</span></div><div class="pr-actions"><form method="post" action="/reviews" enctype="multipart/form-data" class="review-form" data-busy-label="Analyzing…"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="repository_id" value="{{$.Repository.ID}}"><input type="hidden" name="pull_request_number" value="{{.Number}}"><input type="hidden" name="source" value="upload"><label for="plan-{{.Number}}">Upload existing Terraform JSON plan</label><input id="plan-{{.Number}}" type="file" name="plan" accept="application/json,.json" required><p class="field-hint">JSON files only · Maximum 10 MiB</p><button class="button primary"><span class="button-label">Analyze uploaded plan</span> <span aria-hidden="true">→</span></button></form>{{if and $.ActionsEnabled (not .Fork)}}<form method="post" action="/reviews" enctype="multipart/form-data" class="actions-form" data-busy-label="Fetching plan…"><input type="hidden" name="csrf_token" value="{{$.CSRFToken}}"><input type="hidden" name="repository_id" value="{{$.Repository.ID}}"><input type="hidden" name="pull_request_number" value="{{.Number}}"><input type="hidden" name="source" value="actions"><p>Or use the plan your configured CI workflow produced for this head commit.</p><button class="button secondary"><span class="button-label">Use GitHub Actions plan</span> <span aria-hidden="true">→</span></button></form>{{end}}</div></article>{{else}}<div class="panel"><p class="empty-state">No open pull requests.</p></div>{{end}}</div></section><div class="footnote"><span aria-hidden="true">✳</span> Findings are not a comprehensive security or cost assessment.</div></main>
{{template "foot" "GITHUB MODE"}}</body></html>{{end}}
{{define "result"}}<!doctype html><html lang="en"><head>{{template "head" "Analysis"}}</head><body>
<header class="topbar"><div class="topbar-inner">{{template "brand"}}<div class="header-actions"><span class="mode">{{.User}}</span>{{template "nav"}}{{template "theme-toggle"}}</div></div></header>
<main class="container"><div class="page-heading compact"><div><p class="breadcrumb"><a href="/">REPOSITORIES</a> <span>/</span> <a href="/repositories/{{.Repository.ID}}/pull-requests">{{.Repository.FullName}}</a> <span>/</span> ANALYSIS</p><h1>Pull request #{{.PullRequest.Number}}</h1><p class="intro">{{.PullRequest.Title}} · Head <code title="{{.PullRequest.HeadSHA}}">{{shortSHA .PullRequest.HeadSHA}}</code></p></div></div>
{{if not .Analysis.Provenance.Verified}}{{if eq .PlanSource "actions"}}<div class="notice"><strong>Plan from your CI workflow.</strong> It was generated for this exact head commit, but a pull request author can edit that workflow. Protect workflow files with required reviews; DeployGuard cannot attest that the plan matches what Terraform would really do.</div>{{else}}<div class="notice"><strong>Plan provenance matters.</strong> Uploaded plans are associated with this selected head; their source commit is not cryptographically attested.</div>{{end}}{{end}}
{{template "analysis" .Analysis}}<div class="footnote"><span aria-hidden="true">✳</span> Findings are not a comprehensive security or cost assessment. Results are not published to GitHub.</div></main>
{{template "foot" "GITHUB MODE"}}</body></html>{{end}}`
