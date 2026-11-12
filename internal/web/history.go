package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
	"github.com/deployguard/deployguard/internal/review"
	"github.com/deployguard/deployguard/internal/store"
)

// historyLimit is how many verdicts the History page shows.
const historyLimit = 100

// VerdictStore keeps verdicts for the GitHub-mode History page and receives each review started from
// the web UI. *store.Postgres implements it.
type VerdictStore interface {
	RecordAnalysis(ctx context.Context, analysis store.Analysis) error
	ListAnalysesForRepositories(ctx context.Context, installationID int64, repositoryIDs []int64, limit int) ([]store.Analysis, error)
}

// LocalHistory keeps the verdicts of local uploads for the local-mode History page.
// *store.FileHistory implements it.
type LocalHistory interface {
	Add(store.LocalVerdict) error
	List(limit int) ([]store.LocalVerdict, error)
}

// historyRow is one line of the History page, the same shape in both modes.
type historyRow struct {
	When           time.Time
	Subject        string // "acme/app #12", or "Local upload"
	SubjectHref    string // GitHub mode: the repository's pull request list; empty for local uploads
	Detail         string // short commit, or a short plan fingerprint
	Recommendation string
	Level          string
	Score          int
	Rules          []string // "rule-id (SEVERITY)"
}

func rulesOf(findings []store.FindingSummary) []string {
	rules := make([]string, 0, len(findings))
	for _, f := range findings {
		rules = append(rules, fmt.Sprintf("%s (%s)", f.RuleID, f.Severity))
	}
	return rules
}

// historyHandler serves /history for a signed-in GitHub user. It shows only verdicts of repositories
// that user can access: the repositories come from GitHub with the user's own token, the database is
// asked for exactly those (inside each installation's isolated scope), and nothing else is read.
func (h *Handler) history(writer http.ResponseWriter, request *http.Request) {
	session, _, ok := h.session(writer, request)
	if !ok {
		return
	}
	data := pageData{User: session.User.Login, CSRFToken: session.CSRFToken}
	if h.verdicts == nil {
		data.HistoryNote = "History is off. Set DEPLOYGUARD_DATABASE_URL (PostgreSQL) to keep a record of each verdict."
		h.render(writer, "history", data)
		return
	}
	repositories, err := h.github.ListRepositories(request.Context(), session.AccessToken)
	if err != nil {
		h.fail(writer, "GitHub repositories could not be loaded", http.StatusBadGateway)
		return
	}
	byInstallation := map[int64][]int64{}
	for _, repository := range repositories {
		if repository.InstallationID > 0 {
			byInstallation[repository.InstallationID] = append(byInstallation[repository.InstallationID], repository.ID)
		}
	}
	var rows []store.Analysis
	for installationID, ids := range byInstallation {
		found, err := h.verdicts.ListAnalysesForRepositories(request.Context(), installationID, ids, historyLimit)
		if err != nil {
			h.fail(writer, "history could not be loaded", http.StatusInternalServerError)
			return
		}
		rows = append(rows, found...)
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].CreatedAt.After(rows[j].CreatedAt) })
	if len(rows) > historyLimit {
		rows = rows[:historyLimit]
	}
	for _, a := range rows {
		data.History = append(data.History, historyRow{
			When: a.CreatedAt, Subject: fmt.Sprintf("%s #%d", a.RepositoryFullName, a.PullRequest),
			SubjectHref: fmt.Sprintf("/repositories/%d/pull-requests", a.RepositoryID), Detail: shortHash(a.HeadSHA, 7),
			Recommendation: a.Recommendation, Level: a.Level, Score: a.Score, Rules: rulesOf(a.Findings),
		})
	}
	if len(data.History) == 0 {
		data.HistoryNote = "No verdicts yet. They appear here after a pull request is analyzed, by the webhook or from this site."
	}
	h.render(writer, "history", data)
}

// recordReview stores the verdict of a review started from the web UI. History is secondary to the
// answer the user is waiting for, so a storage failure is logged and never shown as a review failure.
func (h *Handler) recordReview(ctx context.Context, verified gh.VerifiedReview, analysis domain.Analysis) {
	if h.verdicts == nil {
		return
	}
	stored := review.StoredAnalysis(verified.InstallationID, verified.Repository.ID, verified.Repository.FullName, verified.PullRequest.Number, verified.PullRequest.HeadSHA, analysis)
	if err := h.verdicts.RecordAnalysis(ctx, stored); err != nil {
		slog.Warn("could not record the review in the history", "repository_id", verified.Repository.ID, "error", err.Error())
	}
}

// localHistory serves /history in local mode.
func (handler *localHandler) showHistory(writer http.ResponseWriter) {
	data := pageData{LocalHistory: true}
	if handler.history == nil {
		data.HistoryNote = "History is off. Set DEPLOYGUARD_HISTORY_FILE to a file path (it is on by default; \"off\" turns it off)."
	} else if entries, err := handler.history.List(historyLimit); err != nil {
		data.HistoryNote = "The history file could not be read."
	} else {
		for _, v := range entries {
			data.History = append(data.History, historyRow{
				When: v.At, Subject: "Local upload", Detail: "plan " + shortHash(v.PlanSHA256, 12),
				Recommendation: v.Recommendation, Level: v.Level, Score: v.Score, Rules: rulesOf(v.Findings),
			})
		}
		if len(data.History) == 0 {
			data.HistoryNote = "No verdicts yet. Each plan you upload on the home page is recorded here (the verdict only, never the plan)."
		}
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := localTemplate.ExecuteTemplate(writer, "history", data); err != nil {
		http.Error(writer, "could not render page", http.StatusInternalServerError)
	}
}

// recordUpload stores the verdict of a local upload; plan is hashed, never kept.
func (handler *localHandler) recordUpload(plan []byte, analysis domain.Analysis) {
	if handler.history == nil {
		return
	}
	digest := sha256.Sum256(plan)
	entry := store.LocalVerdict{
		At: time.Now().UTC(), PlanSHA256: hex.EncodeToString(digest[:]),
		Recommendation: string(analysis.Recommendation), Level: string(analysis.Level), Score: int(analysis.Score),
	}
	for _, f := range analysis.Findings {
		entry.Findings = append(entry.Findings, store.FindingSummary{RuleID: f.RuleID, Severity: string(f.Severity)})
	}
	if err := handler.history.Add(entry); err != nil {
		slog.Warn("could not record the upload in the history", "error", err.Error())
	}
}

func shortHash(value string, n int) string {
	if len(value) > n {
		return value[:n]
	}
	return value
}

// historyTemplate is shared by both modes; the header differs by whether a user is signed in.
const historyTemplate = `
{{define "history"}}<!doctype html><html lang="en"><head>{{template "head" "History"}}</head><body>
<header class="topbar"><div class="topbar-inner">{{template "brand"}}<div class="header-actions">{{if .User}}<div class="account"><span>Signed in as <strong>{{.User}}</strong></span><form method="post" action="/auth/logout"><input type="hidden" name="csrf_token" value="{{.CSRFToken}}"><button class="text-button">Sign out</button></form></div>{{else}}<span class="mode"><span class="mode-dot"></span>LOCAL MODE</span>{{end}}{{template "nav"}}{{template "theme-toggle"}}</div></div></header>
<main class="container"><div class="page-heading"><div><p class="breadcrumb">{{if .LocalHistory}}<a href="/">ANALYZE</a>{{else}}<a href="/">REPOSITORIES</a>{{end}} <span>/</span> HISTORY</p><h1>Verdict history.</h1><p class="intro">{{if .LocalHistory}}Every plan you uploaded here, newest first. Only the verdict is kept, never the plan.{{else}}Verdicts for the repositories you can access, newest first. Analyzing the same commit again replaces its row.{{end}}</p></div></div>
<section class="panel list-panel" aria-labelledby="history-title"><div class="list-title"><div><span class="section-index">RECORD</span><h2 id="history-title">Verdicts</h2></div><span>{{len .History}} SHOWN</span></div>
{{if .History}}<div class="table-wrap"><table class="history-table"><thead><tr><th scope="col">When</th><th scope="col">What</th><th scope="col">Verdict</th><th scope="col">Rules that fired</th></tr></thead><tbody>
{{range .History}}<tr><td><time datetime="{{.When.UTC.Format "2006-01-02T15:04:05Z"}}">{{formatTime .When}}</time></td><td>{{if .SubjectHref}}<a href="{{.SubjectHref}}">{{.Subject}}</a>{{else}}{{.Subject}}{{end}}{{if .Detail}}<small><code>{{.Detail}}</code></small>{{end}}</td><td><span class="risk-label risk-{{.Level}}">{{.Recommendation}}</span> <small>{{.Level}} · {{.Score}}/100</small></td><td>{{range .Rules}}<code>{{.}}</code> {{else}}<small>none</small>{{end}}</td></tr>{{end}}
</tbody></table></div>{{else}}<p class="empty-state">{{.HistoryNote}}</p>{{end}}
</section><div class="footnote"><span aria-hidden="true">✳</span> A record of verdicts, not a safety assessment on its own: each row is what the deterministic rules concluded at that time.</div></main>
{{template "foot" "HISTORY"}}</body></html>{{end}}
{{define "nav"}}<a class="nav-link" href="/history">History</a>{{end}}
`
