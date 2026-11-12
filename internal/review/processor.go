package review

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
	"github.com/deployguard/deployguard/internal/plan"
	"github.com/deployguard/deployguard/internal/risk"
	"github.com/deployguard/deployguard/internal/store"
)

// ArtifactSource downloads the plan JSON the repository's CI workflow produced.
type ArtifactSource interface {
	DownloadPlanArtifact(context.Context, gh.VerifiedReview, gh.PlanArtifactConfig) ([]byte, error)
}

// CheckPublisher writes the Check Run.
type CheckPublisher interface {
	Publish(ctx context.Context, installationID, repositoryID int64, repositoryFullName string, run gh.CheckRun) error
}

// CommentPublisher keeps one DeployGuard comment on a pull request (create or update in place).
type CommentPublisher interface {
	Upsert(ctx context.Context, installationID, repositoryID int64, repositoryFullName string, pullRequest int, update gh.CommentUpdate) error
}

// AnalysisRecorder stores each verdict (never the plan) for history and retention.
type AnalysisRecorder interface {
	RecordAnalysis(ctx context.Context, analysis store.Analysis) error
}

// ProvenanceChecker proves where the plan file came from; see internal/provenance.
type ProvenanceChecker interface {
	Check(ctx context.Context, review gh.VerifiedReview, plan []byte) domain.Provenance
}

// Config holds the processor's dependencies and limits.
type Config struct {
	Artifacts ArtifactSource
	Checks    CheckPublisher
	// Provenance is optional. When set, the plan's attestation is checked and reported.
	Provenance ProvenanceChecker
	// Recorder is optional. When set, every verdict is stored per installation.
	Recorder AnalysisRecorder
	// Comments is optional. When set, the verdict is also kept in one pull request comment.
	Comments CommentPublisher
	Engine   risk.Engine
	// Explain is optional; it returns "" when AI is off or fails.
	Explain func(context.Context, domain.Analysis) string
	Plan    gh.PlanArtifactConfig
	Logger  *slog.Logger
	// MaxConcurrent bounds simultaneous analyses (default 4).
	MaxConcurrent int
	// Timeout bounds one analysis, including GitHub and AI calls (default 90s).
	Timeout time.Duration
}

// Processor implements github.PullRequestProcessor. GitHub waits only about ten
// seconds for a webhook response, so ProcessPullRequest returns as soon as the
// work is queued and the analysis finishes in the background.
type Processor struct {
	config Config
	slots  chan struct{}
	wg     sync.WaitGroup
}

// ErrBusy is returned when MaxConcurrent analyses are already running.
var ErrBusy = errors.New("too many analyses in progress")

// New validates the configuration and returns a Processor.
func New(config Config) (*Processor, error) {
	if config.Artifacts == nil || config.Checks == nil {
		return nil, errors.New("artifact source and check publisher are required")
	}
	if config.Plan.WorkflowFilename == "" || config.Plan.ArtifactName == "" {
		return nil, errors.New("plan workflow filename and artifact name are required")
	}
	if config.MaxConcurrent <= 0 {
		config.MaxConcurrent = 4
	}
	if config.Timeout <= 0 {
		config.Timeout = 90 * time.Second
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.DiscardHandler)
	}
	return &Processor{config: config, slots: make(chan struct{}, config.MaxConcurrent)}, nil
}

// Wait blocks until queued analyses finish (used by tests and shutdown).
func (p *Processor) Wait() { p.wg.Wait() }

// ProcessPullRequest queues the analysis and returns at once. It skips fork pull requests and
// returns ErrBusy when the processor is full.
func (p *Processor) ProcessPullRequest(_ context.Context, event gh.PullRequestEvent) error {
	if event.Fork {
		// Fork plans are never fetched from CI: the workflow would have run
		// untrusted code with the base repository's context.
		p.config.Logger.Info("skipping fork pull request", "repository_id", event.RepositoryID, "pull_request", event.PullRequestNumber)
		return nil
	}
	select {
	case p.slots <- struct{}{}:
	default:
		return ErrBusy
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer func() { <-p.slots }()
		ctx, cancel := context.WithTimeout(context.Background(), p.config.Timeout)
		defer cancel()
		if err := p.analyze(ctx, event); err != nil {
			p.config.Logger.Warn("pull request analysis did not publish a verdict",
				"repository_id", event.RepositoryID, "pull_request", event.PullRequestNumber, "source", event.Source, "error", err.Error())
		}
	}()
	return nil
}

func (p *Processor) analyze(ctx context.Context, event gh.PullRequestEvent) error {
	review := gh.VerifiedReview{
		Repository:     gh.Repository{ID: event.RepositoryID, FullName: event.RepositoryFullName},
		PullRequest:    gh.PullRequest{Number: event.PullRequestNumber, HeadSHA: event.HeadSHA},
		InstallationID: event.InstallationID,
	}
	publish := func(run gh.CheckRun) error {
		return p.config.Checks.Publish(ctx, event.InstallationID, event.RepositoryID, event.RepositoryFullName, run)
	}
	// noVerdict reports "no verdict for this commit" on the Check Run AND in the pull request
	// comment, so the comment never keeps showing the previous commit's verdict as if current.
	noVerdict := func(title, detail string) {
		run := Neutral(event.HeadSHA, title, detail)
		_ = publish(run)
		p.comment(ctx, event, RenderNeutralComment(run), "")
	}
	planJSON, err := p.config.Artifacts.DownloadPlanArtifact(ctx, review, p.config.Plan)
	if err != nil {
		// On a pull_request event the plan workflow usually has not finished
		// yet; its completion sends a workflow_run event, so stay silent. Once
		// the workflow has finished, a missing artifact is worth telling users.
		if event.Source == "workflow_run" {
			noVerdict("Terraform plan not available",
				"The plan workflow finished, but DeployGuard could not retrieve its plan artifact for this commit. Check that the workflow uploads the configured artifact.")
		}
		return err
	}
	parsed, err := plan.Parse(bytes.NewReader(planJSON))
	if err != nil {
		noVerdict("Terraform plan could not be read", "The plan artifact is not valid Terraform plan JSON.")
		return err
	}
	analysis, err := p.config.Engine.Analyze(parsed)
	if err != nil {
		noVerdict("Terraform plan could not be analyzed", "The plan was readable but the analysis failed.")
		return err
	}
	if p.config.Provenance != nil {
		analysis.Provenance = p.config.Provenance.Check(ctx, review, planJSON)
	}
	if p.config.Explain != nil {
		analysis.AIExplanation = p.config.Explain(ctx, analysis)
	}
	if p.config.Recorder != nil {
		if err := p.config.Recorder.RecordAnalysis(ctx, StoredAnalysis(event.InstallationID, event.RepositoryID, event.RepositoryFullName, event.PullRequestNumber, event.HeadSHA, analysis)); err != nil {
			// History is secondary to the verdict, so a storage failure is logged, not fatal.
			p.config.Logger.Warn("could not record analysis", "repository_id", event.RepositoryID, "pull_request", event.PullRequestNumber, "error", err.Error())
		}
	}
	run := Render(event.HeadSHA, analysis)
	if err := publish(run); err != nil {
		return err
	}
	p.comment(ctx, event, RenderComment(event.HeadSHA, analysis), string(analysis.Recommendation))
	p.config.Logger.Info("published check run", "repository_id", event.RepositoryID, "pull_request", event.PullRequestNumber,
		"recommendation", string(analysis.Recommendation), "score", int(analysis.Score), "findings", len(analysis.Findings))
	return nil
}

// comment keeps the pull request comment up to date when comments are enabled. The Check Run is the
// primary result, so a failure here (for example a missing permission) is logged and never fails
// the analysis. recommendation is "" when the commit has no verdict.
func (p *Processor) comment(ctx context.Context, event gh.PullRequestEvent, text, recommendation string) {
	if p.config.Comments == nil {
		return
	}
	err := p.config.Comments.Upsert(ctx, event.InstallationID, event.RepositoryID, event.RepositoryFullName, event.PullRequestNumber,
		gh.CommentUpdate{Body: text, HeadSHA: event.HeadSHA, Recommendation: recommendation})
	switch {
	case err == nil:
	case errors.Is(err, gh.ErrStaleHead):
		p.config.Logger.Info("skipped pull request comment: the head moved on", "repository_id", event.RepositoryID, "pull_request", event.PullRequestNumber)
	case errors.Is(err, gh.ErrCommentPermission):
		p.config.Logger.Warn("could not update pull request comment: permission missing",
			"repository_id", event.RepositoryID, "pull_request", event.PullRequestNumber, "error", err.Error(),
			"fix", "in the GitHub App settings set Pull requests to Read and write, then accept the change on the installation")
	default:
		p.config.Logger.Warn("could not update pull request comment", "repository_id", event.RepositoryID, "pull_request", event.PullRequestNumber, "error", err.Error())
	}
}

var _ gh.PullRequestProcessor = (*Processor)(nil)

// StoredAnalysis is the part of a verdict worth keeping: the outcome and the rules that fired,
// never plan content. The webhook processor and the web UI both record through it.
func StoredAnalysis(installationID, repositoryID int64, repositoryFullName string, pullRequest int, headSHA string, analysis domain.Analysis) store.Analysis {
	findings := make([]store.FindingSummary, 0, len(analysis.Findings))
	for _, finding := range analysis.Findings {
		findings = append(findings, store.FindingSummary{RuleID: finding.RuleID, Severity: string(finding.Severity)})
	}
	return store.Analysis{
		InstallationID: installationID, RepositoryID: repositoryID, RepositoryFullName: repositoryFullName,
		PullRequest: pullRequest, HeadSHA: headSHA,
		Recommendation: string(analysis.Recommendation), Level: string(analysis.Level), Score: int(analysis.Score), Findings: findings,
	}
}
