package review

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/deployguard/deployguard/internal/domain"
	gh "github.com/deployguard/deployguard/internal/github"
	"github.com/deployguard/deployguard/internal/risk"
	"github.com/deployguard/deployguard/internal/store"
)

type fakeArtifacts struct {
	data    []byte
	err     error
	calls   int
	release chan struct{} // when set, downloads block until it is closed
	mu      sync.Mutex
}

func (f *fakeArtifacts) DownloadPlanArtifact(context.Context, gh.VerifiedReview, gh.PlanArtifactConfig) ([]byte, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.release != nil {
		<-f.release
	}
	return f.data, f.err
}

type fakeChecks struct {
	mu   sync.Mutex
	runs []gh.CheckRun
}

func (f *fakeChecks) Publish(_ context.Context, _, _ int64, _ string, run gh.CheckRun) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs = append(f.runs, run)
	return nil
}

func fixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../plan/testdata/redacted-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newProcessor(t *testing.T, artifacts *fakeArtifacts, checks *fakeChecks, explain func(context.Context, domain.Analysis) string) *Processor {
	t.Helper()
	processor, err := New(Config{
		Artifacts: artifacts, Checks: checks, Engine: risk.NewEngine(risk.Config{}), Explain: explain,
		Plan: gh.PlanArtifactConfig{WorkflowFilename: "plan.yml", ArtifactName: "plan"}, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func event(source string) gh.PullRequestEvent {
	return gh.PullRequestEvent{Action: "synchronize", InstallationID: 42, RepositoryID: 7, RepositoryFullName: "acme/app", PullRequestNumber: 3, HeadSHA: "abc1234", Source: source}
}

func TestPublishesCheckRunWithFindingsAndNextSteps(t *testing.T) {
	checks := &fakeChecks{}
	processor := newProcessor(t, &fakeArtifacts{data: fixture(t)}, checks, nil)
	if err := processor.ProcessPullRequest(context.Background(), event("workflow_run")); err != nil {
		t.Fatal(err)
	}
	processor.Wait()
	if len(checks.runs) != 1 {
		t.Fatalf("published %d runs, want 1", len(checks.runs))
	}
	run := checks.runs[0]
	if run.Conclusion != "failure" || !strings.Contains(run.Title, "BLOCK") {
		t.Errorf("public RDS plan must fail the check: %+v", run)
	}
	for _, want := range []string{"Next step:", "aws_db_instance.main", "Findings"} {
		if !strings.Contains(run.Summary, want) {
			t.Errorf("summary missing %q: %s", want, run.Summary)
		}
	}
	if strings.Contains(run.Summary, "AI summary") {
		t.Error("no AI block without an explainer")
	}
}

func TestAISummaryIsLabelledAndSanitized(t *testing.T) {
	checks := &fakeChecks{}
	explain := func(context.Context, domain.Analysis) string { return "Looks fine.\n<script>x</script> ping @octocat" }
	processor := newProcessor(t, &fakeArtifacts{data: fixture(t)}, checks, explain)
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	summary := checks.runs[0].Summary
	if !strings.Contains(summary, "AI summary (generated, not authoritative)") || !strings.Contains(summary, "> Looks fine.") {
		t.Errorf("AI block missing or unquoted: %s", summary)
	}
	if strings.Contains(summary, "<script>") || strings.Contains(summary, "@octocat") {
		t.Errorf("AI text must be escaped and mentions defused: %s", summary)
	}
	if checks.runs[0].Conclusion != "failure" {
		t.Error("AI text must never change the verdict")
	}
}

func TestMissingArtifactIsSilentOnPullRequestButReportedAfterWorkflow(t *testing.T) {
	for source, wantRuns := range map[string]int{"pull_request": 0, "workflow_run": 1} {
		checks := &fakeChecks{}
		processor := newProcessor(t, &fakeArtifacts{err: errors.New("no artifact")}, checks, nil)
		_ = processor.ProcessPullRequest(context.Background(), event(source))
		processor.Wait()
		if len(checks.runs) != wantRuns {
			t.Errorf("%s: published %d runs, want %d", source, len(checks.runs), wantRuns)
		}
		if wantRuns == 1 && checks.runs[0].Conclusion != "neutral" {
			t.Errorf("missing plan must be neutral, got %q", checks.runs[0].Conclusion)
		}
	}
}

func TestInvalidPlanPublishesNeutral(t *testing.T) {
	checks := &fakeChecks{}
	processor := newProcessor(t, &fakeArtifacts{data: []byte("not json")}, checks, nil)
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	if len(checks.runs) != 1 || checks.runs[0].Conclusion != "neutral" {
		t.Fatalf("runs = %+v", checks.runs)
	}
}

func TestForkPullRequestsAreNeverFetched(t *testing.T) {
	artifacts := &fakeArtifacts{data: fixture(t)}
	checks := &fakeChecks{}
	processor := newProcessor(t, artifacts, checks, nil)
	fork := event("pull_request")
	fork.Fork = true
	if err := processor.ProcessPullRequest(context.Background(), fork); err != nil {
		t.Fatal(err)
	}
	processor.Wait()
	if artifacts.calls != 0 || len(checks.runs) != 0 {
		t.Fatalf("fork PR must be skipped: downloads=%d runs=%d", artifacts.calls, len(checks.runs))
	}
}

func TestBusyProcessorRejectsExtraWork(t *testing.T) {
	artifacts := &fakeArtifacts{data: fixture(t), release: make(chan struct{})}
	processor := newProcessor(t, artifacts, &fakeChecks{}, nil)
	if err := processor.ProcessPullRequest(context.Background(), event("workflow_run")); err != nil {
		t.Fatal(err)
	}
	if err := processor.ProcessPullRequest(context.Background(), event("workflow_run")); !errors.Is(err, ErrBusy) {
		t.Fatalf("second event error = %v, want ErrBusy", err)
	}
	close(artifacts.release)
	processor.Wait()
}

func TestRenderEscapesUntrustedResourceNamesAndMapsConclusions(t *testing.T) {
	analysis := domain.Analysis{
		Score: 10, Level: domain.RiskLow, Recommendation: domain.RecommendationReview, Explanation: "Explained.",
		Findings: []domain.Finding{{Severity: domain.SeverityLow, Summary: "x <img src=x onerror=1> @team", Remediation: "fix `it`", Resources: []string{"a`b\n<b>"}}},
	}
	run := Render("abc1234", analysis)
	if run.Conclusion != "neutral" {
		t.Errorf("REVIEW must be neutral, got %s", run.Conclusion)
	}
	// Escaped (\<) or inside a code span, "<" is rendered literally; a bare
	// "<img" or a live mention would not be.
	if strings.Contains(run.Summary, " <img") || !strings.Contains(run.Summary, `\<img`) {
		t.Errorf("HTML in a finding must be backslash-escaped: %s", run.Summary)
	}
	if strings.Contains(run.Summary, "@team") || !strings.Contains(run.Summary, "@\u200bteam") {
		t.Errorf("mentions must be defused: %s", run.Summary)
	}
	if !strings.Contains(run.Summary, "`a'b <b>`") {
		t.Errorf("resource must sit in a code span without backticks or newlines: %s", run.Summary)
	}
	if Conclusion(domain.RecommendationSafe) != "success" || Conclusion(domain.RecommendationBlock) != "failure" {
		t.Error("SAFE must succeed and BLOCK must fail")
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New must reject a missing artifact source and publisher")
	}
	if _, err := New(Config{Artifacts: &fakeArtifacts{}, Checks: &fakeChecks{}}); err == nil {
		t.Error("New must require the plan workflow and artifact names")
	}
}

type fakeComments struct {
	mu      sync.Mutex
	updates []gh.CommentUpdate
	err     error
}

func (f *fakeComments) Upsert(_ context.Context, _, _ int64, _ string, _ int, update gh.CommentUpdate) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updates = append(f.updates, update)
	return f.err
}

func commentProcessor(t *testing.T, artifacts *fakeArtifacts, checks *fakeChecks, comments *fakeComments, logger *slog.Logger) *Processor {
	t.Helper()
	processor, err := New(Config{
		Artifacts: artifacts, Checks: checks, Comments: comments, Engine: risk.NewEngine(risk.Config{}), Logger: logger,
		Plan: gh.PlanArtifactConfig{WorkflowFilename: "plan.yml", ArtifactName: "plan"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return processor
}

func TestProcessorKeepsAPullRequestCommentThatNamesTheCommit(t *testing.T) {
	checks, comments := &fakeChecks{}, &fakeComments{}
	processor := commentProcessor(t, &fakeArtifacts{data: fixture(t)}, checks, comments, nil)
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	if len(comments.updates) != 1 {
		t.Fatalf("updates: %+v", comments.updates)
	}
	update := comments.updates[0]
	if update.Recommendation != "BLOCK" || update.HeadSHA != "abc1234" {
		t.Errorf("the client needs the verdict and the commit: %+v", update)
	}
	for _, want := range []string{"### DeployGuard: BLOCK", "Commit `abc1234`", "Next step:"} {
		if !strings.Contains(update.Body, want) {
			t.Errorf("comment missing %q: %s", want, update.Body)
		}
	}
	if len(checks.runs) != 1 {
		t.Fatal("the Check Run is still published")
	}
}

func TestCommentFailureDoesNotFailTheCheckRun(t *testing.T) {
	checks := &fakeChecks{}
	processor := commentProcessor(t, &fakeArtifacts{data: fixture(t)}, checks, &fakeComments{err: errors.New("forbidden")}, nil)
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	if len(checks.runs) != 1 || checks.runs[0].Conclusion != "failure" {
		t.Fatalf("Check Run must still be published: %+v", checks.runs)
	}
}

func TestStaleHeadIsSkippedQuietlyNotReportedAsAFailure(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	checks := &fakeChecks{}
	processor := commentProcessor(t, &fakeArtifacts{data: fixture(t)}, checks, &fakeComments{err: fmt.Errorf("wrapped: %w", gh.ErrStaleHead)}, logger)
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	if !strings.Contains(logs.String(), "the head moved on") || strings.Contains(logs.String(), "could not update pull request comment") {
		t.Errorf("a stale head is expected and must be logged at info, not as a failure: %s", logs.String())
	}
	if len(checks.runs) != 1 {
		t.Error("the Check Run for the analyzed commit is still published")
	}
}

func TestNoVerdictOutcomesUpdateTheCommentToo(t *testing.T) {
	for name, tc := range map[string]struct {
		artifacts *fakeArtifacts
		title     string
	}{
		"missing artifact": {&fakeArtifacts{err: errors.New("none")}, "Terraform plan not available"},
		"unreadable plan":  {&fakeArtifacts{data: []byte("not json")}, "Terraform plan could not be read"},
	} {
		checks, comments := &fakeChecks{}, &fakeComments{}
		processor := commentProcessor(t, tc.artifacts, checks, comments, nil)
		_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
		processor.Wait()
		if len(comments.updates) != 1 {
			t.Fatalf("%s: updates %+v; a stale verdict must not stay on the pull request", name, comments.updates)
		}
		update := comments.updates[0]
		if update.Recommendation != "" || !strings.Contains(update.Body, tc.title) || !strings.Contains(update.Body, "Commit `abc1234`") {
			t.Errorf("%s: %+v", name, update)
		}
		if len(checks.runs) != 1 || checks.runs[0].Conclusion != "neutral" {
			t.Errorf("%s: the neutral Check Run is still published: %+v", name, checks.runs)
		}
	}
}

func TestNoCommentWhenThePlanIsNotReadyYet(t *testing.T) {
	comments := &fakeComments{}
	processor := commentProcessor(t, &fakeArtifacts{err: errors.New("none")}, &fakeChecks{}, comments, nil)
	_ = processor.ProcessPullRequest(context.Background(), event("pull_request"))
	processor.Wait()
	if len(comments.updates) != 0 {
		t.Fatal("a pull_request event before the plan workflow finished stays silent")
	}
}

type failingRecorder struct{}

func (failingRecorder) RecordAnalysis(context.Context, store.Analysis) error {
	return errors.New("db down")
}

func TestProcessorRecordsTheVerdictWithoutPlanContent(t *testing.T) {
	memory := store.NewMemory()
	checks := &fakeChecks{}
	processor, _ := New(Config{
		Artifacts: &fakeArtifacts{data: fixture(t)}, Checks: checks, Recorder: memory, Engine: risk.NewEngine(risk.Config{}),
		Plan: gh.PlanArtifactConfig{WorkflowFilename: "plan.yml", ArtifactName: "plan"},
	})
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	rows, err := memory.ListAnalyses(context.Background(), 42, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("stored %d rows, err %v", len(rows), err)
	}
	row := rows[0]
	if row.Recommendation != "BLOCK" || row.Score != 75 || row.HeadSHA != "abc1234" || row.PullRequest != 3 || len(row.Findings) != 2 {
		t.Errorf("stored verdict wrong: %+v", row)
	}
	if other, _ := memory.ListAnalyses(context.Background(), 43, 10); len(other) != 0 {
		t.Error("another tenant must see nothing")
	}
}

func TestRecorderFailureDoesNotBlockTheCheckRun(t *testing.T) {
	checks := &fakeChecks{}
	processor, _ := New(Config{
		Artifacts: &fakeArtifacts{data: fixture(t)}, Checks: checks, Recorder: failingRecorder{}, Engine: risk.NewEngine(risk.Config{}),
		Plan: gh.PlanArtifactConfig{WorkflowFilename: "plan.yml", ArtifactName: "plan"},
	})
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	if len(checks.runs) != 1 || checks.runs[0].Conclusion != "failure" {
		t.Fatalf("the Check Run must still be published: %+v", checks.runs)
	}
}

type fakeProvenance struct {
	result domain.Provenance
	gotLen int
}

func (f *fakeProvenance) Check(_ context.Context, review gh.VerifiedReview, plan []byte) domain.Provenance {
	f.gotLen = len(plan)
	return f.result
}

func TestProvenanceIsReportedButNeverChangesTheVerdict(t *testing.T) {
	for name, result := range map[string]domain.Provenance{
		"verified":     {Checked: true, Verified: true, Detail: "signed by workflow plan.yml in acme/app for pull request #3"},
		"not verified": {Checked: true, Detail: "no attestation exists for this exact plan file"},
	} {
		checks := &fakeChecks{}
		fake := &fakeProvenance{result: result}
		processor, _ := New(Config{
			Artifacts: &fakeArtifacts{data: fixture(t)}, Checks: checks, Provenance: fake, Engine: risk.NewEngine(risk.Config{}),
			Plan: gh.PlanArtifactConfig{WorkflowFilename: "plan.yml", ArtifactName: "plan"},
		})
		_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
		processor.Wait()
		if len(checks.runs) != 1 {
			t.Fatalf("%s: runs %d", name, len(checks.runs))
		}
		run := checks.runs[0]
		want := "Plan provenance: " + name
		escaped := strings.ReplaceAll(result.Detail, "#", `\#`) // the renderer escapes markdown
		if !strings.Contains(run.Summary, want) || !strings.Contains(run.Summary, escaped) {
			t.Errorf("%s: summary missing provenance line: %s", name, run.Summary)
		}
		if run.Conclusion != "failure" || fake.gotLen != len(fixture(t)) {
			t.Errorf("%s: verdict changed (%s) or the checker saw %d bytes", name, run.Conclusion, fake.gotLen)
		}
	}
}

func TestNoProvenanceLineWhenNotConfigured(t *testing.T) {
	checks := &fakeChecks{}
	processor := newProcessor(t, &fakeArtifacts{data: fixture(t)}, checks, nil)
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	if strings.Contains(checks.runs[0].Summary, "provenance") {
		t.Errorf("provenance must not be mentioned when checking is off: %s", checks.runs[0].Summary)
	}
}

func TestPermissionRefusalLogsAnActionableFix(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	checks := &fakeChecks{}
	processor := commentProcessor(t, &fakeArtifacts{data: fixture(t)}, checks, &fakeComments{err: fmt.Errorf("%w (status 403)", gh.ErrCommentPermission)}, logger)
	_ = processor.ProcessPullRequest(context.Background(), event("workflow_run"))
	processor.Wait()
	for _, want := range []string{"permission missing", "Pull requests to Read and write", "accept the change on the installation"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log missing %q: %s", want, logs.String())
		}
	}
	if len(checks.runs) != 1 {
		t.Error("the Check Run is still published")
	}
}

func TestUntrustedTextCannotProduceLinksOrCrossReferences(t *testing.T) {
	hostile := "Open https://evil.example/login now, or http://a.example, ftp://files.example, www.evil.example, " +
		"email bob@evil.example, see GH-12 and gh-7, and org/repo#9."
	analysis := domain.Analysis{
		Score: 80, Level: domain.RiskHigh, Recommendation: domain.RecommendationBlock, Explanation: "Explained.", AIExplanation: hostile,
		Findings: []domain.Finding{{Severity: domain.SeverityHigh, Summary: "see https://evil.example/summary", Remediation: "visit www.evil.example/fix", Resources: []string{"https://literal.example/in-code-span"}}},
	}
	for name, text := range map[string]string{"check run": Render("abc1234", analysis).Summary, "comment": RenderComment("abc1234", analysis)} {
		for _, bad := range []*regexp.Regexp{
			regexp.MustCompile(`(?i)[a-z]+://`), regexp.MustCompile(`(?i)www\.`), regexp.MustCompile(`(?i)\bgh-\d`), regexp.MustCompile(`@[A-Za-z]`),
		} {
			cleaned := strings.ReplaceAll(text, "`https://literal.example/in-code-span`", "") // code spans are never linked
			if bad.MatchString(cleaned) {
				t.Errorf("%s still contains something GitHub would link (%s): %s", name, bad, cleaned)
			}
		}
		if !strings.Contains(text, "`https://literal.example/in-code-span`") {
			t.Errorf("%s: a resource address inside a code span must stay exactly as it is", name)
		}
		if !strings.Contains(text, "evil.example") {
			t.Errorf("%s: the text should still be readable, only defused", name)
		}
	}
}
