package risk

import (
	"os"
	"testing"

	"github.com/deployguard/deployguard/internal/domain"
	"github.com/deployguard/deployguard/internal/plan"
)

func TestExamplePlanProducesExpectedFindings(t *testing.T) {
	file, err := os.Open("../../examples/tfplan.json")
	if err != nil {
		t.Fatalf("open example plan: %v", err)
	}
	defer file.Close()

	parsed, err := plan.Parse(file)
	if err != nil {
		t.Fatalf("parse example plan: %v", err)
	}
	analysis, err := NewEngine(Config{}).Analyze(parsed)
	if err != nil {
		t.Fatalf("analyze example plan: %v", err)
	}
	for _, ruleID := range []string{
		"security-group-more-permissive",
		"rds-public-access",
		"capacity-increase",
		"cloudwatch-alarm-deletion",
	} {
		if !hasFinding(analysis.Findings, ruleID) {
			t.Errorf("example plan did not produce %q", ruleID)
		}
	}
}

func TestAnalyzeReportsEveryInitialDeterministicCheck(t *testing.T) {
	plan := domain.Plan{ResourceChanges: []domain.ResourceChange{
		change("aws_instance.web", "aws_instance", []domain.Action{domain.ActionDelete, domain.ActionCreate}, nil, nil),
		change("aws_s3_bucket.production_assets", "aws_s3_bucket", []domain.Action{domain.ActionDelete}, nil, nil),
		change("aws_cloudwatch_metric_alarm.cpu", "aws_cloudwatch_metric_alarm", []domain.Action{domain.ActionDelete}, nil, nil),
		change("aws_security_group.web", "aws_security_group", []domain.Action{domain.ActionUpdate},
			map[string]domain.AttributeValue{"ingress[0].cidr_blocks[0]": known("10.0.0.0/8")},
			map[string]domain.AttributeValue{"ingress[0].cidr_blocks[0]": known("0.0.0.0/0")}),
		change("aws_db_instance.primary", "aws_db_instance", []domain.Action{domain.ActionUpdate},
			map[string]domain.AttributeValue{
				"storage_encrypted":   known(true),
				"publicly_accessible": known(false),
				"allocated_storage":   known(20),
			},
			map[string]domain.AttributeValue{
				"storage_encrypted":   known(false),
				"publicly_accessible": known(true),
				"allocated_storage":   known(100),
			}),
		change("aws_lb.public", "aws_lb", []domain.Action{domain.ActionUpdate}, nil, nil),
	}}

	analysis, err := NewEngine(Config{LargeChangeThreshold: 2}).Analyze(plan)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	wantRuleIDs := map[string]bool{
		"resource-replacement":           false,
		"production-resource-deletion":   false,
		"cloudwatch-alarm-deletion":      false,
		"security-group-more-permissive": false,
		"encryption-disabled":            false,
		"rds-public-access":              false,
		"large-resource-change":          false,
		"critical-resource-change":       false,
		"capacity-increase":              false,
		"monitoring-coverage-regression": false,
	}
	for _, finding := range analysis.Findings {
		if _, expected := wantRuleIDs[finding.RuleID]; expected {
			wantRuleIDs[finding.RuleID] = true
		}
	}
	for ruleID, found := range wantRuleIDs {
		if !found {
			t.Errorf("Analyze() did not produce %q", ruleID)
		}
	}
	if analysis.Score != 100 || analysis.Level != domain.RiskCritical || analysis.Recommendation != domain.RecommendationBlock {
		t.Errorf("analysis disposition = score %d, level %s, recommendation %s; want 100, CRITICAL, BLOCK", analysis.Score, analysis.Level, analysis.Recommendation)
	}
	if analysis.Cost.Score == 0 || analysis.Reliability.Score == 0 || analysis.Security.Score == 0 {
		t.Errorf("dimension scores = cost %d, reliability %d, security %d; each should be non-zero", analysis.Cost.Score, analysis.Reliability.Score, analysis.Security.Score)
	}
	if analysis.BlastRadius.ChangedResources != 6 || analysis.BlastRadius.CriticalResources != 2 {
		t.Errorf("blast radius = %#v, want 6 changed and 2 critical", analysis.BlastRadius)
	}
}

func TestAnalyzeDoesNotTreatUnknownAttributeAsAConfirmedRisk(t *testing.T) {
	plan := domain.Plan{ResourceChanges: []domain.ResourceChange{
		change("aws_db_instance.primary", "aws_db_instance", []domain.Action{domain.ActionUpdate},
			map[string]domain.AttributeValue{"publicly_accessible": known(false)},
			map[string]domain.AttributeValue{"publicly_accessible": {State: domain.ValueUnknown}}),
	}}

	analysis, err := NewEngine(Config{}).Analyze(plan)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if analysis.Score != 15 || analysis.Recommendation != domain.RecommendationSafe {
		t.Errorf("analysis = score %d, recommendation %s; want 15 and SAFE", analysis.Score, analysis.Recommendation)
	}
	if hasFinding(analysis.Findings, "rds-public-access") {
		t.Fatal("Analyze() reported public RDS access for an unknown value")
	}
}

func TestAnalyzeDoesNotInferProductionFromAnUnrelatedSubstring(t *testing.T) {
	plan := domain.Plan{ResourceChanges: []domain.ResourceChange{
		change("aws_s3_bucket.product_catalog", "aws_s3_bucket", []domain.Action{domain.ActionDelete}, nil, nil),
	}}

	analysis, err := NewEngine(Config{}).Analyze(plan)
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}
	if hasFinding(analysis.Findings, "production-resource-deletion") {
		t.Fatal("Analyze() classified product_catalog as a production resource")
	}
}

func change(address, resourceType string, actions []domain.Action, before, after map[string]domain.AttributeValue) domain.ResourceChange {
	if before == nil {
		before = map[string]domain.AttributeValue{}
	}
	if after == nil {
		after = map[string]domain.AttributeValue{}
	}
	return domain.ResourceChange{
		Address: address,
		Type:    resourceType,
		Mode:    domain.ResourceModeManaged,
		Actions: actions,
		Before:  before,
		After:   after,
	}
}

func known(value any) domain.AttributeValue {
	return domain.AttributeValue{State: domain.ValueKnown, Value: value}
}

func hasFinding(findings []domain.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
