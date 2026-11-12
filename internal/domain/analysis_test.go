package domain

import (
	"testing"
)

func TestAnalysisValidateRejectsOutOfRangeOverallScore(t *testing.T) {
	analysis := validAnalysis()
	analysis.Score = 101

	if err := analysis.Validate(); err == nil {
		t.Fatal("Validate() accepted an overall score greater than 100")
	}
}

func TestAnalysisValidateRejectsOutOfRangeDimensionScore(t *testing.T) {
	analysis := validAnalysis()
	analysis.Security.Score = -1

	if err := analysis.Validate(); err == nil {
		t.Fatal("Validate() accepted a dimension score below 0")
	}
}

func TestAnalysisValidateRejectsUnknownRiskLevel(t *testing.T) {
	analysis := validAnalysis()
	analysis.Level = "SEVERE"

	if err := analysis.Validate(); err == nil {
		t.Fatal("Validate() accepted an unknown risk level")
	}
}

func TestAnalysisValidateRejectsUnknownRecommendation(t *testing.T) {
	analysis := validAnalysis()
	analysis.Recommendation = "DEPLOY"

	if err := analysis.Validate(); err == nil {
		t.Fatal("Validate() accepted an unknown recommendation")
	}
}

func TestAnalysisValidateAcceptsCompleteAnalysis(t *testing.T) {
	if err := validAnalysis().Validate(); err != nil {
		t.Fatalf("Validate() rejected a complete analysis: %v", err)
	}
}

func validAnalysis() Analysis {
	return Analysis{
		Score:          42,
		Level:          RiskMedium,
		Cost:           CostImpact{Score: 30, Summary: "Small estimated increase"},
		Reliability:    RiskDimension{Score: 40, Summary: "No major reliability concerns"},
		Security:       RiskDimension{Score: 20, Summary: "No security regressions detected"},
		BlastRadius:    BlastRadius{ChangedResources: 2, CriticalResources: 1},
		Findings:       []Finding{{RuleID: "resource-update", Severity: SeverityLow, Summary: "One resource will be updated", Remediation: "Review the planned change"}},
		Explanation:    "The plan contains a small number of low-impact changes.",
		Recommendation: RecommendationReview,
	}
}
