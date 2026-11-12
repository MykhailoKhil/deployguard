package domain

import "fmt"

// RiskScore is a normalized score from 0 through 100.
type RiskScore int

// RiskLevel is the overall qualitative risk band.
type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// Recommendation is the suggested pull request disposition.
type Recommendation string

const (
	RecommendationSafe   Recommendation = "SAFE"
	RecommendationReview Recommendation = "REVIEW"
	RecommendationBlock  Recommendation = "BLOCK"
)

// Severity is the urgency of an individual deterministic finding.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

// RiskCategory identifies the analysis dimension affected by a finding.
type RiskCategory string

const (
	RiskCategoryCost        RiskCategory = "COST"
	RiskCategoryReliability RiskCategory = "RELIABILITY"
	RiskCategorySecurity    RiskCategory = "SECURITY"
)

// RiskDimension summarizes one risk category.
type RiskDimension struct {
	Score   RiskScore
	Summary string
}

// CostImpact summarizes cost risk. A nil estimate means the plan did not
// provide enough information to calculate a monthly delta.
type CostImpact struct {
	Score                    RiskScore
	Summary                  string
	EstimatedMonthlyDeltaUSD *int64
}

// BlastRadius summarizes the scope of affected infrastructure.
type BlastRadius struct {
	ChangedResources     int
	CriticalResources    int
	AffectedEnvironments []string
}

// Evidence points to a relevant plan fact without copying raw values that may
// be secret.
type Evidence struct {
	ResourceAddress string
	AttributePath   string
	Summary         string
}

// Finding is an actionable result emitted by a deterministic rule.
type Finding struct {
	RuleID      string
	Severity    Severity
	Categories  []RiskCategory
	Summary     string
	Remediation string
	Resources   []string
	Evidence    []Evidence
}

// Provenance says whether the analyzed plan file is proven to come from the expected CI workflow.
type Provenance struct {
	Checked  bool   // an attestation check ran at all
	Verified bool   // a valid attestation matches the plan, workflow, repository and pull request
	Detail   string // short fixed text, safe to show
}

// Analysis is the complete user-facing result derived from normalized plan
// facts and deterministic rules.
type Analysis struct {
	Score       RiskScore
	Level       RiskLevel
	Cost        CostImpact
	Reliability RiskDimension
	Security    RiskDimension
	BlastRadius BlastRadius
	Findings    []Finding
	Explanation string
	// AIExplanation is optional model-written narration of the findings. It is
	// never authoritative and never feeds the score, level, or recommendation.
	AIExplanation string
	// Provenance is optional context about where the plan came from; it never changes the score,
	// level, or recommendation.
	Provenance     Provenance
	Recommendation Recommendation
}

// Validate enforces the analysis output contract. It deliberately does not
// calculate scores or infer risk levels; those belong to the risk engine.
func (a Analysis) Validate() error {
	if err := validateScore("overall", a.Score); err != nil {
		return err
	}
	if !validRiskLevel(a.Level) {
		return fmt.Errorf("invalid risk level %q", a.Level)
	}
	if err := validateScore("cost", a.Cost.Score); err != nil {
		return err
	}
	if a.Cost.Summary == "" {
		return fmt.Errorf("cost summary is required")
	}
	if err := validateDimension("reliability", a.Reliability); err != nil {
		return err
	}
	if err := validateDimension("security", a.Security); err != nil {
		return err
	}
	if a.BlastRadius.ChangedResources < 0 || a.BlastRadius.CriticalResources < 0 {
		return fmt.Errorf("blast radius resource counts cannot be negative")
	}
	if a.BlastRadius.CriticalResources > a.BlastRadius.ChangedResources {
		return fmt.Errorf("critical resource count cannot exceed changed resource count")
	}
	for i, finding := range a.Findings {
		if finding.RuleID == "" || finding.Summary == "" || finding.Remediation == "" {
			return fmt.Errorf("finding %d requires rule ID, summary, and remediation", i)
		}
		if !validSeverity(finding.Severity) {
			return fmt.Errorf("finding %q has invalid severity %q", finding.RuleID, finding.Severity)
		}
	}
	if a.Explanation == "" {
		return fmt.Errorf("explanation is required")
	}
	if !validRecommendation(a.Recommendation) {
		return fmt.Errorf("invalid recommendation %q", a.Recommendation)
	}
	return nil
}

func validateScore(name string, score RiskScore) error {
	if score < 0 || score > 100 {
		return fmt.Errorf("%s score %d is outside 0..100", name, score)
	}
	return nil
}

func validateDimension(name string, dimension RiskDimension) error {
	if err := validateScore(name, dimension.Score); err != nil {
		return err
	}
	if dimension.Summary == "" {
		return fmt.Errorf("%s summary is required", name)
	}
	return nil
}

func validRiskLevel(level RiskLevel) bool {
	switch level {
	case RiskLow, RiskMedium, RiskHigh, RiskCritical:
		return true
	default:
		return false
	}
}

func validRecommendation(recommendation Recommendation) bool {
	switch recommendation {
	case RecommendationSafe, RecommendationReview, RecommendationBlock:
		return true
	default:
		return false
	}
}

func validSeverity(severity Severity) bool {
	switch severity {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}
