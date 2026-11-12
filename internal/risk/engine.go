// Package risk evaluates normalized Terraform changes with deterministic rules.
package risk

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/deployguard/deployguard/internal/domain"
)

// Rule evaluates one deterministic risk condition against a normalized plan.
type Rule interface {
	Evaluate(domain.Plan) []domain.Finding
}

// Config controls conservative, deterministic matching decisions.
type Config struct {
	ProductionIdentifiers []string
	LargeChangeThreshold  int
}

// Engine evaluates the MVP rule set and derives the user-facing analysis.
type Engine struct {
	rules    []Rule
	config   Config
	critical map[string]struct{}
}

// NewEngine constructs an engine with the MVP's deterministic AWS rules.
func NewEngine(config Config) Engine {
	if len(config.ProductionIdentifiers) == 0 {
		config.ProductionIdentifiers = []string{"prod", "production"}
	}
	if config.LargeChangeThreshold <= 0 {
		config.LargeChangeThreshold = 20
	}
	critical := criticalResourceTypes()
	return Engine{
		config:   config,
		critical: critical,
		rules: []Rule{
			replacementRule{},
			productionDeletionRule{identifiers: config.ProductionIdentifiers},
			cloudWatchAlarmDeletionRule{},
			monitoringCoverageRegressionRule{},
			securityGroupPermissivenessRule{},
			encryptionDisabledRule{},
			rdsPublicAccessRule{},
			largeChangeRule{threshold: config.LargeChangeThreshold},
			criticalResourceRule{types: critical},
			capacityIncreaseRule{},
		},
	}
}

// Analyze produces facts, risk dimensions, score, level, and recommendation
// entirely from the supplied plan.
func (e Engine) Analyze(plan domain.Plan) (domain.Analysis, error) {
	if err := plan.Validate(); err != nil {
		return domain.Analysis{}, fmt.Errorf("validate plan: %w", err)
	}

	findings := make([]domain.Finding, 0)
	for _, rule := range e.rules {
		findings = append(findings, rule.Evaluate(plan)...)
	}

	overall, cost, reliability, security := scoreFindings(findings)
	changed, criticalChanged := changedResourceCounts(plan, e.critical)
	analysis := domain.Analysis{
		Score:          overall,
		Level:          levelFor(overall),
		Cost:           domain.CostImpact{Score: cost, Summary: dimensionSummary("cost", cost)},
		Reliability:    domain.RiskDimension{Score: reliability, Summary: dimensionSummary("reliability", reliability)},
		Security:       domain.RiskDimension{Score: security, Summary: dimensionSummary("security", security)},
		BlastRadius:    domain.BlastRadius{ChangedResources: changed, CriticalResources: criticalChanged},
		Findings:       findings,
		Explanation:    explanationFor(findings),
		Recommendation: recommendationFor(overall),
	}
	if err := analysis.Validate(); err != nil {
		return domain.Analysis{}, fmt.Errorf("validate analysis: %w", err)
	}
	return analysis, nil
}

type replacementRule struct{}

func (replacementRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		if change.Mode != domain.ResourceModeManaged || !change.IsReplacement() {
			continue
		}
		findings = append(findings, finding("resource-replacement", domain.SeverityHigh,
			[]domain.RiskCategory{domain.RiskCategoryReliability}, change,
			"Resource will be replaced", "Confirm that replacement will not interrupt dependent workloads."))
	}
	return findings
}

type productionDeletionRule struct{ identifiers []string }

func (r productionDeletionRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		if change.Mode != domain.ResourceModeManaged || !isDeletion(change) || !isProduction(change, r.identifiers) {
			continue
		}
		findings = append(findings, finding("production-resource-deletion", domain.SeverityCritical,
			[]domain.RiskCategory{domain.RiskCategoryReliability}, change,
			"Production resource will be deleted", "Confirm the deletion is intentional and backed by a recovery plan."))
	}
	return findings
}

type cloudWatchAlarmDeletionRule struct{}

func (cloudWatchAlarmDeletionRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		if change.Type != "aws_cloudwatch_metric_alarm" || !isDeletion(change) {
			continue
		}
		findings = append(findings, finding("cloudwatch-alarm-deletion", domain.SeverityHigh,
			[]domain.RiskCategory{domain.RiskCategoryReliability}, change,
			"CloudWatch alarm will be deleted", "Keep equivalent monitoring coverage before removing this alarm."))
	}
	return findings
}

// monitoringCoverageRegressionRule records the operational consequence of
// deleting an alarm separately from the resource-deletion fact.
type monitoringCoverageRegressionRule struct{}

func (monitoringCoverageRegressionRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		if change.Type != "aws_cloudwatch_metric_alarm" || !isDeletion(change) {
			continue
		}
		findings = append(findings, finding("monitoring-coverage-regression", domain.SeverityMedium,
			[]domain.RiskCategory{domain.RiskCategoryReliability}, change,
			"Monitoring coverage will regress", "Add or retain equivalent monitoring and alerting coverage."))
	}
	return findings
}

type securityGroupPermissivenessRule struct{}

func (securityGroupPermissivenessRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		if !isSecurityGroup(change.Type) || !introducesPublicCIDR(change) {
			continue
		}
		findings = append(findings, finding("security-group-more-permissive", domain.SeverityHigh,
			[]domain.RiskCategory{domain.RiskCategorySecurity}, change,
			"Security group is becoming publicly accessible", "Restrict the rule to required CIDR ranges or security groups."))
	}
	return findings
}

type encryptionDisabledRule struct{}

func (encryptionDisabledRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		for path, after := range change.After {
			if !isEncryptionAttribute(path) || !knownBool(after, false) || !knownBool(change.Before[path], true) {
				continue
			}
			findings = append(findings, findingWithEvidence("encryption-disabled", domain.SeverityHigh,
				[]domain.RiskCategory{domain.RiskCategorySecurity}, change, path,
				"Encryption will be disabled", "Keep encryption enabled or document an approved exception."))
		}
	}
	return findings
}

type rdsPublicAccessRule struct{}

func (rdsPublicAccessRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		if change.Type != "aws_db_instance" || !knownBool(change.After["publicly_accessible"], true) || knownBool(change.Before["publicly_accessible"], true) {
			continue
		}
		findings = append(findings, findingWithEvidence("rds-public-access", domain.SeverityCritical,
			[]domain.RiskCategory{domain.RiskCategorySecurity, domain.RiskCategoryReliability}, change, "publicly_accessible",
			"RDS instance will become publicly accessible", "Keep the database private unless there is a documented, approved exception."))
	}
	return findings
}

type largeChangeRule struct{ threshold int }

func (r largeChangeRule) Evaluate(plan domain.Plan) []domain.Finding {
	changed := 0
	for _, change := range plan.ResourceChanges {
		if hasMaterialAction(change) {
			changed++
		}
	}
	if changed < r.threshold {
		return nil
	}
	return []domain.Finding{{
		RuleID:      "large-resource-change",
		Severity:    domain.SeverityMedium,
		Categories:  []domain.RiskCategory{domain.RiskCategoryReliability},
		Summary:     fmt.Sprintf("Plan changes %d resources", changed),
		Remediation: "Review the change set in smaller batches or obtain an explicit rollout plan.",
	}}
}

type criticalResourceRule struct{ types map[string]struct{} }

func (r criticalResourceRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		if !hasMaterialAction(change) {
			continue
		}
		if _, ok := r.types[change.Type]; !ok {
			continue
		}
		findings = append(findings, finding("critical-resource-change", domain.SeverityMedium,
			[]domain.RiskCategory{domain.RiskCategoryReliability}, change,
			"Critical resource will change", "Review expected impact, dependencies, and rollback steps."))
	}
	return findings
}

type capacityIncreaseRule struct{}

func (capacityIncreaseRule) Evaluate(plan domain.Plan) []domain.Finding {
	var findings []domain.Finding
	for _, change := range plan.ResourceChanges {
		for path, after := range change.After {
			if !isCapacityAttribute(path) {
				continue
			}
			before, exists := change.Before[path]
			if !exists || !increased(before, after) {
				continue
			}
			findings = append(findings, findingWithEvidence("capacity-increase", domain.SeverityMedium,
				[]domain.RiskCategory{domain.RiskCategoryCost}, change, path,
				"Resource capacity will increase", "Confirm the capacity change and expected cost impact."))
		}
	}
	return findings
}

func finding(ruleID string, severity domain.Severity, categories []domain.RiskCategory, change domain.ResourceChange, summary, remediation string) domain.Finding {
	return findingWithEvidence(ruleID, severity, categories, change, "", summary, remediation)
}

func findingWithEvidence(ruleID string, severity domain.Severity, categories []domain.RiskCategory, change domain.ResourceChange, path, summary, remediation string) domain.Finding {
	return domain.Finding{
		RuleID:      ruleID,
		Severity:    severity,
		Categories:  categories,
		Summary:     summary,
		Remediation: remediation,
		Resources:   []string{change.Address},
		Evidence: []domain.Evidence{{
			ResourceAddress: change.Address,
			AttributePath:   path,
			Summary:         "Derived from Terraform plan change.",
		}},
	}
}

func isDeletion(change domain.ResourceChange) bool {
	return len(change.Actions) == 1 && change.Actions[0] == domain.ActionDelete
}

func hasMaterialAction(change domain.ResourceChange) bool {
	for _, action := range change.Actions {
		if action != domain.ActionNoOp && action != domain.ActionRead {
			return true
		}
	}
	return false
}

func isProduction(change domain.ResourceChange, identifiers []string) bool {
	values := []string{change.Address}
	for _, path := range []string{"tags.Environment", "tags.environment", "tags_all.Environment", "tags_all.environment"} {
		if value, ok := change.Before[path]; ok && value.State == domain.ValueKnown {
			values = append(values, fmt.Sprint(value.Value))
		}
	}
	for _, value := range values {
		for _, token := range productionTokens(value) {
			for _, identifier := range identifiers {
				if token == strings.ToLower(identifier) {
					return true
				}
			}
		}
	}
	return false
}

func productionTokens(value string) []string {
	return strings.FieldsFunc(strings.ToLower(value), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

func isSecurityGroup(resourceType string) bool {
	return resourceType == "aws_security_group" || resourceType == "aws_vpc_security_group_ingress_rule" || resourceType == "aws_vpc_security_group_egress_rule"
}

func introducesPublicCIDR(change domain.ResourceChange) bool {
	for path, value := range change.After {
		if !(strings.Contains(path, "cidr_blocks") || strings.HasSuffix(path, "cidr_ipv4") || strings.HasSuffix(path, "cidr_ipv6")) || !isPublicCIDR(value) {
			continue
		}
		before, present := change.Before[path]
		if !present || !isPublicCIDR(before) {
			return true
		}
	}
	return false
}

func isPublicCIDR(value domain.AttributeValue) bool {
	if value.State != domain.ValueKnown {
		return false
	}
	text, ok := value.Value.(string)
	return ok && (text == "0.0.0.0/0" || text == "::/0")
}

func isEncryptionAttribute(path string) bool {
	return path == "encrypted" || strings.HasSuffix(path, ".encrypted") || path == "storage_encrypted" || strings.HasSuffix(path, ".storage_encrypted")
}

func knownBool(value domain.AttributeValue, expected bool) bool {
	actual, ok := value.Value.(bool)
	return value.State == domain.ValueKnown && ok && actual == expected
}

func isCapacityAttribute(path string) bool {
	for _, suffix := range []string{"allocated_storage", "read_capacity", "write_capacity", "desired_capacity", "min_size", "max_size", "replicas"} {
		if path == suffix || strings.HasSuffix(path, "."+suffix) {
			return true
		}
	}
	return false
}

func increased(before, after domain.AttributeValue) bool {
	if before.State != domain.ValueKnown || after.State != domain.ValueKnown {
		return false
	}
	beforeNumber, beforeOK := numberValue(before.Value)
	afterNumber, afterOK := numberValue(after.Value)
	return beforeOK && afterOK && afterNumber > beforeNumber
}

func numberValue(value any) (float64, bool) {
	switch typed := value.(type) {
	case json.Number:
		parsed, err := typed.Float64()
		return parsed, err == nil
	case float64:
		return typed, true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	case string:
		parsed, err := strconv.ParseFloat(typed, 64)
		return parsed, err == nil
	default:
		return 0, false
	}
}

func scoreFindings(findings []domain.Finding) (overall, cost, reliability, security domain.RiskScore) {
	for _, finding := range findings {
		points := severityPoints(finding.Severity)
		overall += points
		for _, category := range finding.Categories {
			switch category {
			case domain.RiskCategoryCost:
				cost += points
			case domain.RiskCategoryReliability:
				reliability += points
			case domain.RiskCategorySecurity:
				security += points
			}
		}
	}
	return capScore(overall), capScore(cost), capScore(reliability), capScore(security)
}

func severityPoints(severity domain.Severity) domain.RiskScore {
	switch severity {
	case domain.SeverityCritical:
		return 60
	case domain.SeverityHigh:
		return 35
	case domain.SeverityMedium:
		return 15
	case domain.SeverityLow:
		return 5
	default:
		return 0
	}
}

func capScore(score domain.RiskScore) domain.RiskScore {
	if score > 100 {
		return 100
	}
	return score
}

func levelFor(score domain.RiskScore) domain.RiskLevel {
	switch {
	case score >= 75:
		return domain.RiskCritical
	case score >= 50:
		return domain.RiskHigh
	case score >= 20:
		return domain.RiskMedium
	default:
		return domain.RiskLow
	}
}

func recommendationFor(score domain.RiskScore) domain.Recommendation {
	switch {
	case score >= 60:
		return domain.RecommendationBlock
	case score >= 20:
		return domain.RecommendationReview
	default:
		return domain.RecommendationSafe
	}
}

func dimensionSummary(name string, score domain.RiskScore) string {
	if score == 0 {
		return "No deterministic " + name + " risks detected."
	}
	return fmt.Sprintf("Deterministic %s risk score: %d/100.", name, score)
}

func explanationFor(findings []domain.Finding) string {
	if len(findings) == 0 {
		return "No risky infrastructure changes were detected by the configured deterministic checks."
	}
	return fmt.Sprintf("%d deterministic risk finding(s) were identified. The highest finding severity is %s.", len(findings), highestSeverity(findings))
}

func highestSeverity(findings []domain.Finding) domain.Severity {
	highest := domain.SeverityInfo
	for _, finding := range findings {
		if severityPoints(finding.Severity) > severityPoints(highest) {
			highest = finding.Severity
		}
	}
	return highest
}

func changedResourceCounts(plan domain.Plan, critical map[string]struct{}) (changed, criticalChanged int) {
	for _, change := range plan.ResourceChanges {
		if !hasMaterialAction(change) {
			continue
		}
		changed++
		if _, ok := critical[change.Type]; ok {
			criticalChanged++
		}
	}
	return changed, criticalChanged
}

func criticalResourceTypes() map[string]struct{} {
	return map[string]struct{}{
		"aws_autoscaling_group":   {},
		"aws_db_instance":         {},
		"aws_eks_cluster":         {},
		"aws_elasticache_cluster": {},
		"aws_lb":                  {},
		"aws_rds_cluster":         {},
		"aws_route53_record":      {},
	}
}
