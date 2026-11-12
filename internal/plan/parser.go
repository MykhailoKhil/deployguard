// Package plan parses Terraform's JSON plan output into DeployGuard's
// normalized domain model. It never executes Terraform or provider code.
package plan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/deployguard/deployguard/internal/domain"
)

const (
	maxPlanBytes       = 10 << 20
	maxResourceChanges = 5000
	maxAttributes      = 200000
	maxAttributeDepth  = 64
)

// attributeBudget bounds the number of flattened attributes across a plan so a
// small JSON document cannot expand into an unbounded in-memory map.
type attributeBudget struct{ remaining int }

func (b *attributeBudget) take() error {
	if b.remaining <= 0 {
		return fmt.Errorf("plan exceeds the %d attribute limit", maxAttributes)
	}
	b.remaining--
	return nil
}

// Parse reads one Terraform JSON plan. It bounds input size and redacts values
// marked sensitive by Terraform before returning normalized facts.
func Parse(input io.Reader) (domain.Plan, error) {
	limited := io.LimitReader(input, maxPlanBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return domain.Plan{}, fmt.Errorf("read Terraform plan: %w", err)
	}
	if len(data) > maxPlanBytes {
		return domain.Plan{}, fmt.Errorf("Terraform plan exceeds %d byte limit", maxPlanBytes)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var raw terraformPlan
	if err := decoder.Decode(&raw); err != nil {
		return domain.Plan{}, fmt.Errorf("decode Terraform plan: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return domain.Plan{}, fmt.Errorf("decode Terraform plan: multiple JSON values")
	}
	if raw.FormatVersion == "" {
		return domain.Plan{}, fmt.Errorf("decode Terraform plan: format_version is required")
	}

	if len(raw.ResourceChanges) > maxResourceChanges {
		return domain.Plan{}, fmt.Errorf("Terraform plan exceeds the %d resource change limit", maxResourceChanges)
	}
	budget := &attributeBudget{remaining: maxAttributes}
	parsed := domain.Plan{
		FormatVersion:    raw.FormatVersion,
		TerraformVersion: raw.TerraformVersion,
		ResourceChanges:  make([]domain.ResourceChange, 0, len(raw.ResourceChanges)),
	}
	for i, change := range raw.ResourceChanges {
		normalized, err := normalizeChange(change, budget)
		if err != nil {
			return domain.Plan{}, fmt.Errorf("resource_changes[%d]: %w", i, err)
		}
		parsed.ResourceChanges = append(parsed.ResourceChanges, normalized)
	}
	if err := parsed.Validate(); err != nil {
		return domain.Plan{}, fmt.Errorf("validate Terraform plan: %w", err)
	}
	return parsed, nil
}

type terraformPlan struct {
	FormatVersion    string                    `json:"format_version"`
	TerraformVersion string                    `json:"terraform_version"`
	ResourceChanges  []terraformResourceChange `json:"resource_changes"`
}

type terraformResourceChange struct {
	Address      string          `json:"address"`
	Mode         string          `json:"mode"`
	Type         string          `json:"type"`
	ProviderName string          `json:"provider_name"`
	Change       terraformChange `json:"change"`
}

type terraformChange struct {
	Actions         []string        `json:"actions"`
	Before          json.RawMessage `json:"before"`
	After           json.RawMessage `json:"after"`
	AfterUnknown    json.RawMessage `json:"after_unknown"`
	BeforeSensitive json.RawMessage `json:"before_sensitive"`
	AfterSensitive  json.RawMessage `json:"after_sensitive"`
}

func normalizeChange(raw terraformResourceChange, budget *attributeBudget) (domain.ResourceChange, error) {
	before, err := normalizeAttributes(raw.Change.Before, raw.Change.BeforeSensitive, nil, budget)
	if err != nil {
		return domain.ResourceChange{}, fmt.Errorf("before: %w", err)
	}
	after, err := normalizeAttributes(raw.Change.After, raw.Change.AfterSensitive, raw.Change.AfterUnknown, budget)
	if err != nil {
		return domain.ResourceChange{}, fmt.Errorf("after: %w", err)
	}

	actions := make([]domain.Action, len(raw.Change.Actions))
	for i, action := range raw.Change.Actions {
		actions[i] = domain.Action(action)
	}
	return domain.ResourceChange{
		Address:      raw.Address,
		Type:         raw.Type,
		ProviderName: raw.ProviderName,
		Mode:         domain.ResourceMode(raw.Mode),
		Actions:      actions,
		Before:       before,
		After:        after,
	}, nil
}

func normalizeAttributes(valueJSON, sensitiveJSON, unknownJSON json.RawMessage, budget *attributeBudget) (map[string]domain.AttributeValue, error) {
	value, err := decodeJSONObject(valueJSON)
	if err != nil {
		return nil, fmt.Errorf("decode attributes: %w", err)
	}
	sensitive, err := decodeMarker(sensitiveJSON)
	if err != nil {
		return nil, fmt.Errorf("decode sensitive markers: %w", err)
	}
	unknown, err := decodeMarker(unknownJSON)
	if err != nil {
		return nil, fmt.Errorf("decode unknown markers: %w", err)
	}

	attributes := make(map[string]domain.AttributeValue)
	for key, rawValue := range value {
		if err := flattenAttribute(attributes, key, rawValue, markerChild(sensitive, key), markerChild(unknown, key), 1, budget); err != nil {
			return nil, err
		}
	}
	return attributes, nil
}

func decodeJSONObject(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		return map[string]any{}, nil
	}
	return value, nil
}

func decodeMarker(raw json.RawMessage) (any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func flattenAttribute(attributes map[string]domain.AttributeValue, path string, value, sensitive, unknown any, depth int, budget *attributeBudget) error {
	if depth > maxAttributeDepth {
		return fmt.Errorf("attribute nesting exceeds %d levels", maxAttributeDepth)
	}
	if markerEnabled(sensitive) || markerEnabled(unknown) {
		if err := budget.take(); err != nil {
			return err
		}
		attributes[path] = protectedValue(sensitive, unknown)
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if err := flattenAttribute(attributes, path+"."+key, child, markerChild(sensitive, key), markerChild(unknown, key), depth+1, budget); err != nil {
				return err
			}
		}
	case []any:
		for i, child := range typed {
			index := fmt.Sprintf("%s[%d]", path, i)
			if err := flattenAttribute(attributes, index, child, markerIndex(sensitive, i), markerIndex(unknown, i), depth+1, budget); err != nil {
				return err
			}
		}
	default:
		if err := budget.take(); err != nil {
			return err
		}
		attributes[path] = domain.AttributeValue{State: domain.ValueKnown, Value: value}
	}
	return nil
}

func protectedValue(sensitive, unknown any) domain.AttributeValue {
	if markerEnabled(sensitive) && markerEnabled(unknown) {
		return domain.AttributeValue{State: domain.ValueUnknownSensitive}
	}
	if markerEnabled(sensitive) {
		return domain.AttributeValue{State: domain.ValueSensitive}
	}
	return domain.AttributeValue{State: domain.ValueUnknown}
}

func markerEnabled(marker any) bool {
	enabled, ok := marker.(bool)
	return ok && enabled
}

func markerChild(marker any, key string) any {
	if markerEnabled(marker) {
		return marker
	}
	if object, ok := marker.(map[string]any); ok {
		return object[key]
	}
	return nil
}

func markerIndex(marker any, index int) any {
	if markerEnabled(marker) {
		return marker
	}
	if list, ok := marker.([]any); ok && index < len(list) {
		return list[index]
	}
	return nil
}
