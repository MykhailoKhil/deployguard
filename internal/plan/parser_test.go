package plan

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/deployguard/deployguard/internal/domain"
)

func TestParseNormalizesTerraformResourceChange(t *testing.T) {
	input := `{
  "format_version": "1.2",
  "terraform_version": "1.10.0",
  "resource_changes": [{
    "address": "aws_db_instance.primary",
    "mode": "managed",
    "type": "aws_db_instance",
    "provider_name": "registry.terraform.io/hashicorp/aws",
    "change": {
      "actions": ["update"],
      "before": {"publicly_accessible": false, "allocated_storage": 20},
      "after": {"publicly_accessible": true, "allocated_storage": 100},
      "after_unknown": {}
    }
  }]
}`

	parsed, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if parsed.FormatVersion != "1.2" || parsed.TerraformVersion != "1.10.0" {
		t.Fatalf("Parse() versions = %#v", parsed)
	}
	if len(parsed.ResourceChanges) != 1 {
		t.Fatalf("Parse() found %d resource changes, want 1", len(parsed.ResourceChanges))
	}

	change := parsed.ResourceChanges[0]
	if change.Mode != domain.ResourceModeManaged || change.Actions[0] != domain.ActionUpdate {
		t.Fatalf("Parse() change = %#v", change)
	}
	if value := change.Before["publicly_accessible"]; value.State != domain.ValueKnown || value.Value != false {
		t.Errorf("before publicly_accessible = %#v, want known false", value)
	}
	if value := change.After["allocated_storage"]; value.State != domain.ValueKnown || value.Value != json.Number("100") {
		t.Errorf("after allocated_storage = %#v, want known json number 100", value)
	}
}

func TestParseRedactsSensitiveAndUnknownValues(t *testing.T) {
	input := `{
  "format_version": "1.2",
  "resource_changes": [{
    "address": "aws_db_instance.primary",
    "mode": "managed",
    "type": "aws_db_instance",
    "change": {
      "actions": ["update"],
      "after": {
        "password": "do-not-retain",
        "endpoint": "pending.example.test",
        "nested": {"token": "also-do-not-retain"}
      },
      "after_unknown": {"endpoint": true},
      "after_sensitive": {"password": true, "nested": {"token": true}}
    }
  }]
}`

	parsed, err := Parse(strings.NewReader(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	after := parsed.ResourceChanges[0].After
	if value := after["password"]; value.State != domain.ValueSensitive || value.Value != nil {
		t.Errorf("password = %#v, want redacted sensitive value", value)
	}
	if value := after["endpoint"]; value.State != domain.ValueUnknown || value.Value != nil {
		t.Errorf("endpoint = %#v, want unknown value", value)
	}
	if value := after["nested.token"]; value.State != domain.ValueSensitive || value.Value != nil {
		t.Errorf("nested.token = %#v, want redacted sensitive value", value)
	}
}

func TestParseRejectsInvalidPlan(t *testing.T) {
	_, err := Parse(strings.NewReader(`{"format_version":"1.2","resource_changes":"not-an-array"}`))
	if err == nil {
		t.Fatal("Parse() accepted a malformed Terraform plan")
	}
}

func planWithAfter(after string) string {
	return `{"format_version":"1.2","resource_changes":[{"address":"aws_x.a","mode":"managed","type":"aws_x","provider_name":"registry.terraform.io/hashicorp/aws","change":{"actions":["create"],"before":null,"after":` + after + `,"after_unknown":{}}}]}`
}

func TestParseRejectsExcessiveNesting(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxAttributeDepth+5) + `1` + strings.Repeat(`}`, maxAttributeDepth+5)
	if _, err := Parse(strings.NewReader(planWithAfter(deep))); err == nil || !strings.Contains(err.Error(), "nesting") {
		t.Fatalf("Parse() error = %v, want nesting error", err)
	}
}

func TestParseRejectsTooManyAttributes(t *testing.T) {
	var builder strings.Builder
	builder.WriteString("[")
	for i := 0; i < maxAttributes+1; i++ {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString("0")
	}
	builder.WriteString("]")
	input := planWithAfter(`{"items":` + builder.String() + `}`)
	if _, err := Parse(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "attribute limit") {
		t.Fatalf("Parse() error = %v, want attribute limit error", err)
	}
}

func TestParseRejectsTooManyResourceChanges(t *testing.T) {
	change := `{"address":"aws_x.a","mode":"managed","type":"aws_x","provider_name":"p","change":{"actions":["no-op"],"before":{},"after":{},"after_unknown":{}}}`
	input := `{"format_version":"1.2","resource_changes":[` + strings.TrimSuffix(strings.Repeat(change+",", maxResourceChanges+1), ",") + `]}`
	if _, err := Parse(strings.NewReader(input)); err == nil || !strings.Contains(err.Error(), "resource change limit") {
		t.Fatalf("Parse() error = %v, want resource change limit error", err)
	}
}

func TestParseAcceptsRedactedWorkflowOutput(t *testing.T) {
	file, err := os.Open("testdata/redacted-plan.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	parsed, err := Parse(file)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(parsed.ResourceChanges) != 2 {
		t.Fatalf("resource changes = %d, want 2", len(parsed.ResourceChanges))
	}
	password := parsed.ResourceChanges[0].After["password"]
	if password.State != domain.ValueSensitive || password.Value != nil {
		t.Fatalf("password = %#v, want redacted sensitive value", password)
	}
}
