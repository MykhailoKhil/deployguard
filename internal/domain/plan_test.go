package domain

import "testing"

func TestResourceChangeIsReplacementForEitherTerraformActionOrder(t *testing.T) {
	for _, actions := range [][]Action{
		{ActionDelete, ActionCreate},
		{ActionCreate, ActionDelete},
	} {
		change := ResourceChange{Actions: actions}
		if !change.IsReplacement() {
			t.Errorf("IsReplacement() = false for actions %v", actions)
		}
	}
}

func TestResourceChangeIsNotReplacementForSingleAction(t *testing.T) {
	change := ResourceChange{Actions: []Action{ActionUpdate}}
	if change.IsReplacement() {
		t.Fatal("IsReplacement() = true for an update")
	}
}

func TestPlanValidateAcceptsUnknownAndRedactedAttributes(t *testing.T) {
	plan := Plan{ResourceChanges: []ResourceChange{{
		Address: "aws_db_instance.primary",
		Type:    "aws_db_instance",
		Mode:    ResourceModeManaged,
		Actions: []Action{ActionUpdate},
		Before: map[string]AttributeValue{
			"publicly_accessible": {State: ValueKnown, Value: false},
		},
		After: map[string]AttributeValue{
			"publicly_accessible": {State: ValueUnknown},
			"password":            {State: ValueSensitive},
			"generated_secret":    {State: ValueUnknownSensitive},
		},
	}}}

	if err := plan.Validate(); err != nil {
		t.Fatalf("Validate() rejected a plan with unknown and redacted attributes: %v", err)
	}
}

func TestPlanValidateRejectsSensitiveValueMaterial(t *testing.T) {
	plan := Plan{ResourceChanges: []ResourceChange{{
		Address: "aws_db_instance.primary",
		Type:    "aws_db_instance",
		Mode:    ResourceModeManaged,
		Actions: []Action{ActionUpdate},
		After: map[string]AttributeValue{
			"password": {State: ValueSensitive, Value: "should-not-be-retained"},
		},
	}}}

	if err := plan.Validate(); err == nil {
		t.Fatal("Validate() accepted sensitive attribute material")
	}
}
