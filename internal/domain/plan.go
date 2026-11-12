package domain

import "fmt"

// Action is one operation Terraform will perform for a resource.
type Action string

const (
	ActionNoOp   Action = "no-op"
	ActionCreate Action = "create"
	ActionRead   Action = "read"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"
)

// ResourceMode distinguishes managed resources from data sources.
type ResourceMode string

const (
	ResourceModeManaged ResourceMode = "managed"
	ResourceModeData    ResourceMode = "data"
)

// ValueState describes whether an attribute value is known and safe to retain.
type ValueState string

const (
	ValueKnown     ValueState = "known"
	ValueUnknown   ValueState = "unknown"
	ValueSensitive ValueState = "sensitive"
	// ValueUnknownSensitive represents a value whose contents are unknown and
	// marked sensitive by Terraform.
	ValueUnknownSensitive ValueState = "unknown-sensitive"
)

// AttributeValue keeps unknown and sensitive values distinct from known values.
// Sensitive values must be redacted before they enter this domain model.
type AttributeValue struct {
	State ValueState
	Value any
}

// ResourceChange is the normalized Terraform change for one resource address.
// Attribute map keys are provider attribute paths, such as "storage_encrypted".
type ResourceChange struct {
	Address      string
	Type         string
	ProviderName string
	Mode         ResourceMode
	Actions      []Action
	Before       map[string]AttributeValue
	After        map[string]AttributeValue
}

// IsReplacement reports whether Terraform will delete and create this resource,
// regardless of the order in which those actions appear.
func (c ResourceChange) IsReplacement() bool {
	create, delete := false, false
	for _, action := range c.Actions {
		create = create || action == ActionCreate
		delete = delete || action == ActionDelete
	}
	return create && delete
}

// Plan contains the Terraform plan facts consumed by deterministic rules.
type Plan struct {
	TerraformVersion string
	FormatVersion    string
	ResourceChanges  []ResourceChange
}

// Validate checks normalized resource changes and ensures secret material has
// not been retained in an attribute marked sensitive.
func (p Plan) Validate() error {
	for i, change := range p.ResourceChanges {
		if change.Address == "" {
			return fmt.Errorf("resource change %d: address is required", i)
		}
		if change.Type == "" {
			return fmt.Errorf("resource change %q: type is required", change.Address)
		}
		if change.Mode != ResourceModeManaged && change.Mode != ResourceModeData {
			return fmt.Errorf("resource change %q: invalid mode %q", change.Address, change.Mode)
		}
		if len(change.Actions) == 0 {
			return fmt.Errorf("resource change %q: at least one action is required", change.Address)
		}
		for _, action := range change.Actions {
			if !validAction(action) {
				return fmt.Errorf("resource change %q: invalid action %q", change.Address, action)
			}
		}
		if err := validateAttributes(change.Address, "before", change.Before); err != nil {
			return err
		}
		if err := validateAttributes(change.Address, "after", change.After); err != nil {
			return err
		}
	}
	return nil
}

func validAction(action Action) bool {
	switch action {
	case ActionNoOp, ActionCreate, ActionRead, ActionUpdate, ActionDelete:
		return true
	default:
		return false
	}
}

func validateAttributes(address, side string, attributes map[string]AttributeValue) error {
	for path, value := range attributes {
		if path == "" {
			return fmt.Errorf("resource change %q: %s attribute path is required", address, side)
		}
		switch value.State {
		case ValueKnown:
		case ValueUnknown, ValueUnknownSensitive:
			if value.Value != nil {
				return fmt.Errorf("resource change %q: unknown attribute %q retains a value", address, path)
			}
		case ValueSensitive:
			if value.Value != nil {
				return fmt.Errorf("resource change %q: sensitive attribute %q retains a value", address, path)
			}
		default:
			return fmt.Errorf("resource change %q: attribute %q has invalid state %q", address, path, value.State)
		}
	}
	return nil
}
