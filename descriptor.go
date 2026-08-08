// Package repost is the Repost client runtime for Go. Generated clients
// (emitted by `repost schema generate`) embed serialization descriptors and
// typed structs; this package implements every behavior behind them —
// descriptor-driven serialization, the Standard Webhooks envelope, the HTTP
// transport with retries and idempotency, and the injectable clock/id seams.
// The behavioral contract is sdk/conformance/CONTRACT.md in the Repost
// monorepo, pinned byte-for-byte by its vectors.
//
// See https://repost.sh/docs/send/go/quickstart to get started.
package repost

import (
	"fmt"
	"sort"
)

// DefaultSpec is an @default injection spec: literals are injected verbatim;
// "now" emits an ISO-8601 timestamp at send time; "uuid" / "cuid" are
// generated at send time.
type DefaultSpec struct {
	// Kind is one of "literal", "now", "uuid", or "cuid".
	Kind string `json:"kind"`
	// Value is the injected value when Kind is "literal".
	Value any `json:"value,omitempty"`
}

// FieldDescriptor is one field's serialization descriptor, as emitted into
// the generated client by `repost schema generate`. Field order is payload
// key order.
type FieldDescriptor struct {
	// SchemaName is the DSL identifier — the key on SDK inputs.
	SchemaName string `json:"schemaName,omitempty"`
	// WireName is the explicit post-@map wire key.
	WireName string `json:"wireName,omitempty"`
	// ScalarKind is descriptor v2's closed language-neutral scalar identity.
	ScalarKind string `json:"scalarKind,omitempty"`
	// DescriptorID references an enum or nested model descriptor.
	DescriptorID string `json:"descriptorId,omitempty"`
	// RequiredInInput distinguishes required presence from nullability.
	RequiredInInput bool `json:"requiredInInput"`
	// NullableInInput permits an explicitly present null.
	NullableInInput bool `json:"nullableInInput"`
	// List marks the field as a list container; elements are never nullable.
	List bool `json:"list"`
	// Default is the typed client-side default, nil when absent.
	Default *DefaultSpec `json:"default"`

	// Descriptor-format-1 compatibility fields. Generated v2 clients never
	// set these; the immutable v1 conformance vectors still decode them.
	// Name is the DSL identifier — the key in dynamic input maps and the
	// value of the `repost` struct tag on generated structs.
	Name string `json:"name,omitempty"`
	// Wire is the @map'd wire name; empty means Name is the wire name.
	Wire string `json:"wire,omitempty"`
	// List is true for list arity — elements are serialized one by one.
	// Model names a nested payload model to recurse into; empty means none.
	Model string `json:"model,omitempty"`
	// Enum maps member name → wire value; nil means the field is not an enum.
	Enum map[string]string `json:"enum,omitempty"`
	// Default is the @default injection applied when the field is absent
	// from the input; nil means no default.
}

// ModelDescriptor is a payload model's serialization descriptor.
type ModelDescriptor struct {
	// Fields in declaration order — the wire emits keys in this order.
	Fields []FieldDescriptor `json:"fields"`
}

// EventDescriptor is one catalog member's binding: wire event type plus
// payload model.
type EventDescriptor struct {
	// Type is the wire event type, e.g. "book.created".
	Type string `json:"type"`
	// Model is the payload model's key in the model-descriptor map.
	Model string `json:"model"`
}

// SchemaDescriptor is everything the runtime needs from the generated client.
type SchemaDescriptor struct {
	// DescriptorFormatVersion is the descriptor-format version the generated
	// client was emitted for; Send refuses a mismatch.
	DescriptorFormatVersion int
	// Enums maps enum descriptor ID to member name to wire value.
	Enums map[string]map[string]string
	// Models maps model name → serialization descriptor.
	Models map[string]ModelDescriptor
	// Webhooks maps camelCase(Catalog) → member → event binding.
	Webhooks map[string]map[string]EventDescriptor
}

// ValidateSchemaDescriptor performs the construction-time descriptor-v2
// handshake, including the generated-source shape. This prevents a new
// runtime from silently accepting pointer-shaped format-1 generated models.
func ValidateSchemaDescriptor(schema SchemaDescriptor) error {
	if err := AssertDescriptorVersion(schema.DescriptorFormatVersion); err != nil {
		return err
	}
	modelNames := sortedKeys(schema.Models)
	for _, modelName := range modelNames {
		model := schema.Models[modelName]
		for index := range model.Fields {
			field := &model.Fields[index]
			if !isV2Field(field) {
				return fmt.Errorf("repost: [GENERATED_SOURCE_OUTDATED] $.models.%s.fields[%d]: generated model uses descriptor format 1; re-run `repost schema generate` with the current CLI", modelName, index)
			}
			if err := validateFieldDescriptor(field, appendPath("$", field.SchemaName)); err != nil {
				return err
			}
			if err := validateDescriptorReference(schema.Models, schema.Enums, modelName, index, field); err != nil {
				return err
			}
		}
	}
	for _, group := range sortedKeys(schema.Webhooks) {
		members := schema.Webhooks[group]
		for _, member := range sortedKeys(members) {
			event := members[member]
			if _, ok := schema.Models[event.Model]; !ok {
				path := appendPath(appendPath("$.webhooks", group), member) + ".model"
				return validationError("INVALID_DESCRIPTOR_REFERENCE", path, fmt.Sprintf("model descriptor %q does not exist", event.Model))
			}
		}
	}
	return nil
}

func validateModelDescriptorReferences(models map[string]ModelDescriptor, enums map[string]map[string]string) error {
	for _, modelName := range sortedKeys(models) {
		model := models[modelName]
		for index := range model.Fields {
			field := &model.Fields[index]
			if !isV2Field(field) {
				continue
			}
			if err := validateFieldDescriptor(field, appendPath("$", field.SchemaName)); err != nil {
				return err
			}
			if err := validateDescriptorReference(models, enums, modelName, index, field); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateDescriptorReference(models map[string]ModelDescriptor, enums map[string]map[string]string, modelName string, index int, field *FieldDescriptor) error {
	if field.ScalarKind != "enum" && field.ScalarKind != "model" {
		return nil
	}
	path := fmt.Sprintf("%s.fields[%d].descriptorId", appendPath("$.models", modelName), index)
	if field.ScalarKind == "enum" {
		if _, ok := enums[field.DescriptorID]; ok && field.DescriptorID != "" {
			return nil
		}
	} else if _, ok := models[field.DescriptorID]; ok && field.DescriptorID != "" {
		return nil
	}
	return validationError("INVALID_DESCRIPTOR_REFERENCE", path, fmt.Sprintf("%s descriptor %q does not exist", field.ScalarKind, field.DescriptorID))
}

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
