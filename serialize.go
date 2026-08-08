package repost

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// SerializeModel serializes a send input into its wire payload, driven by
// legacy descriptor-format-1 model descriptors. Descriptor-v2 callers use
// SerializeModelWithSchema so enum descriptors and the version handshake are
// available during serialization.
//
// The input is either a map[string]any keyed by descriptor field names (a
// nil map value is explicit JSON null — presence distinguishes null from
// absence), or a struct/*struct whose fields carry `repost:"<name>"` tags
// (a nil pointer field is absent; non-pointer zero values are present;
// untagged fields are ignored).
func SerializeModel(models map[string]ModelDescriptor, modelName string, input any, generators Generators) (*OrderedObject, error) {
	return serializeModelAt(models, nil, modelName, input, generators.withDefaults(), "$")
}

// SerializeModelWithSchema serializes a descriptor-v2 model after validating
// the complete schema descriptor. Descriptor-v2 callers use this entry point;
// SerializeModel remains available for legacy model-only descriptors.
func SerializeModelWithSchema(schema SchemaDescriptor, modelName string, input any, generators Generators) (*OrderedObject, error) {
	if err := ValidateSchemaDescriptor(schema); err != nil {
		return nil, err
	}
	return serializeModelAtUnchecked(schema.Models, schema.Enums, modelName, input, generators.withDefaults(), "$")
}

func serializeModelAt(models map[string]ModelDescriptor, enums map[string]map[string]string, modelName string, input any, generators Generators, path string) (*OrderedObject, error) {
	if err := validateModelDescriptorReferences(models, enums); err != nil {
		return nil, err
	}
	return serializeModelAtUnchecked(models, enums, modelName, input, generators, path)
}

func serializeModelAtUnchecked(models map[string]ModelDescriptor, enums map[string]map[string]string, modelName string, input any, generators Generators, path string) (*OrderedObject, error) {
	descriptor, ok := models[modelName]
	if !ok {
		return nil, fmt.Errorf("repost: no serialization descriptor for model %q", modelName)
	}
	get, err := inputGetter(modelName, input)
	if err != nil {
		return nil, err
	}

	payload := NewOrderedObject()
	issues := newSerializerValidationErrors()
	for index := range descriptor.Fields {
		field := &descriptor.Fields[index]
		name := fieldName(field)
		fieldPath := appendPath(path, name)
		if err := validateFieldDescriptor(field, fieldPath); err != nil {
			return nil, err
		}
		value, present := get(name)
		if !present {
			switch {
			case field.Default != nil:
				value = resolveDefault(field.Default, generators)
				if field.Default.Kind == "now" && field.ScalarKind == "datetime" {
					value = generatedDateTime(value.(string))
				}
			case isV2Field(field) && field.RequiredInInput:
				issues.add(validationError("REQUIRED_FIELD", fieldPath, "required field is absent"))
				continue
			default:
				continue
			}
		}
		if value == nil && isV2Field(field) && !field.NullableInInput {
			issues.add(validationError("NULL_NOT_ALLOWED", fieldPath, "null is not allowed"))
			continue
		}
		serialized, err := serializeValue(models, enums, field, value, generators, fieldPath)
		if err != nil {
			if !issues.add(err) {
				return nil, err
			}
			continue
		}
		wire := fieldWireName(field)
		payload.Set(wire, serialized)
	}
	if issues.issueCount != 0 {
		return nil, issues
	}
	return payload, nil
}

// inputGetter normalizes the two accepted input forms into a presence-aware
// field lookup.
func inputGetter(modelName string, input any) (func(name string) (any, bool), error) {
	if m, ok := input.(map[string]any); ok {
		return func(name string) (any, bool) {
			value, present := m[name]
			return value, present
		}, nil
	}

	rv := reflect.ValueOf(input)
	if rv.Kind() == reflect.Pointer && !rv.IsNil() {
		rv = rv.Elem()
	}
	if rv.IsValid() && rv.Kind() == reflect.Map {
		return nil, validationError("INVALID_JSON", "$", "object keys must be strings")
	}
	if !rv.IsValid() || rv.Kind() != reflect.Struct {
		return nil, fmt.Errorf("repost: expected an object for model %q, got %s", modelName, describeInput(input))
	}

	fields := make(map[string]reflect.Value)
	rt := rv.Type()
	for i := range rt.NumField() {
		tag := rt.Field(i).Tag.Get("repost")
		if tag == "" || tag == "-" || !rt.Field(i).IsExported() {
			continue
		}
		fields[tag] = rv.Field(i)
	}
	return func(name string) (any, bool) {
		fv, ok := fields[name]
		if !ok {
			return nil, false
		}
		if fv.CanInterface() {
			if optional, ok := fv.Interface().(optionalCarrier); ok {
				value, state := optional.repostOptional()
				switch state {
				case optionalAbsent:
					return nil, false
				case optionalNull:
					return nil, true
				default:
					return value, true
				}
			}
		}
		if fv.Kind() == reflect.Pointer {
			if fv.IsNil() {
				return nil, false // nil pointer = absent
			}
			return fv.Elem().Interface(), true
		}
		return fv.Interface(), true
	}, nil
}

func describeInput(input any) string {
	if input == nil {
		return "null"
	}
	return reflect.TypeOf(input).String()
}

// serializeValue applies list arity, then per-item model recursion or enum
// mapping.
func serializeValue(models map[string]ModelDescriptor, enums map[string]map[string]string, field *FieldDescriptor, value any, generators Generators, path string) (any, error) {
	if value == nil {
		return nil, nil
	}
	if field.List {
		rv := reflect.ValueOf(value)
		if rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array {
			if rv.Kind() == reflect.Slice && rv.IsNil() {
				if isV2Field(field) {
					return []any{}, nil
				}
				return nil, nil
			}
			items := make([]any, rv.Len())
			issues := newSerializerValidationErrors()
			for i := range rv.Len() {
				itemValue := rv.Index(i).Interface()
				itemPath := fmt.Sprintf("%s[%d]", path, i)
				if isNilValue(itemValue) && isV2Field(field) {
					issues.add(validationError("NULL_LIST_ELEMENT", itemPath, "null list elements are not allowed"))
					continue
				}
				item, err := serializeItem(models, enums, field, itemValue, generators, itemPath)
				if err != nil {
					if !issues.add(err) {
						return nil, err
					}
					continue
				}
				items[i] = item
			}
			if issues.issueCount != 0 {
				return nil, issues
			}
			return items, nil
		}
		if isV2Field(field) {
			return nil, validationError("TYPE_MISMATCH", path, "expected a list")
		}
	}
	return serializeItem(models, enums, field, value, generators, path)
}

func serializeItem(models map[string]ModelDescriptor, enums map[string]map[string]string, field *FieldDescriptor, value any, generators Generators, path string) (any, error) {
	if value, ok := value.(generatedDateTime); ok {
		return string(value), nil
	}
	model := field.Model
	if field.ScalarKind == "model" {
		model = field.DescriptorID
	}
	if model != "" {
		return serializeModelAtUnchecked(models, enums, model, value, generators, path)
	}
	enumValues := field.Enum
	if field.ScalarKind == "enum" {
		enumValues = enums[field.DescriptorID]
	}
	if enumValues != nil {
		// Kind-based check so generated named enum types (type Currency
		// string) map like plain strings.
		rv := reflect.ValueOf(value)
		if rv.IsValid() && rv.Kind() == reflect.String {
			if wire, mapped := enumValues[rv.String()]; mapped {
				return wire, nil
			}
			return value, nil // unrecognized members pass through verbatim
		}
		if isV2Field(field) {
			return nil, validationError("TYPE_MISMATCH", path, "expected enum string")
		}
		return value, nil // unrecognized members pass through verbatim
	}
	// A time.Time (generated DateTime fields; *time.Time arrives here already
	// dereferenced) serializes as the contract's timestamp canon in UTC.
	if t, ok := value.(time.Time); ok && (!isV2Field(field) || field.ScalarKind == "datetime") {
		return t.UTC().Format(timestampLayout), nil
	}
	if isV2Field(field) {
		if err := validateScalar(field.ScalarKind, value, path); err != nil {
			return nil, err
		}
	}
	return value, nil
}

type generatedDateTime string

var scalarKinds = map[string]struct{}{
	"string": {}, "boolean": {}, "int64": {}, "float64": {},
	"datetime": {}, "json": {}, "enum": {}, "model": {},
}

func isV2Field(field *FieldDescriptor) bool { return field.SchemaName != "" }

func fieldName(field *FieldDescriptor) string {
	if field.SchemaName != "" {
		return field.SchemaName
	}
	return field.Name
}

func fieldWireName(field *FieldDescriptor) string {
	if field.SchemaName != "" {
		return field.WireName
	}
	if field.Wire != "" {
		return field.Wire
	}
	return field.Name
}

func validateFieldDescriptor(field *FieldDescriptor, path string) error {
	if !isV2Field(field) {
		return nil
	}
	if _, ok := scalarKinds[field.ScalarKind]; !ok {
		return validationError("UNKNOWN_SCALAR_KIND", path, fmt.Sprintf("unknown scalar kind %q", field.ScalarKind))
	}
	return nil
}

func validateScalar(kind string, value any, path string) error {
	rv := reflect.ValueOf(value)
	var valid bool
	switch kind {
	case "string":
		valid = rv.IsValid() && rv.Kind() == reflect.String
	case "boolean":
		valid = rv.IsValid() && rv.Kind() == reflect.Bool
	case "int64":
		if number, ok := value.(json.Number); ok {
			_, err := strconv.ParseInt(string(number), 10, 64)
			valid = err == nil
		} else {
			valid = rv.IsValid() && rv.Kind() >= reflect.Int && rv.Kind() <= reflect.Int64
		}
	case "float64":
		if number, ok := value.(json.Number); ok {
			parsed, err := strconv.ParseFloat(string(number), 64)
			valid = err == nil
			if valid && (math.IsInf(parsed, 0) || math.IsNaN(parsed)) {
				return validationError("NON_FINITE_NUMBER", path, "non-finite numbers are not allowed")
			}
		} else {
			valid = rv.IsValid() && (rv.Kind() == reflect.Float32 || rv.Kind() == reflect.Float64)
		}
		if valid && rv.IsValid() && (rv.Kind() == reflect.Float32 || rv.Kind() == reflect.Float64) && (math.IsInf(rv.Float(), 0) || math.IsNaN(rv.Float())) {
			return validationError("NON_FINITE_NUMBER", path, "non-finite numbers are not allowed")
		}
	case "datetime":
		_, valid = value.(time.Time)
	case "json":
		return validateJSON(value, path)
	default:
		return nil
	}
	if !valid {
		return validationError("TYPE_MISMATCH", path, "value does not match "+kind)
	}
	return nil
}

func validateJSON(value any, path string) error {
	issues := newSerializerValidationErrors()
	validateJSONAt(value, path, make(map[jsonAncestor]struct{}), issues)
	if issues.issueCount != 0 {
		return issues
	}
	return nil
}

type jsonAncestor struct {
	kind    reflect.Kind
	pointer uintptr
	length  int
}

func validateJSONAt(value any, path string, activeAncestors map[jsonAncestor]struct{}, issues *serializerValidationErrors) {
	if value == nil {
		return
	}
	if number, ok := value.(json.Number); ok {
		parsed, err := strconv.ParseFloat(string(number), 64)
		if err != nil {
			issues.add(validationError("INVALID_JSON", path, "invalid JSON number"))
		} else if math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			issues.add(validationError("NON_FINITE_NUMBER", path, "non-finite numbers are not allowed"))
		}
		return
	}
	rv := reflect.ValueOf(value)
	for rv.Kind() == reflect.Interface {
		if rv.IsNil() {
			return
		}
		rv = rv.Elem()
	}

	var ancestor jsonAncestor
	entered := false
	switch rv.Kind() {
	case reflect.Map, reflect.Pointer, reflect.Slice:
		if rv.IsNil() {
			return
		}
		ancestor = jsonAncestor{kind: rv.Kind(), pointer: rv.Pointer()}
		if rv.Kind() == reflect.Slice {
			ancestor.length = rv.Len()
		}
		if _, ok := activeAncestors[ancestor]; ok {
			issues.add(validationErrorWithIssue("INVALID_JSON", "CYCLE", path, "cyclic JSON values are not allowed"))
			return
		}
		activeAncestors[ancestor] = struct{}{}
		entered = true
	}
	if entered {
		defer delete(activeAncestors, ancestor)
	}
	if rv.Kind() == reflect.Pointer {
		validateJSONAt(rv.Elem().Interface(), path, activeAncestors, issues)
		return
	}
	if rv.Kind() == reflect.Float32 || rv.Kind() == reflect.Float64 {
		if math.IsNaN(rv.Float()) || math.IsInf(rv.Float(), 0) {
			issues.add(validationError("NON_FINITE_NUMBER", path, "non-finite numbers are not allowed"))
		}
		return
	}
	switch rv.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return
	case reflect.String:
		if !utf8.ValidString(rv.String()) {
			issues.add(validationError("INVALID_UNICODE", path, "invalid Unicode is not allowed"))
		}
	case reflect.Slice, reflect.Array:
		for i := range rv.Len() {
			validateJSONAt(rv.Index(i).Interface(), fmt.Sprintf("%s[%d]", path, i), activeAncestors, issues)
		}
	case reflect.Map:
		keys := rv.MapKeys()
		for _, mapKey := range keys {
			if mapKey.Kind() != reflect.String {
				issues.add(validationError("INVALID_JSON", path+"[{*}]", "JSON object keys must be strings"))
				return
			}
			if !utf8.ValidString(mapKey.String()) {
				issues.add(validationError("INVALID_UNICODE", path+"[{*}]", "JSON object keys must be valid Unicode"))
				return
			}
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].String() < keys[j].String()
		})
		for _, mapKey := range keys {
			validateJSONAt(rv.MapIndex(mapKey).Interface(), path+"[{*}]", activeAncestors, issues)
		}
	default:
		issues.add(validationError("INVALID_JSON", path, "value is not representable as JSON"))
	}
}

var pathIdentifier = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*$`)

func appendPath(path, key string) string {
	if pathIdentifier.MatchString(key) {
		return path + "." + key
	}
	return path + "[" + quoteJSONString(key) + "]"
}

func quoteJSONString(value string) string {
	var quoted strings.Builder
	quoted.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"':
			quoted.WriteString(`\"`)
		case '\\':
			quoted.WriteString(`\\`)
		case '\b':
			quoted.WriteString(`\b`)
		case '\f':
			quoted.WriteString(`\f`)
		case '\n':
			quoted.WriteString(`\n`)
		case '\r':
			quoted.WriteString(`\r`)
		case '\t':
			quoted.WriteString(`\t`)
		default:
			if character < 0x20 {
				fmt.Fprintf(&quoted, `\u%04x`, character)
			} else {
				quoted.WriteRune(character)
			}
		}
	}
	quoted.WriteByte('"')
	return quoted.String()
}

func validationError(code, path, message string) error {
	return validationErrorWithIssue(code, code, path, message)
}

func validationErrorWithIssue(code, issueCode, path, message string) error {
	return &serializerValidationError{code: code, issueCode: issueCode, path: path, message: message}
}

type serializerValidationError struct {
	code      string
	issueCode string
	path      string
	message   string
}

func (e *serializerValidationError) Error() string {
	return fmt.Sprintf("repost: [%s] %s: %s", e.code, e.path, e.message)
}

const (
	maxValidationIssues         = 32
	maxValidationIssuePathBytes = 1_024
	maxValidationPathBytes      = 16_384
	validationPathMarker        = ".<truncated>"
)

type serializerValidationErrors struct {
	issues         []*serializerValidationError
	issueCount     int
	totalPathBytes int
}

func newSerializerValidationErrors() *serializerValidationErrors {
	return &serializerValidationErrors{issues: make([]*serializerValidationError, 0, maxValidationIssues)}
}

func (e *serializerValidationErrors) Error() string {
	if e != nil && len(e.issues) != 0 {
		return e.issues[0].Error()
	}
	return "repost: message validation failed"
}

func (e *serializerValidationErrors) add(err error) bool {
	var aggregate *serializerValidationErrors
	if errors.As(err, &aggregate) {
		e.merge(aggregate)
		return true
	}
	var issue *serializerValidationError
	if !errors.As(err, &issue) {
		return false
	}
	e.issueCount = saturatingValidationIssueCount(e.issueCount, 1)
	e.retain(issue)
	return true
}

func (e *serializerValidationErrors) merge(other *serializerValidationErrors) {
	if other == nil {
		return
	}
	e.issueCount = saturatingValidationIssueCount(e.issueCount, other.issueCount)
	for _, issue := range other.issues {
		e.retain(issue)
	}
}

func (e *serializerValidationErrors) retain(issue *serializerValidationError) {
	if issue == nil || len(e.issues) >= maxValidationIssues {
		return
	}
	snapshot := *issue
	snapshot.path = truncateValidationPath(snapshot.path)
	if e.totalPathBytes+len(snapshot.path) > maxValidationPathBytes {
		return
	}
	e.totalPathBytes += len(snapshot.path)
	e.issues = append(e.issues, &snapshot)
}

func saturatingValidationIssueCount(current, increment int) int {
	if increment <= 0 {
		return current
	}
	if current >= math.MaxInt32-increment {
		return math.MaxInt32
	}
	return current + increment
}

func truncateValidationPath(path string) string {
	if len(path) <= maxValidationIssuePathBytes {
		return path
	}
	prefixBytes := maxValidationIssuePathBytes - len(validationPathMarker)
	for prefixBytes > 0 && !utf8.RuneStart(path[prefixBytes]) {
		prefixBytes--
	}
	prefix := path[:prefixBytes]
	if path[prefixBytes] != '.' && path[prefixBytes] != '[' {
		for len(prefix) > 1 && prefix[len(prefix)-1] != '.' && prefix[len(prefix)-1] != ']' {
			prefix = prefix[:len(prefix)-1]
		}
		prefix = strings.TrimSuffix(prefix, ".")
	}
	return prefix + validationPathMarker
}

func isNilValue(value any) bool {
	if value == nil {
		return true
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func resolveDefault(spec *DefaultSpec, generators Generators) any {
	switch spec.Kind {
	case "now":
		return generators.Now()
	case "uuid":
		return generators.UUID()
	case "cuid":
		return generators.CUID()
	default: // "literal"
		return spec.Value
	}
}
