package schema

import (
	"errors"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ValidationError contains schema validation failures.
// It provides detailed information about what validation rules were violated.
type ValidationError struct {
	SchemaURL string
	Errors    []string
}

func (e *ValidationError) Error() string {
	if len(e.Errors) == 0 {
		return fmt.Sprintf("validation failed for schema %s", e.SchemaURL)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "validation failed for schema %s:\n", e.SchemaURL)
	for i, err := range e.Errors {
		fmt.Fprintf(&sb, "  [%d] %s\n", i+1, err)
	}
	return sb.String()
}

// FormatValidationError converts jsonschema error to readable format.
// It extracts all validation errors and returns a structured ValidationError.
func FormatValidationError(schemaURL string, err error) *ValidationError {
	if err == nil {
		return nil
	}

	verr := &ValidationError{
		SchemaURL: schemaURL,
		Errors:    make([]string, 0),
	}

	// Check if it's a validation error from jsonschema
	// errors.As, not a type assertion: anything upstream that wraps the
	// validation error made the assertion fail and silently discarded the
	// detailed schema errors, which is the entire purpose of this function.
	var ve *jsonschema.ValidationError
	if errors.As(err, &ve) {
		verr.Errors = append(verr.Errors, formatSchemaError(ve))

		// Add detailed errors if available
		for _, cause := range ve.Causes {
			verr.Errors = append(verr.Errors, formatSchemaError(cause))
		}
	} else {
		// Generic error
		verr.Errors = append(verr.Errors, err.Error())
	}

	return verr
}

// formatSchemaError formats a single jsonschema validation error.
func formatSchemaError(err *jsonschema.ValidationError) string {
	if err == nil {
		return ""
	}

	// Use the built-in Error() method which provides a formatted message
	return err.Error()
}
