package telemetry

import (
	"fmt"

	"github.com/google/uuid"
)

// newExecutionID returns a UUID v4 string (RFC 4122).
func newExecutionID() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generating execution id: %w", err)
	}
	return u.String(), nil
}
