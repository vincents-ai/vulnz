package http

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// timeoutError is a net.Error with a timeout, used to check that retry
// classification survives wrapping.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// A wrapped timeout must still be retried. This package wraps errors with %w
// throughout, so a bare type assertion silently turned a transient failure into
// a permanent one for every wrapped caller — the same "decided the work was
// done when it was not" shape as the incremental cursor defect.
func TestWrappedTimeoutIsStillRetried(t *testing.T) {
	if !shouldRetry(0, timeoutError{}) {
		t.Fatal("an unwrapped timeout must be retried")
	}
	wrapped := fmt.Errorf("fetch vulnerability page: %w", timeoutError{})
	if !shouldRetry(0, wrapped) {
		t.Error("a WRAPPED timeout must be retried; errors.As is required because " +
			"this package wraps errors with %w throughout")
	}
	// Double-wrapped, as a caller three layers up would produce.
	twice := fmt.Errorf("provider sync: %w", wrapped)
	if !shouldRetry(0, twice) {
		t.Error("a doubly-wrapped timeout must still be retried")
	}
}

// A non-network error must not be retried; the fix must not over-retry.
func TestNonNetworkErrorIsNotRetried(t *testing.T) {
	if shouldRetry(0, errors.New("schema validation failed")) {
		t.Error("a validation error must not be retried; retrying cannot fix it")
	}
}

// The status-code path must be unaffected.
func TestStatusCodeRetryClassificationUnchanged(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		if !shouldRetry(code, nil) {
			t.Errorf("status %d should be retryable", code)
		}
	}
	if shouldRetry(http.StatusBadRequest, nil) {
		t.Error("400 must not be retryable")
	}
}

var _ = time.Second
