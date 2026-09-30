package provider

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// cursorOf reads the persisted high-water mark the next run would resume from.
func cursorOf(t *testing.T, workspace, provider string) time.Time {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(workspace, provider, "metadata.json"))
	if err != nil {
		t.Fatalf("read metadata: %v", err)
	}
	var state struct {
		Timestamp time.Time `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	return state.Timestamp
}

// The incremental query is bounded by a lastModEndDate captured when the
// request is BUILT, which for NVD is the moment FetchUpdatesStream is entered.
// Completion happens later — arbitrarily later for a large paginated run.
//
// If the cursor were the completion time, the next run's lower bound would sit
// above this run's upper bound, and every record modified in between would be
// fetched by neither run. That is a permanent, silent hole in a vulnerability
// feed, and it is invisible in the logs because both runs report success.
//
// The cursor must therefore be at or before the moment the query was bounded.
func TestPersistedCursorDoesNotLeaveAGapBetweenRuns(t *testing.T) {
	workspace := t.TempDir()
	e := &Executor{workspace: workspace, storeType: "json"}

	// The instant the provider's query upper bound was captured, and the
	// instant the run finished some time later.
	queryBoundedAt := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	runCompletedAt := time.Date(2026, 9, 30, 12, 40, 0, 0, time.UTC)

	if err := e.updateState("nvd", nil, 10, queryBoundedAt); err != nil {
		t.Fatalf("updateState: %v", err)
	}
	cursor := cursorOf(t, workspace, "nvd")

	if cursor.After(queryBoundedAt) {
		t.Fatalf("cursor %s is after the query upper bound %s: the next run would "+
			"start at %s and the 40 minutes in between would never be fetched, "+
			"by this run or the next",
			cursor, queryBoundedAt, cursor)
	}
	if cursor.After(runCompletedAt) {
		t.Fatalf("cursor %s is after the run's completion time %s", cursor, runCompletedAt)
	}
	t.Logf("cursor %s, query bounded at %s, completed at %s — windows overlap, no gap",
		cursor, queryBoundedAt, runCompletedAt)
}

// A cursor equal to the query bound is the tightest safe case: the next window
// starts exactly where this one ended, so nothing is missed and nothing is
// needlessly replayed.
func TestCursorMayEqualTheQueryBoundExactly(t *testing.T) {
	workspace := t.TempDir()
	e := &Executor{workspace: workspace, storeType: "json"}
	bound := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	if err := e.updateState("nvd", nil, 1, bound); err != nil {
		t.Fatalf("updateState: %v", err)
	}
	got := cursorOf(t, workspace, "nvd")
	if !got.Equal(bound) {
		t.Errorf("cursor = %s, want %s", got, bound)
	}
}

// readLastUpdated is what the next run reads, so the round trip through
// metadata must preserve the cursor rather than re-deriving it.
func TestReadLastUpdatedReturnsThePersistedCursor(t *testing.T) {
	workspace := t.TempDir()
	e := &Executor{workspace: workspace, storeType: "json"}
	bound := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	if err := e.updateState("nvd", nil, 1, bound); err != nil {
		t.Fatalf("updateState: %v", err)
	}
	got := e.readLastUpdated("nvd")
	if got == nil {
		t.Fatal("readLastUpdated returned nil; the next run would do a full bootstrap")
	}
	if !got.Equal(bound) {
		t.Errorf("readLastUpdated = %s, want %s", got, bound)
	}
}

var _ = context.Background
