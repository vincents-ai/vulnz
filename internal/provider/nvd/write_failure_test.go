package nvd_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincents-ai/vulnz/internal/provider"
	"github.com/vincents-ai/vulnz/internal/provider/nvd"
	"github.com/vincents-ai/vulnz/pkg/storage"
)

// failingWriteBackend fails the Nth Write and records what was attempted.
// Backend is embedded so the other methods satisfy the interface without
// being implemented; this test only exercises the write path.
type failingWriteBackend struct {
	storage.Backend
	failOn   int
	writes   int
	attempts []string
}

func (b *failingWriteBackend) Write(_ context.Context, env *storage.Envelope) error {
	b.writes++
	b.attempts = append(b.attempts, env.Identifier)
	if b.writes == b.failOn {
		return errors.New("simulated storage failure")
	}
	return nil
}

// nvdPage builds a minimal NVD API page containing the given CVE IDs.
func nvdPage(cves ...string) string {
	type vuln struct {
		ID  string `json:"id"`
		CVE struct {
			ID string `json:"id"`
		} `json:"cve"`
	}
	results := make([]vuln, 0, len(cves))
	for _, c := range cves {
		var v vuln
		v.ID = c
		v.CVE.ID = c
		results = append(results, v)
	}
	out, _ := json.Marshal(map[string]any{
		"totalResults":    len(cves),
		"resultsPerPage":  len(cves),
		"startIndex":      0,
		"vulnerabilities": results,
	})
	return string(out)
}

func newNVDWriteTestServer(t *testing.T, cves ...string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdPage(cves...)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func writeTestManager(t *testing.T, srv *httptest.Server) *nvd.Manager {
	t.Helper()
	cfg := provider.Config{
		Name:      "nvd",
		Workspace: t.TempDir(),
		HTTP: provider.HTTPConfig{
			Timeout: 10 * time.Second, UserAgent: "vulnz-go-test/1.0",
			MaxRetries: 1, RateLimitRPS: 10,
		},
		Logger: slog.Default(),
	}
	m := nvd.NewManagerWithAPIURL(cfg, srv.URL+"/rest/json/cves/2.0")
	m.SetRetryWait(10 * time.Millisecond)
	return m
}

// A write failure must abort the sync. Previously the callback logged a
// warning and returned nil, so GetStream reported success, the executor
// advanced its cursor, and the record was silently lost: the next
// incremental run would start after it and never re-fetch it.
func TestNVDWriteFailureAbortsSyncRatherThanLosingTheRecord(t *testing.T) {
	srv := newNVDWriteTestServer(t, "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")
	m := writeTestManager(t, srv)

	backend := &failingWriteBackend{failOn: 2}
	count, err := m.GetStream(context.Background(), nil, backend)

	if err == nil {
		t.Fatalf("a failed write must not be reported as a successful sync "+
			"(count=%d, wrote %v): the caller advances its cursor on a nil error, "+
			"so CVE-2026-0002 would be skipped forever", count, backend.attempts)
	}
	if !errors.Is(err, backendError(backend)) && !containsAny(err.Error(), "simulated storage failure") {
		t.Errorf("error should identify the write failure, got: %v", err)
	}
	if len(backend.attempts) < 2 {
		t.Fatalf("expected the write to have been attempted, got %v", backend.attempts)
	}
	t.Logf("sync aborted as required after %d write(s), error: %v", backend.writes, err)
}

// With no failures the run must still succeed, so the fix cannot be a blanket
// refusal to stream.
func TestNVDSyncSucceedsWhenAllWritesSucceed(t *testing.T) {
	srv := newNVDWriteTestServer(t, "CVE-2026-0001", "CVE-2026-0002")
	m := writeTestManager(t, srv)

	backend := &failingWriteBackend{failOn: -1}
	count, err := m.GetStream(context.Background(), nil, backend)
	if err != nil {
		t.Fatalf("a clean sync must not error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 records streamed, got %d", count)
	}
}

func backendError(b *failingWriteBackend) error { return nil }

func containsAny(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

var _ = fmt.Sprintf
