package storage

import (
	"context"
	"encoding/json"
	"fmt"

	vulnzstorage "github.com/shift/vulnz/pkg/storage"
)

// Re-export types from pkg/storage for use in unified Backend methods.
type ControlRow = vulnzstorage.ControlRow
type VulnerabilityRow = vulnzstorage.VulnerabilityRow
type MappingRow = vulnzstorage.MappingRow

// ---------------------------------------------------------------------------
// SQLiteBackend — unified Backend interface adapters
// ---------------------------------------------------------------------------

// WriteVulnerability stores a vulnerability record by wrapping it in an Envelope
// and delegating to the existing Write method.
func (s *SQLiteBackend) WriteVulnerability(ctx context.Context, id string, record interface{}) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal vulnerability record: %w", err)
	}
	envelope := &Envelope{
		Schema:     "https://schema.vulnz.sh/vuln/1.0",
		Identifier: id,
		Item:       json.RawMessage(data),
	}
	return s.Write(ctx, envelope)
}

// ReadVulnerability retrieves a vulnerability record as raw JSON bytes.
func (s *SQLiteBackend) ReadVulnerability(ctx context.Context, id string) ([]byte, error) {
	envelope, err := s.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// ListAllVulnerabilities returns all vulnerability records as VulnerabilityRow entries.
func (s *SQLiteBackend) ListAllVulnerabilities(ctx context.Context) ([]VulnerabilityRow, error) {
	ids, err := s.List(ctx)
	if err != nil {
		return nil, err
	}

	rows := make([]VulnerabilityRow, 0, len(ids))
	for _, id := range ids {
		envelope, err := s.Read(ctx, id)
		if err != nil {
			continue // skip unreadable records
		}
		data, err := json.Marshal(envelope)
		if err != nil {
			continue
		}
		rows = append(rows, VulnerabilityRow{
			ID:   id,
			Data: data,
		})
	}
	return rows, nil
}

// GRC Control operations — internal/storage is vulnerability-only.
// These methods return empty results since the internal/storage backends
// do not store GRC control data. Use pkg/storage.SQLiteBackend for full GRC support.

// WriteControl is not supported by internal/storage backends.
func (s *SQLiteBackend) WriteControl(ctx context.Context, id string, control interface{}) error {
	return fmt.Errorf("WriteControl not supported by internal storage; use pkg/storage")
}

// ReadControl is not supported by internal/storage backends.
func (s *SQLiteBackend) ReadControl(ctx context.Context, id string) ([]byte, error) {
	return nil, fmt.Errorf("ReadControl not supported by internal storage; use pkg/storage")
}

// ListAllControls returns empty (no GRC data in internal/storage).
func (s *SQLiteBackend) ListAllControls(ctx context.Context) ([]ControlRow, error) {
	return nil, nil
}

// ListControlsByCWE returns empty (no GRC data in internal/storage).
func (s *SQLiteBackend) ListControlsByCWE(ctx context.Context, cwe string) ([]ControlRow, error) {
	return nil, nil
}

// ListControlsByCPE returns empty (no GRC data in internal/storage).
func (s *SQLiteBackend) ListControlsByCPE(ctx context.Context, cpe string) ([]ControlRow, error) {
	return nil, nil
}

// ListControlsByFramework returns empty (no GRC data in internal/storage).
func (s *SQLiteBackend) ListControlsByFramework(ctx context.Context, framework string) ([]ControlRow, error) {
	return nil, nil
}

// ListControlsByTag returns empty (no GRC data in internal/storage).
func (s *SQLiteBackend) ListControlsByTag(ctx context.Context, tag string) ([]ControlRow, error) {
	return nil, nil
}

// WriteMapping is not supported by internal/storage backends.
func (s *SQLiteBackend) WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error {
	return fmt.Errorf("WriteMapping not supported by internal storage; use pkg/storage")
}

// ListMappings returns empty (no mapping data in internal/storage).
func (s *SQLiteBackend) ListMappings(ctx context.Context, vulnID string) ([]MappingRow, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// FlatFileBackend — unified Backend interface adapters
// ---------------------------------------------------------------------------

// WriteVulnerability stores a vulnerability record by wrapping it in an Envelope.
func (f *FlatFileBackend) WriteVulnerability(ctx context.Context, id string, record interface{}) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal vulnerability record: %w", err)
	}
	envelope := &Envelope{
		Schema:     "https://schema.vulnz.sh/vuln/1.0",
		Identifier: id,
		Item:       json.RawMessage(data),
	}
	return f.Write(ctx, envelope)
}

// ReadVulnerability retrieves a vulnerability record as raw JSON bytes.
func (f *FlatFileBackend) ReadVulnerability(ctx context.Context, id string) ([]byte, error) {
	envelope, err := f.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope)
}

// ListAllVulnerabilities returns all vulnerability records as VulnerabilityRow entries.
func (f *FlatFileBackend) ListAllVulnerabilities(ctx context.Context) ([]VulnerabilityRow, error) {
	ids, err := f.List(ctx)
	if err != nil {
		return nil, err
	}

	rows := make([]VulnerabilityRow, 0, len(ids))
	for _, id := range ids {
		envelope, err := f.Read(ctx, id)
		if err != nil {
			continue
		}
		data, err := json.Marshal(envelope)
		if err != nil {
			continue
		}
		rows = append(rows, VulnerabilityRow{
			ID:   id,
			Data: data,
		})
	}
	return rows, nil
}

// WriteControl is not supported by internal/storage backends.
func (f *FlatFileBackend) WriteControl(ctx context.Context, id string, control interface{}) error {
	return fmt.Errorf("WriteControl not supported by internal storage; use pkg/storage")
}

// ReadControl is not supported by internal/storage backends.
func (f *FlatFileBackend) ReadControl(ctx context.Context, id string) ([]byte, error) {
	return nil, fmt.Errorf("ReadControl not supported by internal storage; use pkg/storage")
}

// ListAllControls returns empty (no GRC data in internal/storage).
func (f *FlatFileBackend) ListAllControls(ctx context.Context) ([]ControlRow, error) {
	return nil, nil
}

// ListControlsByCWE returns empty (no GRC data in internal/storage).
func (f *FlatFileBackend) ListControlsByCWE(ctx context.Context, cwe string) ([]ControlRow, error) {
	return nil, nil
}

// ListControlsByCPE returns empty (no GRC data in internal/storage).
func (f *FlatFileBackend) ListControlsByCPE(ctx context.Context, cpe string) ([]ControlRow, error) {
	return nil, nil
}

// ListControlsByFramework returns empty (no GRC data in internal/storage).
func (f *FlatFileBackend) ListControlsByFramework(ctx context.Context, framework string) ([]ControlRow, error) {
	return nil, nil
}

// ListControlsByTag returns empty (no GRC data in internal/storage).
func (f *FlatFileBackend) ListControlsByTag(ctx context.Context, tag string) ([]ControlRow, error) {
	return nil, nil
}

// WriteMapping is not supported by internal/storage backends.
func (f *FlatFileBackend) WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error {
	return fmt.Errorf("WriteMapping not supported by internal storage; use pkg/storage")
}

// ListMappings returns empty (no mapping data in internal/storage).
func (f *FlatFileBackend) ListMappings(ctx context.Context, vulnID string) ([]MappingRow, error) {
	return nil, nil
}
