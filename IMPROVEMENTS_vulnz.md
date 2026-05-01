# vulnz - Interface Design Improvement Plan

## Current State Assessment

**Status**: Partial interface design
**Effort Required**: Small

### Existing Interfaces

| Interface | Location | Purpose |
|-----------|----------|---------|
| `storage.Backend` | `internal/storage/storage.go:9` | Storage operations for vulnerability data |
| `storage.Backend` | `pkg/storage/sqlite.go:14` | Storage for vulnerabilities, GRC controls, mappings (different from internal) |
| `provider.Provider` | `internal/provider/provider.go:12` | Core interface for vulnerability data providers |
| `provider.MetadataProvider` | `internal/provider/provider.go:39` | Optional metadata interface |
| `provider.TagsProvider` | `internal/provider/provider.go:46` | Optional tags interface |
| `grc.Runner` | `internal/grc/registry.go:34` | GRC provider runner interface |

### Interface Usage Patterns

1. **Storage abstraction**: Two separate `Backend` interfaces exist (`internal/storage` and `pkg/storage`). The `pkg/storage` version is used by enrichment-engine.
2. **Provider pattern**: Well-designed with optional interface extensions (MetadataProvider, TagsProvider)
3. **Registry pattern**: `internal/grc/registry.go` uses factory functions, not interfaces

## Required Refactoring

### 1. Unify Storage Interfaces (Priority: High)

**Problem**: Two different `Backend` interfaces exist in `internal/storage` and `pkg/storage`.

**Solution**:
```go
// pkg/storage/backend.go - Single interface definition
package storage

import "context"

type Backend interface {
    // Vulnerability operations
    WriteVulnerability(ctx context.Context, id string, record interface{}) error
    ReadVulnerability(ctx context.Context, id string) ([]byte, error)
    ListAllVulnerabilities(ctx context.Context) ([]VulnerabilityRow, error)
    
    // GRC Control operations
    WriteControl(ctx context.Context, id string, control interface{}) error
    ReadControl(ctx context.Context, id string) ([]byte, error)
    ListAllControls(ctx context.Context) ([]ControlRow, error)
    ListControlsByCWE(ctx context.Context, cwe string) ([]ControlRow, error)
    ListControlsByCPE(ctx context.Context, cpe string) ([]ControlRow, error)
    ListControlsByFramework(ctx context.Context, framework string) ([]ControlRow, error)
    ListControlsByTag(ctx context.Context, tag string) ([]ControlRow, error)
    
    // Mapping operations
    WriteMapping(ctx context.Context, vulnID, controlID, framework, mappingType string, confidence float64, evidence string) error
    ListMappings(ctx context.Context, vulnID string) ([]MappingRow, error)
    
    // Lifecycle
    Close(ctx context.Context) error
}

// Internal re-exports for backward compatibility
// internal/storage/backend.go
package storage

import "github.com/shift/vulnz/pkg/storage"

type Backend = storage.Backend
```

**Files to modify**:
- `pkg/storage/backend.go` (new file)
- `pkg/storage/sqlite.go` - remove interface definition, keep implementation
- `internal/storage/storage.go` - re-export from pkg/storage
- Update all imports across vulnz and enrichment-engine

### 2. Extract Workspace Interface (Priority: Medium)

**Problem**: `internal/workspace/workspace.go` uses concrete type without interface.

**Solution**:
```go
// internal/workspace/workspace.go
type Workspace interface {
    Initialize(ctx context.Context) error
    Fetch(ctx context.Context, provider string) error
    Status(ctx context.Context) (*WorkspaceStatus, error)
    Checksum(ctx context.Context) (string, error)
}

type workspace struct { /* implementation */ }

func NewWorkspace(path string) Workspace { /* return interface */ }
```

**Files to modify**:
- `internal/workspace/workspace.go`

### 3. Add HTTP Client Interface (Priority: Medium)

**Problem**: `internal/http/client.go` uses concrete HTTP client.

**Solution**:
```go
// internal/http/client.go
type HTTPClient interface {
    Fetch(ctx context.Context, url string) ([]byte, error)
    FetchWithRetry(ctx context.Context, url string, maxRetries int) ([]byte, error)
}

type httpClient struct { /* implementation */ }

func NewHTTPClient(config Config) HTTPClient { /* return interface */ }
```

**Files to modify**:
- `internal/http/client.go`

### 4. Standardize GRC Registry (Priority: Low)

**Problem**: Registry uses factory functions instead of interface-based registration.

**Current pattern**:
```go
type providerFactory func(s storage.Backend, l *slog.Logger) GRCProvider
```

**Optional improvement**:
```go
type GRCProviderFactory interface {
    Create(s storage.Backend, l *slog.Logger) GRCProvider
}

// Then registry accepts factories
func (r *Registry) Register(name string, factory GRCProviderFactory)
```

**Files to modify**:
- `internal/grc/registry.go`

## Implementation Order

1. **Phase 1** (2-3 hours): Unify storage interfaces
2. **Phase 2** (1-2 hours): Extract Workspace interface
3. **Phase 3** (1-2 hours): Add HTTP Client interface
4. **Phase 4** (1 hour): Standardize GRC Registry (optional)

## Testing Strategy

- All interface changes must maintain backward compatibility
- Add interface-based unit tests
- Ensure enrichment-engine still compiles with `go.mod` replace directive

## Success Criteria

- [ ] Single `Backend` interface defined in `pkg/storage`
- [ ] All storage implementations implement the unified interface
- [ ] Workspace operations go through interface
- [ ] HTTP client operations go through interface
- [ ] All existing tests pass
- [ ] No regressions in enrichment-engine integration
