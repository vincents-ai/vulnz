# Contributing to Vulnz

Thank you for your interest in contributing! This project provides vulnerability data libraries for EU CRA/NIS2 compliance tooling.

## Prerequisites

- **Go 1.25+** — [go.dev/dl](https://go.dev/dl/)
- **Nix** (optional) — reproducible builds via `nix develop`

## Building

```bash
go build ./...
```

## Testing

```bash
# Unit tests
go test ./...

# Behavioral tests (godog)
go test -tags behavioral -count=1 -timeout 10m ./test/behavioral/...

# Fuzz tests
go test -fuzz=Fuzz -fuzztime=30s ./internal/...
```

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add NVD 2026 feed parser
fix: correct CVE-ID validation regex
docs: update provider documentation
test: add fuzz test for version matching
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make changes and add tests
4. Ensure all tests pass
5. Commit with conventional commit format
6. Open a PR against `main`

## Code Style

- Follow [Effective Go](https://go.dev/doc/effective_go) guidelines
- Error messages should not start with a capital letter
- All functions that do I/O must accept `context.Context`
- Implement the `storage.Backend` interface for new storage backends

## License

By contributing, you agree that your contributions will be licensed under the AGPL-3.0 license.
