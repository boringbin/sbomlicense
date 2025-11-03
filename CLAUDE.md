# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Design Philosophy

This project follows a **minimal and simple** design philosophy. Two focused tools share code without duplication.

## Project Overview

sbomlicense is a toolkit for enriching Software Bill of Materials (SBOM) files with license information using the Ecosyste.ms API.

**Two Focused Tools:**
1. **`sbomlicense`** (CLI) - Local, one-off enrichment with in-memory caching
2. **`sbomlicensed`** (Daemon) - HTTP API for high-volume processing with persistent bbolt caching

**Core Purpose:** Enable SBOM enrichment for both local development (CLI) and production/CI scenarios (daemon) without code duplication through shared `internal/` packages.

**Shared Features:**
- Supports SPDX and CycloneDX formats (including GitHub-wrapped SBOMs)
- Parallel enrichment with configurable worker pools
- Ecosyste.ms API integration for license lookups

## CLI Usage

```bash
./bin/sbomlicense sbom.json                      # Basic usage
./bin/sbomlicense -parallel=20 sbom.json         # With parallelism
./bin/sbomlicense -v sbom.json                   # Verbose logging
./bin/sbomlicense -email=you@example.com sbom.json  # With email (optional for CLI)
```

**Output:** Enriched SBOM to stdout

## Daemon Usage

**Start daemon:**
```bash
# Via docker-compose (recommended)
docker compose up -d

# Or manually (requires email)
./bin/sbomlicensed -email=you@example.com -cache-path ./cache.db
```

**API Usage:**
```bash
# Health check
curl http://localhost:8080/health

# Enrich SBOM (handles large files)
jq -n --slurpfile sbom testdata/example-spdx.json '{sbom: $sbom[0]}' \
  | curl -X POST http://localhost:8080/enrich \
    -H "Content-Type: application/json" \
    -d @- \
  | jq '.sbom' > enriched.json
```

**IMPORTANT:** Email is REQUIRED for daemon mode (ecosyste.ms API polite pool access).

## Development Commands

```bash
# Build
make all                  # Build both CLI and daemon to bin/
make cli                  # Build CLI only
make daemon               # Build daemon only

# Test
make test                 # Unit tests (-short flag, race detection)
make test-integration     # Integration tests (-tags=integration)
make test-all             # All tests with race detection
make test-coverage        # Coverage report

# Quality
make check                # Run format-check and lint-check (CI validation)
make fix                  # Run format-fix and lint-fix
make vet                  # Run go vet

# Maintenance
make tidy                 # Run go mod tidy
make clean                # Remove bin/, coverage files
```

## Architecture

### Package Structure

```
sbomlicense/
├── cmd/
│   ├── sbomlicense/      # CLI entry point (memory cache)
│   └── sbomlicensed/     # Daemon entry point (bbolt cache, HTTP server)
└── internal/             # Shared packages (80% code reuse)
    ├── cache/            # Cache interface + implementations (memory, bbolt)
    ├── enricher/         # Core enrichment logic (SPDX, CycloneDX)
    ├── provider/         # Ecosyste.ms API client
    ├── sbom/             # Format detection
    ├── server/           # HTTP server for daemon
    └── version/          # Version info
```

### Key Types and Flow

**Enricher interface** (`internal/enricher/enricher.go`):
```go
type Enricher interface {
    Enrich(ctx context.Context, opts Options) ([]byte, error)
}
```

**Provider interface** (`internal/provider/provider.go`):
```go
type Provider interface {
    Get(ctx context.Context, purl string) (string, error)
}
```

**Cache interface** (`internal/cache/cache.go`):
```go
type Cache interface {
    Get(key string) (string, error)
    SetWithTTL(key string, value string, ttl time.Duration) error
    Delete(key string) error
    Close() error
}
```

**Enrichment flow:**
1. `sbom.DetectFormat()` - Auto-detect SPDX or CycloneDX
2. Select enricher (SPDX or CycloneDX) based on format
3. Enricher fetches licenses via provider with cache-through pattern
4. Return enriched SBOM JSON

### Architecture Philosophy

- **CLI:** Simple, zero-dependency, local enrichment (memory cache)
- **Daemon:** Production-ready, persistent enrichment (bbolt file cache, HTTP API)
- **Shared:** 80% code reuse via `internal/` packages (SBOM parsing, enrichment logic, API client)

**Why two binaries?**
- Each tool has a single, clear purpose (minimalism)
- No conditional complexity or feature flags (simplicity)
- Users install only what they need (low maintenance)
- Code reuse without duplication (robustness)

## Code Standards

**Linting:** Strict golangci-lint config (`.golangci.yaml`) based on Marat Reymers' "Golden config"

**Key rules:**
- **Line length:** Max 120 characters (golines formatter)
- **Function complexity:** Cyclomatic ≤30, Cognitive ≤20
- **Import organization:** Local imports (`github.com/boringbin/sbomlicense`) grouped after third-party
- **Forbidden packages:**
  - Use `log/slog` instead of `log` (except in main.go)
  - Use `math/rand/v2` instead of `math/rand`
- **Testing:** Tests use separate `_test` package, run with `-short` flag for unit tests

## Key Patterns

1. **Cache-through pattern:** Provider wrapped with cache in `provider.Get()`
2. **Format detection:** Auto-detect SPDX/CycloneDX with GitHub wrapper support
3. **Context propagation:** All processing functions accept `context.Context`
4. **Explicit logger parameters:** Pass `*slog.Logger` to functions
5. **Parallel processing:** Worker pools for concurrent license lookups

## Dependencies

**Shared:**
- Ecosyste.ms API (HTTP)
- Standard library (context, encoding/json, log/slog)

**Daemon only:**
- `go.etcd.io/bbolt` - Embedded key-value database for persistent caching (pure Go, no CGo)

**CLI:** No external dependencies (standard library only)

## Environment

- Go 1.25.0
- golangci-lint v2.5.0
