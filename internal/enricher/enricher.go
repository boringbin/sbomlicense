package enricher

import (
	"context"
	"log/slog"
)

// Options are the options for enriching the SBOM with license information.
type Options struct {
	// SBOM is the SBOM file to enrich.
	SBOM []byte
	// Logger is the logger to use for logging.
	//
	// If nil, a no-op logger will be used.
	Logger *slog.Logger
	// Parallelism is the number of concurrent workers to use for enrichment.
	//
	// If <= 0, defaults to 1 (sequential processing).
	Parallelism int
}

// Enricher is the interface that each enrichment service must implement.
//
// This is the thing that will enrich the SBOM with information.
type Enricher interface {
	// Enrich enriches the SBOM with information.
	Enrich(ctx context.Context, opts Options) ([]byte, error)
}
