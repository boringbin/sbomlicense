package enricher

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/provider"
)

// enrichableItem represents an item that can be enriched with license information.
type enrichableItem interface {
	// GetPurl returns the package URL for license lookup.
	// Returns an error if the purl cannot be extracted.
	GetPurl() (string, error)

	// HasLicense returns true if the item already has license information.
	HasLicense() bool

	// SetLicense updates the item with the provided license string.
	SetLicense(license string)

	// GetLogID returns a unique identifier for logging purposes.
	GetLogID() string
}

// enrichDocument handles the common enrichment flow for any document type.
// It sets up parallelism, creates a logger if needed, enriches items in parallel,
// and marshals the result.
func enrichDocument[T enrichableItem, D any](
	ctx context.Context,
	opts Options,
	doc *D,
	items []T,
	prov provider.Provider,
	cacheInstance cache.Cache,
	cacheTTL time.Duration,
	marshalFn func(*D) ([]byte, error),
) ([]byte, error) {
	// No items to enrich, return original SBOM
	if len(items) == 0 {
		return opts.SBOM, nil
	}

	// Determine parallelism
	parallelism := opts.Parallelism
	if parallelism <= 0 {
		parallelism = 1
	}

	// Use provided logger or create a no-op logger
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Process items in parallel using generic worker function
	if err := processItemsParallel(
		ctx,
		items,
		parallelism,
		prov,
		cacheInstance,
		cacheTTL,
		logger,
	); err != nil {
		return nil, err
	}

	return marshalFn(doc)
}

// job represents a single enrichment task.
type job[T enrichableItem] struct {
	item T
	purl string
}

// processItemsParallel enriches items in parallel using a worker pool pattern.
// It distributes work across multiple goroutines, skips items that already have licenses,
// and logs errors without stopping processing.
func processItemsParallel[T enrichableItem](
	ctx context.Context,
	items []T,
	parallelism int,
	prov provider.Provider,
	cacheInstance cache.Cache,
	cacheTTL time.Duration,
	logger *slog.Logger,
) error {
	// Create buffered channel sized to all items to avoid blocking on send
	jobs := make(chan job[T], len(items))
	var wg sync.WaitGroup

	// Spawn worker goroutines
	for range parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Skip if item already has license
				if j.item.HasLicense() {
					continue
				}

				// Get license from provider (cache-through pattern)
				lic, licErr := provider.Get(ctx, provider.GetOptions{
					Purl:     j.purl,
					Provider: prov,
					Cache:    cacheInstance,
					CacheTTL: cacheTTL,
				})
				if licErr != nil {
					// Log error but continue processing other items
					logger.ErrorContext(ctx, "failed to get license for item",
						"purl", j.purl,
						"id", j.item.GetLogID(),
						"error", licErr)
					continue
				}

				// Update item if license was found
				if lic != "" {
					j.item.SetLicense(lic)
				}
			}
		}()
	}

	// Queue all items for processing
	for _, item := range items {
		purl, purlErr := item.GetPurl()
		if purlErr != nil {
			// Log error but continue processing other items
			logger.ErrorContext(ctx, "failed to get purl for item",
				"id", item.GetLogID(),
				"error", purlErr)
			continue
		}

		jobs <- job[T]{item: item, purl: purl}
	}

	// Signal no more jobs and wait for workers to finish
	close(jobs)
	wg.Wait()

	return nil
}
