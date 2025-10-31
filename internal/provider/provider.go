package provider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
)

var (
	// ErrLicenseNotFound is returned when a license is not found.
	ErrLicenseNotFound = errors.New("license not found")
	// ErrInvalidResponse is returned when the API response is invalid.
	ErrInvalidResponse = errors.New("invalid API response")
)

// Provider is the interface that each enrichment provider must implement.
//
// This is the thing that will actually get the license for a package.
type Provider interface {
	// Get returns the license for a package.
	Get(ctx context.Context, purl string) (string, error)
}

// GetOptions are the options for getting the license for a package.
type GetOptions struct {
	// Purl is the purl of the package.
	Purl string
	// Provider is the provider to use for the information.
	Provider Provider
	// Cache is the cache to use for the information.
	Cache cache.Cache
	// CacheTTL is the time-to-live duration for the cache.
	CacheTTL time.Duration
}

// Get gets the license for a package from the provider or cache.
//
// This is basically a wrapper around the chosen provider with the cache.
func Get(ctx context.Context, opts GetOptions) (string, error) {
	// If we have a cache, try to get the license from it
	if opts.Cache != nil {
		license, err := opts.Cache.Get(opts.Purl)
		if err != nil && !errors.Is(err, cache.ErrCacheMiss) {
			return "", fmt.Errorf("failed to get license from cache: %w", err)
		}
		if err == nil {
			return license, nil
		}
	}

	// If we don't have a cache, or the license is not in the cache, get it from the service
	license, err := opts.Provider.Get(ctx, opts.Purl)
	if err != nil {
		return "", fmt.Errorf("failed to get license from provider: %w", err)
	}

	// If we have a license, add it to the cache with the TTL
	if license != "" && opts.Cache != nil {
		if setErr := opts.Cache.SetWithTTL(opts.Purl, license, opts.CacheTTL); setErr != nil {
			return "", fmt.Errorf("failed to set license in cache: %w", setErr)
		}
	}

	return license, nil
}
