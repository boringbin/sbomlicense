package cache

import (
	"errors"
	"time"
)

var (
	// ErrCacheMiss is returned when a key is not found in the cache.
	// This is analogous to redis.Nil and should be checked using errors.Is().
	ErrCacheMiss = errors.New("cache miss")
	// ErrCacheClosed is returned when an operation is attempted on a closed cache.
	ErrCacheClosed = errors.New("cache is closed")
)

// Cache is the interface that each cache must implement.
type Cache interface {
	// Get retrieves a value from the cache.
	// Returns ErrCacheMiss if the key is not found.
	// Returns ErrCacheClosed if the cache has been closed.
	Get(key string) (string, error)

	// SetWithTTL stores a value in the cache with a time-to-live duration.
	// If ttl is <= 0, the value never expires.
	// Returns ErrCacheClosed if the cache has been closed.
	SetWithTTL(key string, value string, ttl time.Duration) error

	// Delete removes a value from the cache.
	// This operation is idempotent - deleting a non-existent key is not an error.
	// Returns ErrCacheClosed if the cache has been closed.
	Delete(key string) error

	// Close closes the cache and releases any associated resources.
	// This method is idempotent - calling Close multiple times is safe.
	// After Close is called, all other operations will return ErrCacheClosed.
	Close() error
}
