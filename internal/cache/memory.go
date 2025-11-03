package cache

import (
	"sync"
	"time"
)

// cacheEntry represents a cached value with optional expiration.
type cacheEntry struct {
	value      string
	expiration time.Time // Zero value means no expiration
}

// isExpired returns true if the entry has expired.
func (e *cacheEntry) isExpired() bool {
	return !e.expiration.IsZero() && time.Now().After(e.expiration)
}

// MemoryCache is a cache that uses an in-memory map with TTL support.
type MemoryCache struct {
	mu     sync.RWMutex
	cache  map[string]*cacheEntry
	closed bool
}

var _ Cache = (*MemoryCache)(nil)

// NewMemoryCache creates a new MemoryCache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		cache: make(map[string]*cacheEntry),
	}
}

// Get retrieves a value from the cache.
// Returns ErrCacheMiss if the key is not found or has expired.
func (c *MemoryCache) Get(key string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", ErrCacheClosed
	}

	entry, ok := c.cache[key]
	if !ok || entry.isExpired() {
		return "", ErrCacheMiss
	}
	return entry.value, nil
}

// SetWithTTL stores a value in the cache with a time-to-live duration.
// If ttl is <= 0, the value never expires.
func (c *MemoryCache) SetWithTTL(key string, value string, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrCacheClosed
	}

	entry := &cacheEntry{
		value: value,
	}
	if ttl > 0 {
		entry.expiration = time.Now().Add(ttl)
	}
	c.cache[key] = entry
	return nil
}

// Delete removes a value from the cache.
// This operation is idempotent - deleting a non-existent key is not an error.
func (c *MemoryCache) Delete(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return ErrCacheClosed
	}

	delete(c.cache, key)
	return nil
}

// Close closes the cache and releases resources.
// This method is idempotent - calling Close multiple times is safe.
func (c *MemoryCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil // Already closed, idempotent
	}

	c.closed = true
	c.cache = nil
	return nil
}
