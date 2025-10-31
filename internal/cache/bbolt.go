package cache

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

const (
	// bucketName is the name of the bbolt bucket used for caching.
	bucketName = "licenses"
)

// bboltEntry represents a cached value with optional expiration stored in bbolt.
type bboltEntry struct {
	Value      string    `json:"value"`
	Expiration time.Time `json:"expiration,omitempty"` // Zero value means no expiration
}

// isExpired returns true if the entry has expired.
func (e *bboltEntry) isExpired() bool {
	return !e.Expiration.IsZero() && time.Now().After(e.Expiration)
}

// BboltCache is a cache that uses bbolt (embedded key-value store) with TTL support.
type BboltCache struct {
	db     *bbolt.DB
	mu     sync.RWMutex
	closed bool
}

var _ Cache = (*BboltCache)(nil)

// NewBboltCache creates a new BboltCache.
func NewBboltCache(db *bbolt.DB) (*BboltCache, error) {
	// Create bucket if it doesn't exist
	err := db.Update(func(tx *bbolt.Tx) error {
		_, createErr := tx.CreateBucketIfNotExists([]byte(bucketName))
		return createErr
	})
	if err != nil {
		return nil, err
	}

	return &BboltCache{
		db: db,
	}, nil
}

// Get retrieves a value from the cache.
// Returns ErrCacheMiss if the key is not found or has expired.
func (c *BboltCache) Get(key string) (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return "", ErrCacheClosed
	}

	var value string
	err := c.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return errors.New("bucket not found")
		}
		data := b.Get([]byte(key))
		if data == nil {
			return ErrCacheMiss
		}

		var entry bboltEntry
		if err := json.Unmarshal(data, &entry); err != nil {
			// Backward compatibility: treat as plain string value
			value = string(data)
			return nil //nolint:nilerr // Intentional: backward compatibility with non-TTL entries
		}

		if entry.isExpired() {
			return ErrCacheMiss
		}

		value = entry.Value
		return nil
	})
	if err != nil {
		return "", err
	}
	return value, nil
}

// SetWithTTL stores a value in the cache with a time-to-live duration.
// If ttl is <= 0, the value never expires.
func (c *BboltCache) SetWithTTL(key string, value string, ttl time.Duration) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return ErrCacheClosed
	}

	return c.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return errors.New("bucket not found")
		}

		entry := bboltEntry{
			Value: value,
		}
		if ttl > 0 {
			entry.Expiration = time.Now().Add(ttl)
		}

		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}

		return b.Put([]byte(key), data)
	})
}

// Delete removes a value from the cache.
// This operation is idempotent - deleting a non-existent key is not an error.
func (c *BboltCache) Delete(key string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return ErrCacheClosed
	}

	return c.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b == nil {
			return nil // Idempotent: if bucket doesn't exist, nothing to delete
		}
		return b.Delete([]byte(key))
	})
}

// Close closes the cache and the underlying database.
// This method is idempotent - calling Close multiple times is safe.
func (c *BboltCache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil // Already closed, idempotent
	}

	c.closed = true
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
