package cache_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
)

// TestMemoryCache_Interface tests that MemoryCache implements the Cache interface.
func TestMemoryCache_Interface(t *testing.T) {
	t.Parallel()

	// Verify MemoryCache implements Cache interface
	var _ cache.Cache = cache.NewMemoryCache()
}

// TestMemoryCache_BasicOperations tests the basic operations of MemoryCache.
func TestMemoryCache_BasicOperations(t *testing.T) {
	t.Parallel()

	c := cache.NewMemoryCache()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	t.Run("Set and Get", func(t *testing.T) {
		t.Parallel()
		key := "test-key"
		value := "test-value"

		// Set a value
		if err := c.SetWithTTL(key, value, 0); err != nil {
			t.Fatalf("SetWithTTL() error = %v", err)
		}

		// Get the value back
		got, err := c.Get(key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		t.Parallel()
		_, err := c.Get("non-existent-key")
		if !errors.Is(err, cache.ErrCacheMiss) {
			t.Errorf("Get() error = %v, want ErrCacheMiss", err)
		}
	})

	t.Run("Overwrite existing key", func(t *testing.T) {
		t.Parallel()
		key := "overwrite-key"
		value1 := "value1"
		value2 := "value2"

		// Set initial value
		if err := c.SetWithTTL(key, value1, 0); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		// Overwrite with new value
		if err := c.SetWithTTL(key, value2, 0); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		// Verify new value
		got, err := c.Get(key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value2 {
			t.Errorf("Get() = %v, want %v", got, value2)
		}
	})

	t.Run("Delete existing key", func(t *testing.T) {
		t.Parallel()
		key := "delete-key"
		value := "delete-value"

		// Set a value
		if err := c.SetWithTTL(key, value, 0); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		// Delete the value
		if err := c.Delete(key); err != nil {
			t.Fatalf("Delete() error = %v", err)
		}

		// Verify it's gone
		_, err := c.Get(key)
		if !errors.Is(err, cache.ErrCacheMiss) {
			t.Errorf("Get() after Delete() error = %v, want ErrCacheMiss", err)
		}
	})

	t.Run("Delete non-existent key", func(t *testing.T) {
		t.Parallel()
		// Should not return an error (matches map delete behavior)
		if err := c.Delete("non-existent-key"); err != nil {
			t.Errorf("Delete() error = %v, want nil", err)
		}
	})
}

// TestMemoryCache_EmptyValues tests the behavior of MemoryCache with empty values.
func TestMemoryCache_EmptyValues(t *testing.T) {
	t.Parallel()

	c := cache.NewMemoryCache()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	t.Run("Empty string value", func(t *testing.T) {
		t.Parallel()
		key := "empty-key"
		value := ""

		// Set empty value
		if err := c.SetWithTTL(key, value, 0); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		// Get empty value back
		got, err := c.Get(key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value {
			t.Errorf("Get() = %v, want empty string", got)
		}
	})

	t.Run("Empty key", func(t *testing.T) {
		t.Parallel()
		key := ""
		value := "some-value"

		// Set with empty key
		if err := c.SetWithTTL(key, value, 0); err != nil {
			t.Fatalf("Set() error = %v", err)
		}

		// Get with empty key
		got, err := c.Get(key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}
	})
}

// TestMemoryCache_ConcurrentAccess tests the concurrent access of MemoryCache.
func TestMemoryCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	c := cache.NewMemoryCache()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	const numGoroutines = 100
	const numOperations = 100

	var wg sync.WaitGroup

	// Concurrent writes
	t.Run("Concurrent writes", func(t *testing.T) {
		t.Parallel()
		wg.Add(numGoroutines)
		for i := range numGoroutines {
			go func(_ int) {
				defer wg.Done()
				for range numOperations {
					key := "key"
					value := "value"
					if err := c.SetWithTTL(key, value, 0); err != nil {
						t.Errorf("Set() error = %v", err)
					}
				}
			}(i)
		}
		wg.Wait()
	})

	// Concurrent reads and writes
	t.Run("Concurrent reads and writes", func(t *testing.T) {
		t.Parallel()
		// Pre-populate cache
		for range 10 {
			key := "concurrent-key"
			if err := c.SetWithTTL(key, "initial-value", 0); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
		}

		wg.Add(numGoroutines * 2)

		// Writers
		for i := range numGoroutines {
			go func(_ int) {
				defer wg.Done()
				for range numOperations {
					key := "concurrent-key"
					value := "value"
					if err := c.SetWithTTL(key, value, 0); err != nil {
						t.Errorf("Set() error = %v", err)
					}
				}
			}(i)
		}

		// Readers
		for i := range numGoroutines {
			go func(_ int) {
				defer wg.Done()
				for range numOperations {
					key := "concurrent-key"
					_, _ = c.Get(key) // Ignore errors as key might not exist
				}
			}(i)
		}

		wg.Wait()
	})

	// Concurrent deletes
	t.Run("Concurrent deletes", func(t *testing.T) {
		t.Parallel()
		// Pre-populate cache
		for range numGoroutines {
			key := "delete-key"
			if err := c.SetWithTTL(key, "value", 0); err != nil {
				t.Fatalf("Set() error = %v", err)
			}
		}

		wg.Add(numGoroutines)
		for i := range numGoroutines {
			go func(_ int) {
				defer wg.Done()
				key := "delete-key"
				if err := c.Delete(key); err != nil {
					t.Errorf("Delete() error = %v", err)
				}
			}(i)
		}
		wg.Wait()
	})
}

// TestMemoryCache_Close tests the closing of MemoryCache.
func TestMemoryCache_Close(t *testing.T) {
	t.Parallel()

	c := cache.NewMemoryCache()

	// Close should not return an error
	if err := c.Close(); err != nil {
		t.Errorf("Close() error = %v, want nil", err)
	}

	// Multiple closes should be safe
	if err := c.Close(); err != nil {
		t.Errorf("Second Close() error = %v, want nil", err)
	}
}

// TestMemoryCache_TTL tests TTL functionality of MemoryCache.
func TestMemoryCache_TTL(t *testing.T) {
	t.Parallel()

	c := cache.NewMemoryCache()
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	})

	t.Run("Entry with TTL expires", func(t *testing.T) {
		t.Parallel()
		key := "ttl-key"
		value := "ttl-value"

		// Set value with 50ms TTL
		if err := c.SetWithTTL(key, value, 50*time.Millisecond); err != nil {
			t.Fatalf("SetWithTTL() error = %v", err)
		}

		// Should be retrievable immediately
		got, err := c.Get(key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Should now return ErrCacheMiss
		_, err = c.Get(key)
		if !errors.Is(err, cache.ErrCacheMiss) {
			t.Errorf("Get() after TTL error = %v, want ErrCacheMiss", err)
		}
	})

	t.Run("Entry with zero TTL never expires", func(t *testing.T) {
		t.Parallel()
		key := "no-ttl-key"
		value := "no-ttl-value"

		// Set value with zero TTL (no expiration)
		if err := c.SetWithTTL(key, value, 0); err != nil {
			t.Fatalf("SetWithTTL() error = %v", err)
		}

		// Wait a bit
		time.Sleep(100 * time.Millisecond)

		// Should still be retrievable
		got, err := c.Get(key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}
	})

	t.Run("Entry with negative TTL never expires", func(t *testing.T) {
		t.Parallel()
		key := "negative-ttl-key"
		value := "negative-ttl-value"

		// Set value with negative TTL (treated as no expiration)
		if err := c.SetWithTTL(key, value, -1*time.Hour); err != nil {
			t.Fatalf("SetWithTTL() error = %v", err)
		}

		// Wait a bit
		time.Sleep(100 * time.Millisecond)

		// Should still be retrievable
		got, err := c.Get(key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}
	})

	t.Run("Overwrite extends TTL", func(t *testing.T) {
		t.Parallel()
		key := "overwrite-ttl-key"
		value1 := "value1"
		value2 := "value2"

		// Set value with short TTL
		if err := c.SetWithTTL(key, value1, 50*time.Millisecond); err != nil {
			t.Fatalf("SetWithTTL() error = %v", err)
		}

		// Immediately overwrite with longer TTL
		if err := c.SetWithTTL(key, value2, 1*time.Hour); err != nil {
			t.Fatalf("SetWithTTL() error = %v", err)
		}

		// Wait past first TTL
		time.Sleep(100 * time.Millisecond)

		// Should still be retrievable with new value
		got, err := c.Get(key)
		if err != nil {
			t.Fatalf("Get() error = %v", err)
		}
		if got != value2 {
			t.Errorf("Get() = %v, want %v", got, value2)
		}
	})
}
