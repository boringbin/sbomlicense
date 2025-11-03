package cache_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.etcd.io/bbolt"

	"github.com/boringbin/sbomlicense/internal/cache"
)

// TestBboltCache_Interface tests that BboltCache implements the Cache interface.
func TestBboltCache_Interface(t *testing.T) {
	t.Parallel()

	db := createTempBboltDB(t)
	c, err := cache.NewBboltCache(db)
	if err != nil {
		t.Fatalf("NewBboltCache() error = %v", err)
	}
	defer func() {
		if closeErr := c.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	// Verify BboltCache implements Cache interface
	var _ cache.Cache = c
}

// TestBboltCache_BasicOperations tests the basic operations of BboltCache.
//
//nolint:tparallel // Subtests cannot be parallel as they share the same bbolt database instance
func TestBboltCache_BasicOperations(t *testing.T) {
	t.Parallel()

	db := createTempBboltDB(t)
	c, err := cache.NewBboltCache(db)
	if err != nil {
		t.Fatalf("NewBboltCache() error = %v", err)
	}
	defer func() {
		if closeErr := c.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	t.Run("Set and Get", func(t *testing.T) {
		key := "test-key"
		value := "test-value"

		// Set a value
		if setErr := c.SetWithTTL(key, value, 0); setErr != nil {
			t.Fatalf("Set() error = %v", setErr)
		}

		// Get the value back
		got, getErr := c.Get(key)
		if getErr != nil {
			t.Fatalf("Get() error = %v", getErr)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}
	})

	t.Run("Get non-existent key", func(t *testing.T) {
		_, getErr := c.Get("non-existent-key")
		if !errors.Is(getErr, cache.ErrCacheMiss) {
			t.Errorf("Get() error = %v, want ErrCacheMiss", getErr)
		}
	})

	t.Run("Overwrite existing key", func(t *testing.T) {
		key := "overwrite-key"
		value1 := "value1"
		value2 := "value2"

		// Set initial value
		if setErr := c.SetWithTTL(key, value1, 0); setErr != nil {
			t.Fatalf("Set() error = %v", setErr)
		}

		// Overwrite with new value
		if setErr := c.SetWithTTL(key, value2, 0); setErr != nil {
			t.Fatalf("Set() error = %v", setErr)
		}

		// Verify new value
		got, getErr := c.Get(key)
		if getErr != nil {
			t.Fatalf("Get() error = %v", getErr)
		}
		if got != value2 {
			t.Errorf("Get() = %v, want %v", got, value2)
		}
	})

	t.Run("Delete existing key", func(t *testing.T) {
		key := "delete-key"
		value := "delete-value"

		// Set a value
		if setErr := c.SetWithTTL(key, value, 0); setErr != nil {
			t.Fatalf("Set() error = %v", setErr)
		}

		// Delete the value
		if delErr := c.Delete(key); delErr != nil {
			t.Fatalf("Delete() error = %v", delErr)
		}

		// Verify it's gone
		_, getErr := c.Get(key)
		if !errors.Is(getErr, cache.ErrCacheMiss) {
			t.Errorf("Get() after Delete() error = %v, want ErrCacheMiss", getErr)
		}
	})

	t.Run("Delete non-existent key", func(t *testing.T) {
		// Should not return an error (bbolt Delete returns nil for non-existent keys)
		if delErr := c.Delete("non-existent-key"); delErr != nil {
			t.Errorf("Delete() error = %v, want nil", delErr)
		}
	})
}

// TestBboltCache_EmptyValues tests the behavior of BboltCache with empty values.
//
//nolint:tparallel // Subtests cannot be parallel as they share the same bbolt database instance
func TestBboltCache_EmptyValues(t *testing.T) {
	t.Parallel()

	db := createTempBboltDB(t)
	c, err := cache.NewBboltCache(db)
	if err != nil {
		t.Fatalf("NewBboltCache() error = %v", err)
	}
	defer func() {
		if closeErr := c.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	t.Run("Empty string value", func(t *testing.T) {
		key := "empty-key"
		value := ""

		// Set empty value
		if setErr := c.SetWithTTL(key, value, 0); setErr != nil {
			t.Fatalf("Set() error = %v", setErr)
		}

		// Get empty value back
		got, getErr := c.Get(key)
		if getErr != nil {
			t.Fatalf("Get() error = %v", getErr)
		}
		if got != value {
			t.Errorf("Get() = %v, want empty string", got)
		}
	})

	t.Run("Empty key", func(t *testing.T) {
		key := ""
		value := "some-value"

		// Set with empty key should fail (bbolt requirement)
		setErr := c.SetWithTTL(key, value, 0)
		if setErr == nil {
			t.Error("Set() with empty key error = nil, want error")
		}
	})
}

// TestBboltCache_Persistence tests the persistence of BboltCache.
func TestBboltCache_Persistence(t *testing.T) {
	t.Parallel()

	// Create temp database file
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test-persist.db")

	// First cache instance
	db1, err := bbolt.Open(dbPath, 0o600, nil)
	if err != nil {
		t.Fatalf("bbolt.Open() error = %v", err)
	}

	c1, err := cache.NewBboltCache(db1)
	if err != nil {
		t.Fatalf("NewBboltCache() error = %v", err)
	}

	// Write data
	key := "persist-key"
	value := "persist-value"
	if setErr := c1.SetWithTTL(key, value, 0); setErr != nil {
		t.Fatalf("Set() error = %v", setErr)
	}

	// Close first instance
	if closeErr := c1.Close(); closeErr != nil {
		t.Fatalf("Close() error = %v", closeErr)
	}

	// Open second cache instance with same file
	db2, err := bbolt.Open(dbPath, 0o600, nil)
	if err != nil {
		t.Fatalf("bbolt.Open() second time error = %v", err)
	}

	c2, err := cache.NewBboltCache(db2)
	if err != nil {
		t.Fatalf("NewBboltCache() second time error = %v", err)
	}
	defer func() {
		if closeErr := c2.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	// Read data from second instance
	got, err := c2.Get(key)
	if err != nil {
		t.Fatalf("Get() from second instance error = %v", err)
	}
	if got != value {
		t.Errorf("Get() from second instance = %v, want %v", got, value)
	}
}

// TestBboltCache_Close tests the closing of BboltCache.
func TestBboltCache_Close(t *testing.T) {
	t.Parallel()

	db := createTempBboltDB(t)
	c, err := cache.NewBboltCache(db)
	if err != nil {
		t.Fatalf("NewBboltCache() error = %v", err)
	}

	// Close should not return an error
	if closeErr := c.Close(); closeErr != nil {
		t.Errorf("Close() error = %v, want nil", closeErr)
	}
}

// TestBboltCache_MultipleKeys tests the multiple keys of BboltCache.
func TestBboltCache_MultipleKeys(t *testing.T) {
	t.Parallel()

	db := createTempBboltDB(t)
	c, err := cache.NewBboltCache(db)
	if err != nil {
		t.Fatalf("NewBboltCache() error = %v", err)
	}
	defer func() {
		if closeErr := c.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	}()

	// Set multiple keys
	keys := []string{"key1", "key2", "key3", "key4", "key5"}
	for i, key := range keys {
		value := "value" + string(rune('1'+i))
		if setErr := c.SetWithTTL(key, value, 0); setErr != nil {
			t.Fatalf("Set(%v) error = %v", key, setErr)
		}
	}

	// Verify all keys
	for i, key := range keys {
		expectedValue := "value" + string(rune('1'+i))
		got, getErr := c.Get(key)
		if getErr != nil {
			t.Fatalf("Get(%v) error = %v", key, getErr)
		}
		if got != expectedValue {
			t.Errorf("Get(%v) = %v, want %v", key, got, expectedValue)
		}
	}

	// Delete one key
	if delErr := c.Delete("key3"); delErr != nil {
		t.Fatalf("Delete(key3) error = %v", delErr)
	}

	// Verify deleted key is gone
	_, getErr := c.Get("key3")
	if !errors.Is(getErr, cache.ErrCacheMiss) {
		t.Errorf("Get(key3) after Delete() error = %v, want ErrCacheMiss", getErr)
	}

	// Verify other keys still exist
	for _, key := range []string{"key1", "key2", "key4", "key5"} {
		if _, verifyErr := c.Get(key); verifyErr != nil {
			t.Errorf("Get(%v) after Delete(key3) error = %v, want nil", key, verifyErr)
		}
	}
}

// TestBboltCache_TTL tests TTL functionality of BboltCache.
func TestBboltCache_TTL(t *testing.T) {
	// Cannot use t.Parallel() because db is shared resource

	db := createTempBboltDB(t)
	c, err := cache.NewBboltCache(db)
	if err != nil {
		t.Fatalf("NewBboltCache() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := c.Close(); closeErr != nil {
			t.Errorf("Close() error = %v", closeErr)
		}
	})

	t.Run("Entry with TTL expires", func(t *testing.T) {
		key := "ttl-key"
		value := "ttl-value"

		// Set value with 50ms TTL
		if setErr := c.SetWithTTL(key, value, 50*time.Millisecond); setErr != nil {
			t.Fatalf("SetWithTTL() error = %v", setErr)
		}

		// Should be retrievable immediately
		got, getErr := c.Get(key)
		if getErr != nil {
			t.Fatalf("Get() error = %v", getErr)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Should now return ErrCacheMiss
		_, getErr = c.Get(key)
		if !errors.Is(getErr, cache.ErrCacheMiss) {
			t.Errorf("Get() after TTL error = %v, want ErrCacheMiss", getErr)
		}
	})

	t.Run("Entry with zero TTL never expires", func(t *testing.T) {
		key := "no-ttl-key"
		value := "no-ttl-value"

		// Set value with zero TTL (no expiration)
		if setErr := c.SetWithTTL(key, value, 0); setErr != nil {
			t.Fatalf("SetWithTTL() error = %v", setErr)
		}

		// Wait a bit
		time.Sleep(100 * time.Millisecond)

		// Should still be retrievable
		got, getErr := c.Get(key)
		if getErr != nil {
			t.Fatalf("Get() error = %v", getErr)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}
	})

	t.Run("Entry with negative TTL never expires", func(t *testing.T) {
		key := "negative-ttl-key"
		value := "negative-ttl-value"

		// Set value with negative TTL (treated as no expiration)
		if setErr := c.SetWithTTL(key, value, -1*time.Hour); setErr != nil {
			t.Fatalf("SetWithTTL() error = %v", setErr)
		}

		// Wait a bit
		time.Sleep(100 * time.Millisecond)

		// Should still be retrievable
		got, getErr := c.Get(key)
		if getErr != nil {
			t.Fatalf("Get() error = %v", getErr)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}
	})

	t.Run("Persistence of TTL across cache reopens", func(t *testing.T) {
		// Create a dedicated db for this test
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "persist-test.db")

		db1, openErr := bbolt.Open(dbPath, 0o600, nil)
		if openErr != nil {
			t.Fatalf("bbolt.Open() error = %v", openErr)
		}

		c1, newErr := cache.NewBboltCache(db1)
		if newErr != nil {
			t.Fatalf("NewBboltCache() error = %v", newErr)
		}

		key := "persist-ttl-key"
		value := "persist-ttl-value"

		// Set value with 1 hour TTL
		if setErr := c1.SetWithTTL(key, value, 1*time.Hour); setErr != nil {
			t.Fatalf("SetWithTTL() error = %v", setErr)
		}

		// Close cache and db
		if closeErr := c1.Close(); closeErr != nil {
			t.Fatalf("Close() error = %v", closeErr)
		}

		// Reopen db and cache
		db2, openErr := bbolt.Open(dbPath, 0o600, nil)
		if openErr != nil {
			t.Fatalf("bbolt.Open() second time error = %v", openErr)
		}
		defer db2.Close()

		c2, newErr := cache.NewBboltCache(db2)
		if newErr != nil {
			t.Fatalf("NewBboltCache() second time error = %v", newErr)
		}
		defer c2.Close()

		// Should still be retrievable after reopen
		got, getErr := c2.Get(key)
		if getErr != nil {
			t.Fatalf("Get() after reopen error = %v", getErr)
		}
		if got != value {
			t.Errorf("Get() = %v, want %v", got, value)
		}
	})

	t.Run("Overwrite extends TTL", func(t *testing.T) {
		key := "overwrite-ttl-key"
		value1 := "value1"
		value2 := "value2"

		// Set value with short TTL
		if setErr := c.SetWithTTL(key, value1, 50*time.Millisecond); setErr != nil {
			t.Fatalf("SetWithTTL() error = %v", setErr)
		}

		// Immediately overwrite with longer TTL
		if setErr := c.SetWithTTL(key, value2, 1*time.Hour); setErr != nil {
			t.Fatalf("SetWithTTL() error = %v", setErr)
		}

		// Wait past first TTL
		time.Sleep(100 * time.Millisecond)

		// Should still be retrievable with new value
		got, getErr := c.Get(key)
		if getErr != nil {
			t.Fatalf("Get() error = %v", getErr)
		}
		if got != value2 {
			t.Errorf("Get() = %v, want %v", got, value2)
		}
	})
}

// createTempBboltDB creates a temporary bbolt database for testing.
func createTempBboltDB(t *testing.T) *bbolt.DB {
	t.Helper()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")

	db, err := bbolt.Open(dbPath, 0o600, nil)
	if err != nil {
		t.Fatalf("bbolt.Open() error = %v", err)
	}

	// Clean up on test completion
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			// Only log, don't fail, as test may have already closed it
			t.Logf("Cleanup: db.Close() error = %v", closeErr)
		}
		if removeErr := os.Remove(dbPath); removeErr != nil && !os.IsNotExist(removeErr) {
			t.Logf("Cleanup: os.Remove() error = %v", removeErr)
		}
	})

	return db
}
