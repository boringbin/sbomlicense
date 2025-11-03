package cache_test

import (
	"errors"
	"testing"

	"github.com/boringbin/sbomlicense/internal/cache"
)

// TestErrCacheMiss tests the ErrCacheMiss error.
func TestErrCacheMiss(t *testing.T) {
	t.Parallel()

	// Test that ErrCacheMiss is a sentinel error
	err := cache.ErrCacheMiss
	if err == nil {
		t.Fatal("ErrCacheMiss should not be nil")
	}

	// Test that ErrCacheMiss can be compared with errors.Is
	wrappedErr := errors.New("wrapped: cache miss")
	if errors.Is(wrappedErr, cache.ErrCacheMiss) {
		t.Error("errors.Is should not match unwrapped error")
	}

	// Test direct comparison
	if !errors.Is(cache.ErrCacheMiss, cache.ErrCacheMiss) {
		t.Error("errors.Is should match the same error")
	}
}
