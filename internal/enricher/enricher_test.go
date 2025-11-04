package enricher_test

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
)

// mockProvider implements the provider.Provider interface for testing.
type mockProvider struct {
	getLicense func(ctx context.Context, purl string) (string, error)
}

func (m *mockProvider) Get(ctx context.Context, purl string) (string, error) {
	if m.getLicense != nil {
		return m.getLicense(ctx, purl)
	}
	return "", nil
}

// mockCache implements the cache.Cache interface for testing.
type mockCache struct {
	getFunc        func(key string) (string, error)
	setWithTTLFunc func(key string, value string, ttl time.Duration) error
	deleteFunc     func(key string) error
	closeFunc      func() error
}

func (m *mockCache) Get(key string) (string, error) {
	if m.getFunc != nil {
		return m.getFunc(key)
	}
	return "", cache.ErrCacheMiss
}

func (m *mockCache) SetWithTTL(key string, value string, ttl time.Duration) error {
	if m.setWithTTLFunc != nil {
		return m.setWithTTLFunc(key, value, ttl)
	}
	return nil
}

func (m *mockCache) Delete(key string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(key)
	}
	return nil
}

func (m *mockCache) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

// newTestLogger creates a logger for tests that writes to stderr.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

// noopLogger creates a logger that discards all output.
func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.NewFile(0, os.DevNull), nil))
}
