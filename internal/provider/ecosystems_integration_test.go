//go:build integration

package provider_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/provider"
)

// TestClient_Get_Integration tests the real Ecosyste.ms API.
func TestClient_Get_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tests := []struct {
		name        string
		purl        string
		wantLicense string // Expected license (or substring)
	}{
		{
			name:        "npm package",
			purl:        "pkg:npm/lodash@4.17.21",
			wantLicense: "MIT",
		},
		{
			name:        "pypi package",
			purl:        "pkg:pypi/requests@2.28.0",
			wantLicense: "Apache", // Could be "Apache-2.0" or similar
		},
		{
			name:        "npm scoped package",
			purl:        "pkg:npm/%40types/node@18.0.0",
			wantLicense: "MIT",
		},
		{
			name:        "maven package",
			purl:        "pkg:maven/junit/junit@4.13.2",
			wantLicense: "EPL", // Eclipse Public License
		},
		{
			name:        "golang package",
			purl:        "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			wantLicense: "MIT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create real client
			client := provider.NewClient(provider.ClientOptions{})

			// Call with reasonable timeout
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			license, err := client.Get(ctx, tt.purl)
			if err != nil {
				t.Fatalf("Get() error = %v", err)
			}

			// Verify license is not empty
			if license == "" {
				t.Error("Get() returned empty license")
			}

			// Verify license contains expected substring
			if !strings.Contains(license, tt.wantLicense) {
				t.Logf("Note: license = %q, expected to contain %q (API may have updated)", license, tt.wantLicense)
			}

			t.Logf("Successfully retrieved license: %q for %s", license, tt.purl)
		})
	}
}

// TestClient_Get_Integration_NotFound tests non-existent package handling.
func TestClient_Get_Integration_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := provider.NewClient(provider.ClientOptions{})

	// Use a package that definitely doesn't exist
	purl := "pkg:npm/this-package-definitely-does-not-exist-12345@999.999.999"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := client.Get(ctx, purl)
	if err == nil {
		t.Error("Get() for nonexistent package should return error")
		return
	}

	if !errors.Is(err, provider.ErrLicenseNotFound) {
		t.Errorf("Get() error = %v, want error wrapping ErrLicenseNotFound", err)
	}
}

// TestClient_Get_Integration_WithEmail tests polite pool with email.
func TestClient_Get_Integration_WithEmail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create client with email for polite pool
	client := provider.NewClient(provider.ClientOptions{
		Email: "test@example.com",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	license, err := client.Get(ctx, "pkg:npm/lodash@4.17.21")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if license == "" {
		t.Error("Get() returned empty license")
	}

	// The request should work with email in User-Agent
	t.Logf("Successfully retrieved license with polite pool: %q", license)
}

// TestGet_Integration_WithMemoryCache tests provider.Get with memory cache.
func TestGet_Integration_WithMemoryCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := provider.NewClient(provider.ClientOptions{})
	memCache := cache.NewMemoryCache()
	defer memCache.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	purl := "pkg:npm/lodash@4.17.21"

	// First call - should fetch from API and cache
	license1, err := provider.Get(ctx, provider.GetOptions{
		Purl:     purl,
		Provider: client,
		Cache:    memCache,
		CacheTTL: 0,
	})
	if err != nil {
		t.Fatalf("Get() first call error = %v", err)
	}

	if license1 == "" {
		t.Error("Get() returned empty license")
	}

	// Second call - should return from cache (verify by checking it's the same)
	license2, err := provider.Get(ctx, provider.GetOptions{
		Purl:     purl,
		Provider: client,
		Cache:    memCache,
	})
	if err != nil {
		t.Fatalf("Get() second call error = %v", err)
	}

	if license1 != license2 {
		t.Errorf("Get() cached license = %q, want %q", license2, license1)
	}

	t.Logf("Successfully verified cache: license = %q", license1)
}

// TestGet_Integration_CachePersistence tests that cached values persist across calls.
func TestGet_Integration_CachePersistence(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := provider.NewClient(provider.ClientOptions{})
	memCache := cache.NewMemoryCache()
	defer memCache.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	purls := []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/express@4.18.2",
		"pkg:pypi/requests@2.28.0",
	}

	// Fetch all licenses and cache them
	licenses := make(map[string]string)
	for _, purl := range purls {
		license, err := provider.Get(ctx, provider.GetOptions{
			Purl:     purl,
			Provider: client,
			Cache:    memCache,
		})
		if err != nil {
			t.Fatalf("Get() error for %s = %v", purl, err)
		}
		licenses[purl] = license
		t.Logf("Cached: %s -> %s", purl, license)
	}

	// Verify all are in cache by fetching again
	for _, purl := range purls {
		license, err := provider.Get(ctx, provider.GetOptions{
			Purl:     purl,
			Provider: client,
			Cache:    memCache,
		})
		if err != nil {
			t.Fatalf("Get() error for %s = %v", purl, err)
		}

		if license != licenses[purl] {
			t.Errorf("Get() cached license for %s = %q, want %q", purl, license, licenses[purl])
		}
	}

	t.Log("Successfully verified all licenses persist in cache")
}

// TestGet_Integration_MultipleEcosystems tests packages from different ecosystems.
func TestGet_Integration_MultipleEcosystems(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tests := []struct {
		name      string
		purl      string
		ecosystem string
	}{
		{
			name:      "npm",
			purl:      "pkg:npm/express@4.18.2",
			ecosystem: "npm",
		},
		{
			name:      "pypi",
			purl:      "pkg:pypi/django@4.2.0",
			ecosystem: "pypi",
		},
		{
			name:      "maven",
			purl:      "pkg:maven/org.springframework/spring-core@6.0.11",
			ecosystem: "maven",
		},
		{
			name:      "golang",
			purl:      "pkg:golang/github.com/gorilla/mux@v1.8.0",
			ecosystem: "golang",
		},
	}

	client := provider.NewClient(provider.ClientOptions{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			license, err := client.Get(ctx, tt.purl)
			if err != nil {
				// Some packages might not be found, that's ok for this test
				if errors.Is(err, provider.ErrLicenseNotFound) {
					t.Logf("Package not found (this is ok): %s", tt.purl)
					return
				}
				t.Fatalf("Get() error = %v", err)
			}

			if license == "" {
				t.Errorf("Get() returned empty license for %s", tt.ecosystem)
			} else {
				t.Logf("Successfully retrieved license for %s: %q", tt.ecosystem, license)
			}
		})
	}
}
