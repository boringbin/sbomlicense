package provider_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/provider"
)

// TestNewClient tests the NewClient constructor.
func TestNewClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		opts            provider.ClientOptions
		wantBaseURL     string
		wantEmail       string
		checkHTTPClient bool
		wantTimeout     time.Duration
	}{
		{
			name:            "default options",
			opts:            provider.ClientOptions{},
			wantBaseURL:     "https://packages.ecosyste.ms",
			wantEmail:       "",
			checkHTTPClient: true,
			wantTimeout:     30 * time.Second,
		},
		{
			name: "custom base URL",
			opts: provider.ClientOptions{
				BaseURL: "https://example.com",
			},
			wantBaseURL: "https://example.com",
			wantEmail:   "",
		},
		{
			name: "with email",
			opts: provider.ClientOptions{
				Email: "test@example.com",
			},
			wantBaseURL: "https://packages.ecosyste.ms",
			wantEmail:   "test@example.com",
		},
		{
			name: "custom HTTP client",
			opts: provider.ClientOptions{
				Client: &http.Client{Timeout: 5 * time.Second},
			},
			wantBaseURL:     "https://packages.ecosyste.ms",
			wantEmail:       "",
			checkHTTPClient: false, // Don't check timeout, provided client takes precedence
		},
		{
			name: "all custom options",
			opts: provider.ClientOptions{
				BaseURL: "https://custom.example.com",
				Email:   "custom@example.com",
				Client:  &http.Client{Timeout: 10 * time.Second},
			},
			wantBaseURL:     "https://custom.example.com",
			wantEmail:       "custom@example.com",
			checkHTTPClient: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := provider.NewClient(tt.opts)

			// We can't directly access private fields, so we'll test behavior instead
			// by making a request to a test server and checking the URL and headers

			// Create a test server to verify the client behavior
			requestReceived := false
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestReceived = true

				// Check base URL is used by verifying the request was received
				// The actual baseURL check will be done in the Get tests

				// Check email in User-Agent
				userAgent := r.Header.Get("User-Agent")
				if tt.wantEmail != "" {
					expectedUA := fmt.Sprintf("sbomlicense/dev (mailto:%s)", tt.wantEmail)
					if userAgent != expectedUA {
						t.Errorf("User-Agent = %q, want %q", userAgent, expectedUA)
					}
				} else {
					expectedUA := "sbomlicense/dev"
					if userAgent != expectedUA {
						t.Errorf("User-Agent = %q, want %q", userAgent, expectedUA)
					}
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"normalized_licenses": ["MIT"]}]`))
			}))
			t.Cleanup(server.Close)

			// Override baseURL for this test
			if tt.opts.BaseURL == "" || strings.HasPrefix(tt.opts.BaseURL, "https://packages.ecosyste.ms") ||
				strings.HasPrefix(tt.opts.BaseURL, "https://example.com") ||
				strings.HasPrefix(tt.opts.BaseURL, "https://custom.example.com") {
				// Create a new client with the test server URL
				testOpts := tt.opts
				testOpts.BaseURL = server.URL
				client = provider.NewClient(testOpts)
			}

			// Make a request to verify the client works
			ctx := context.Background()
			_, err := client.Get(ctx, "pkg:npm/test@1.0.0")
			if err != nil {
				t.Errorf("Get() unexpected error = %v", err)
			}

			if !requestReceived {
				t.Error("Request was not received by test server")
			}
		})
	}
}

// TestClient_Get_Success tests successful Get requests.
func TestClient_Get_Success(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		mockResponse string
		purl         string
		want         string
	}{
		{
			name:         "single license",
			mockResponse: `[{"normalized_licenses": ["MIT"]}]`,
			purl:         "pkg:npm/lodash@4.17.21",
			want:         "MIT",
		},
		{
			name:         "multiple licenses returns first",
			mockResponse: `[{"normalized_licenses": ["Apache-2.0", "MIT"]}]`,
			purl:         "pkg:pypi/requests@2.28.0",
			want:         "Apache-2.0",
		},
		{
			name:         "multiple results returns first license of first result",
			mockResponse: `[{"normalized_licenses": ["BSD-3-Clause"]}, {"normalized_licenses": ["MIT"]}]`,
			purl:         "pkg:npm/test@1.0.0",
			want:         "BSD-3-Clause",
		},
		{
			name:         "complex license expression",
			mockResponse: `[{"normalized_licenses": ["MIT OR Apache-2.0"]}]`,
			purl:         "pkg:npm/test@1.0.0",
			want:         "MIT OR Apache-2.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify request method
				if r.Method != http.MethodGet {
					t.Errorf("expected GET request, got %s", r.Method)
				}

				// Verify purl query parameter
				if r.URL.Query().Get("purl") == "" {
					t.Error("expected purl query parameter")
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.mockResponse))
			}))
			t.Cleanup(server.Close)

			client := provider.NewClient(provider.ClientOptions{
				BaseURL: server.URL,
			})

			ctx := context.Background()
			got, err := client.Get(ctx, tt.purl)
			if err != nil {
				t.Errorf("Get() unexpected error = %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("Get() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestClient_Get_UserAgent tests User-Agent header.
func TestClient_Get_UserAgent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		email         string
		wantUserAgent string
	}{
		{
			name:          "without email",
			email:         "",
			wantUserAgent: "sbomlicense/dev",
		},
		{
			name:          "with email",
			email:         "test@example.com",
			wantUserAgent: "sbomlicense/dev (mailto:test@example.com)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				userAgent := r.Header.Get("User-Agent")
				if userAgent != tt.wantUserAgent {
					t.Errorf("User-Agent = %q, want %q", userAgent, tt.wantUserAgent)
				}

				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[{"normalized_licenses": ["MIT"]}]`))
			}))
			t.Cleanup(server.Close)

			client := provider.NewClient(provider.ClientOptions{
				BaseURL: server.URL,
				Email:   tt.email,
			})

			ctx := context.Background()
			_, err := client.Get(ctx, "pkg:npm/test@1.0.0")
			if err != nil {
				t.Errorf("Get() unexpected error = %v", err)
			}
		})
	}
}

// TestClient_Get_URLEncoding tests that purl is properly URL-encoded.
func TestClient_Get_URLEncoding(t *testing.T) {
	t.Parallel()

	purl := "pkg:npm/@types/node@18.0.0"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queryPurl := r.URL.Query().Get("purl")
		if queryPurl != purl {
			t.Errorf("purl query parameter = %q, want %q", queryPurl, purl)
		}

		// Verify the raw query string has encoded characters
		if !strings.Contains(r.URL.RawQuery, "%40") {
			t.Error("expected URL-encoded @ character (%40) in query string")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"normalized_licenses": ["MIT"]}]`))
	}))
	t.Cleanup(server.Close)

	client := provider.NewClient(provider.ClientOptions{
		BaseURL: server.URL,
	})

	ctx := context.Background()
	_, err := client.Get(ctx, purl)
	if err != nil {
		t.Errorf("Get() unexpected error = %v", err)
	}
}

// TestClient_Get_HTTPErrors tests various HTTP error responses.
func TestClient_Get_HTTPErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		statusCode      int
		mockResponse    string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:         "404 not found",
			statusCode:   http.StatusNotFound,
			mockResponse: `{"error": "not found"}`,
			wantErr:      true,
			wantErrIs:    provider.ErrLicenseNotFound,
		},
		{
			name:            "429 rate limited",
			statusCode:      http.StatusTooManyRequests,
			mockResponse:    `{"error": "too many requests"}`,
			wantErr:         true,
			wantErrContains: "rate limited",
		},
		{
			name:            "502 bad gateway",
			statusCode:      http.StatusBadGateway,
			mockResponse:    `{"error": "bad gateway"}`,
			wantErr:         true,
			wantErrContains: "service unavailable",
		},
		{
			name:            "503 service unavailable",
			statusCode:      http.StatusServiceUnavailable,
			mockResponse:    `{"error": "service unavailable"}`,
			wantErr:         true,
			wantErrContains: "service unavailable",
		},
		{
			name:            "504 gateway timeout",
			statusCode:      http.StatusGatewayTimeout,
			mockResponse:    `{"error": "gateway timeout"}`,
			wantErr:         true,
			wantErrContains: "service unavailable",
		},
		{
			name:            "500 internal server error",
			statusCode:      http.StatusInternalServerError,
			mockResponse:    `{"error": "internal server error"}`,
			wantErr:         true,
			wantErrContains: "API error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.mockResponse))
			}))
			t.Cleanup(server.Close)

			client := provider.NewClient(provider.ClientOptions{
				BaseURL: server.URL,
			})

			ctx := context.Background()
			_, err := client.Get(ctx, "pkg:npm/test@1.0.0")

			if !tt.wantErr {
				if err != nil {
					t.Errorf("Get() unexpected error = %v", err)
				}
				return
			}

			if err == nil {
				t.Error("Get() expected error, got nil")
				return
			}

			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Errorf("Get() error = %v, want error wrapping %v", err, tt.wantErrIs)
				}
			}

			if tt.wantErrContains != "" {
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("Get() error = %q, want error containing %q", err.Error(), tt.wantErrContains)
				}
			}
		})
	}
}

// TestClient_Get_ResponseErrors tests invalid response handling.
func TestClient_Get_ResponseErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		mockResponse    string
		wantErr         bool
		wantErrIs       error
		wantErrContains string
	}{
		{
			name:         "empty array",
			mockResponse: `[]`,
			wantErr:      true,
			wantErrIs:    provider.ErrLicenseNotFound,
		},
		{
			name:         "empty licenses array",
			mockResponse: `[{"normalized_licenses": []}]`,
			wantErr:      true,
			wantErrIs:    provider.ErrLicenseNotFound,
		},
		{
			name:         "malformed JSON",
			mockResponse: `[{invalid json}]`,
			wantErr:      true,
			wantErrIs:    provider.ErrInvalidResponse,
		},
		{
			name:         "not an array",
			mockResponse: `{"name": "test"}`,
			wantErr:      true,
			wantErrIs:    provider.ErrInvalidResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(tt.mockResponse))
			}))
			t.Cleanup(server.Close)

			client := provider.NewClient(provider.ClientOptions{
				BaseURL: server.URL,
			})

			ctx := context.Background()
			_, err := client.Get(ctx, "pkg:npm/test@1.0.0")

			if !tt.wantErr {
				if err != nil {
					t.Errorf("Get() unexpected error = %v", err)
				}
				return
			}

			if err == nil {
				t.Error("Get() expected error, got nil")
				return
			}

			if tt.wantErrIs != nil {
				if !errors.Is(err, tt.wantErrIs) {
					t.Errorf("Get() error = %v, want error wrapping %v", err, tt.wantErrIs)
				}
			}

			if tt.wantErrContains != "" {
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("Get() error = %q, want error containing %q", err.Error(), tt.wantErrContains)
				}
			}
		})
	}
}

// TestClient_Get_ContextCancellation tests context cancellation handling.
func TestClient_Get_ContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"normalized_licenses": ["MIT"]}]`))
	}))
	t.Cleanup(server.Close)

	client := provider.NewClient(provider.ClientOptions{
		BaseURL: server.URL,
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := client.Get(ctx, "pkg:npm/test@1.0.0")
	if err == nil {
		t.Error("Get() with cancelled context should return error")
	}
}

// TestClient_Get_Timeout tests timeout handling.
func TestClient_Get_Timeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"normalized_licenses": ["MIT"]}]`))
	}))
	t.Cleanup(server.Close)

	client := provider.NewClient(provider.ClientOptions{
		BaseURL: server.URL,
		Client:  &http.Client{Timeout: 50 * time.Millisecond},
	})

	ctx := context.Background()
	_, err := client.Get(ctx, "pkg:npm/test@1.0.0")
	if err == nil {
		t.Error("Get() with timeout should return error")
	}
}

// mockCache is a mock implementation of cache.Cache for testing.
type mockCache struct {
	data     map[string]string
	getErr   error
	setErr   error
	getCalls int
	setCalls int
}

func newMockCache() *mockCache {
	return &mockCache{
		data: make(map[string]string),
	}
}

func (m *mockCache) Get(key string) (string, error) {
	m.getCalls++
	if m.getErr != nil {
		return "", m.getErr
	}
	value, ok := m.data[key]
	if !ok {
		return "", cache.ErrCacheMiss
	}
	return value, nil
}

func (m *mockCache) SetWithTTL(key, value string, _ time.Duration) error {
	m.setCalls++
	if m.setErr != nil {
		return m.setErr
	}
	m.data[key] = value
	return nil
}

func (m *mockCache) Delete(key string) error {
	delete(m.data, key)
	return nil
}

func (m *mockCache) Close() error {
	return nil
}

// mockProvider is a mock implementation of provider.Provider for testing.
type mockProvider struct {
	license  string
	err      error
	getCalls int
}

func (m *mockProvider) Get(_ context.Context, _ string) (string, error) {
	m.getCalls++
	if m.err != nil {
		return "", m.err
	}
	return m.license, nil
}

// TestGet_CacheHit tests that cached values are returned without calling provider.
func TestGet_CacheHit(t *testing.T) {
	t.Parallel()

	mockCache := newMockCache()
	mockCache.data["pkg:npm/test@1.0.0"] = "MIT"

	mockProv := &mockProvider{
		license: "Apache-2.0", // Different from cache
	}

	ctx := context.Background()
	license, err := provider.Get(ctx, provider.GetOptions{
		Purl:     "pkg:npm/test@1.0.0",
		Provider: mockProv,
		Cache:    mockCache,
		CacheTTL: 0,
	})

	if err != nil {
		t.Errorf("Get() unexpected error = %v", err)
	}

	if license != "MIT" {
		t.Errorf("Get() = %q, want %q (from cache)", license, "MIT")
	}

	if mockProv.getCalls != 0 {
		t.Errorf("Provider.Get() called %d times, want 0 (should use cache)", mockProv.getCalls)
	}

	if mockCache.getCalls != 1 {
		t.Errorf("Cache.Get() called %d times, want 1", mockCache.getCalls)
	}
}

// TestGet_CacheMiss tests that provider is called on cache miss and result is cached.
func TestGet_CacheMiss(t *testing.T) {
	t.Parallel()

	mockCache := newMockCache()
	mockProv := &mockProvider{
		license: "Apache-2.0",
	}

	ctx := context.Background()
	license, err := provider.Get(ctx, provider.GetOptions{
		Purl:     "pkg:npm/test@1.0.0",
		Provider: mockProv,
		Cache:    mockCache,
		CacheTTL: time.Hour,
	})

	if err != nil {
		t.Errorf("Get() unexpected error = %v", err)
	}

	if license != "Apache-2.0" {
		t.Errorf("Get() = %q, want %q", license, "Apache-2.0")
	}

	if mockProv.getCalls != 1 {
		t.Errorf("Provider.Get() called %d times, want 1", mockProv.getCalls)
	}

	if mockCache.setCalls != 1 {
		t.Errorf("Cache.Set() called %d times, want 1", mockCache.setCalls)
	}

	// Verify it was cached
	cachedValue, ok := mockCache.data["pkg:npm/test@1.0.0"]
	if !ok {
		t.Error("license was not cached")
	}
	if cachedValue != "Apache-2.0" {
		t.Errorf("cached value = %q, want %q", cachedValue, "Apache-2.0")
	}
}

// TestGet_CacheDisabled tests that Get works when cache is nil.
func TestGet_CacheDisabled(t *testing.T) {
	t.Parallel()

	mockProv := &mockProvider{
		license: "MIT",
	}

	ctx := context.Background()
	license, err := provider.Get(ctx, provider.GetOptions{
		Purl:     "pkg:npm/test@1.0.0",
		Provider: mockProv,
		Cache:    nil, // No cache
		CacheTTL: 0,
	})

	if err != nil {
		t.Errorf("Get() unexpected error = %v", err)
	}

	if license != "MIT" {
		t.Errorf("Get() = %q, want %q", license, "MIT")
	}

	if mockProv.getCalls != 1 {
		t.Errorf("Provider.Get() called %d times, want 1", mockProv.getCalls)
	}
}

// TestGet_CacheGetError tests handling of cache.Get errors (non-ErrCacheMiss).
func TestGet_CacheGetError(t *testing.T) {
	t.Parallel()

	mockCache := newMockCache()
	mockCache.getErr = errors.New("cache get error")

	mockProv := &mockProvider{
		license: "MIT",
	}

	ctx := context.Background()
	_, err := provider.Get(ctx, provider.GetOptions{
		Purl:     "pkg:npm/test@1.0.0",
		Provider: mockProv,
		Cache:    mockCache,
		CacheTTL: 0,
	})

	if err == nil {
		t.Error("Get() expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "failed to get license from cache") {
		t.Errorf("Get() error = %q, want error containing %q", err.Error(), "failed to get license from cache")
	}

	// Provider should not be called if cache.Get returns non-ErrCacheMiss error
	if mockProv.getCalls != 0 {
		t.Errorf("Provider.Get() called %d times, want 0 (cache error should stop execution)", mockProv.getCalls)
	}
}

// TestGet_CacheSetError tests handling of cache.Set errors.
func TestGet_CacheSetError(t *testing.T) {
	t.Parallel()

	mockCache := newMockCache()
	mockCache.setErr = errors.New("cache set error")

	mockProv := &mockProvider{
		license: "MIT",
	}

	ctx := context.Background()
	_, err := provider.Get(ctx, provider.GetOptions{
		Purl:     "pkg:npm/test@1.0.0",
		Provider: mockProv,
		Cache:    mockCache,
		CacheTTL: 0,
	})

	if err == nil {
		t.Error("Get() expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "failed to set license in cache") {
		t.Errorf("Get() error = %q, want error containing %q", err.Error(), "failed to set license in cache")
	}

	// Provider should be called even though cache.Set will fail
	if mockProv.getCalls != 1 {
		t.Errorf("Provider.Get() called %d times, want 1", mockProv.getCalls)
	}
}

// TestGet_ProviderError tests that provider errors are propagated.
func TestGet_ProviderError(t *testing.T) {
	t.Parallel()

	mockCache := newMockCache()
	mockProv := &mockProvider{
		err: provider.ErrLicenseNotFound,
	}

	ctx := context.Background()
	_, err := provider.Get(ctx, provider.GetOptions{
		Purl:     "pkg:npm/test@1.0.0",
		Provider: mockProv,
		Cache:    mockCache,
		CacheTTL: 0,
	})

	if err == nil {
		t.Error("Get() expected error, got nil")
		return
	}

	if !strings.Contains(err.Error(), "failed to get license from provider") {
		t.Errorf("Get() error = %q, want error containing %q", err.Error(), "failed to get license from provider")
	}

	// Verify the original error is wrapped
	if !errors.Is(err, provider.ErrLicenseNotFound) {
		t.Errorf("Get() error should wrap ErrLicenseNotFound")
	}
}

// TestGet_EmptyLicenseNotCached tests that empty licenses are not cached.
func TestGet_EmptyLicenseNotCached(t *testing.T) {
	t.Parallel()

	mockCache := newMockCache()
	mockProv := &mockProvider{
		license: "", // Empty license
	}

	ctx := context.Background()
	license, err := provider.Get(ctx, provider.GetOptions{
		Purl:     "pkg:npm/test@1.0.0",
		Provider: mockProv,
		Cache:    mockCache,
		CacheTTL: 0,
	})

	if err != nil {
		t.Errorf("Get() unexpected error = %v", err)
	}

	if license != "" {
		t.Errorf("Get() = %q, want empty string", license)
	}

	// Verify empty license was not cached
	if mockCache.setCalls != 0 {
		t.Errorf("Cache.Set() called %d times, want 0 (empty license should not be cached)", mockCache.setCalls)
	}

	if len(mockCache.data) != 0 {
		t.Error("empty license should not be stored in cache")
	}
}
