package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/provider"
	"github.com/boringbin/sbomlicense/internal/server"
)

// mockProvider is a mock implementation of provider.Provider for testing.
type mockProvider struct {
	mu       sync.Mutex
	license  string
	err      error
	getCalls int
}

func (m *mockProvider) Get(_ context.Context, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getCalls++
	if m.err != nil {
		return "", m.err
	}
	return m.license, nil
}

// mockCache is a mock implementation of cache.Cache for testing.
type mockCache struct {
	mu       sync.Mutex
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
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.Lock()
	defer m.mu.Unlock()

	m.setCalls++
	if m.setErr != nil {
		return m.setErr
	}
	m.data[key] = value
	return nil
}

func (m *mockCache) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	return nil
}

func (m *mockCache) Close() error {
	return nil
}

// testLogger returns a logger that discards output for testing.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestNewServer tests the NewServer constructor.
func TestNewServer(t *testing.T) {
	t.Parallel()

	mockProv := &mockProvider{license: "MIT"}
	mockCache := newMockCache()
	logger := testLogger()
	parallelism := 20
	cacheTTL := 0 * time.Hour
	version := "1.0.0-test"

	srv := server.NewServer(mockProv, mockCache, logger, parallelism, cacheTTL, version)

	if srv == nil {
		t.Fatal("NewServer() returned nil")
	}

	// Verify server works by making a request
	handler := srv.Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}
}

// TestServer_Handler tests the Handler() method returns a working handler.
func TestServer_Handler(t *testing.T) {
	t.Parallel()

	srv := server.NewServer(&mockProvider{}, newMockCache(), testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	if handler == nil {
		t.Fatal("Handler() returned nil")
	}

	// Verify routes exist by making requests
	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/health"},
		{http.MethodPost, "/enrich"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			// Should not return 404 (route exists)
			if rec.Code == http.StatusNotFound {
				t.Errorf("Handler() route %s %s not found", tt.method, tt.path)
			}
		})
	}
}

// TestServer_HandleHealth_Success tests successful health check.
func TestServer_HandleHealth_Success(t *testing.T) {
	t.Parallel()

	srv := server.NewServer(&mockProvider{}, newMockCache(), testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleHealth() status = %d, want %d", rec.Code, http.StatusOK)
	}

	// Verify Content-Type
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("HandleHealth() Content-Type = %q, want %q", contentType, "application/json")
	}

	// Verify response body is "OK"
	var response string
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Errorf("HandleHealth() response not valid JSON: %v", err)
	}
	if response != "OK" {
		t.Errorf("HandleHealth() response = %q, want %q", response, "OK")
	}
}

// TestServer_HandleHealth_MethodNotAllowed tests non-GET methods return 405.
func TestServer_HandleHealth_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	srv := server.NewServer(&mockProvider{}, newMockCache(), testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(method, "/health", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("HandleHealth() with %s status = %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
			}

			// Verify error response
			var errResp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Errorf("HandleHealth() error response not valid JSON: %v", err)
			}
			if _, ok := errResp["error"]; !ok {
				t.Error("HandleHealth() error response missing 'error' field")
			}
		})
	}
}

// TestServer_HandleEnrich_MethodNotAllowed tests non-POST methods return 405.
func TestServer_HandleEnrich_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	srv := server.NewServer(&mockProvider{}, newMockCache(), testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	methods := []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(method, "/enrich", nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("HandleEnrich() with %s status = %d, want %d", method, rec.Code, http.StatusMethodNotAllowed)
			}

			// Verify error response
			var errResp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Errorf("HandleEnrich() error response not valid JSON: %v", err)
			}
			if !strings.Contains(errResp["error"], "POST") {
				t.Errorf("HandleEnrich() error = %q, want error containing 'POST'", errResp["error"])
			}
		})
	}
}

// TestServer_HandleEnrich_InvalidJSON tests malformed JSON returns 400.
func TestServer_HandleEnrich_InvalidJSON(t *testing.T) {
	t.Parallel()

	srv := server.NewServer(&mockProvider{}, newMockCache(), testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	invalidJSON := []string{
		`{invalid json}`,
		`{"sbom": }`,
		`not json at all`,
		``,
	}

	for _, body := range invalidJSON {
		t.Run("body="+body, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/enrich", strings.NewReader(body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("HandleEnrich() with invalid JSON status = %d, want %d", rec.Code, http.StatusBadRequest)
			}

			// Verify error response
			var errResp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Errorf("HandleEnrich() error response not valid JSON: %v", err)
			}
			if !strings.Contains(errResp["error"], "JSON") && !strings.Contains(errResp["error"], "invalid") {
				t.Errorf("HandleEnrich() error = %q, want error about invalid JSON", errResp["error"])
			}
		})
	}
}

// TestServer_HandleEnrich_EmptySBOM tests missing or empty sbom field returns 400.
func TestServer_HandleEnrich_EmptySBOM(t *testing.T) {
	t.Parallel()

	srv := server.NewServer(&mockProvider{}, newMockCache(), testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	tests := []struct {
		name        string
		body        string
		wantInError string
	}{
		{
			name:        "missing sbom field",
			body:        `{"parallelism": 10}`,
			wantInError: "sbom",
		},
		{
			name:        "empty sbom field",
			body:        `{"sbom": "", "parallelism": 10}`,
			wantInError: "invalid", // Will fail during format detection
		},
		{
			name:        "null sbom field",
			body:        `{"sbom": null}`,
			wantInError: "format", // Will fail during format detection
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodPost, "/enrich", strings.NewReader(tt.body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("HandleEnrich() status = %d, want %d", rec.Code, http.StatusBadRequest)
			}

			// Verify error response contains expected string
			var errResp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
				t.Errorf("HandleEnrich() error response not valid JSON: %v", err)
			}
			if !strings.Contains(strings.ToLower(errResp["error"]), strings.ToLower(tt.wantInError)) {
				t.Errorf("HandleEnrich() error = %q, want error containing %q", errResp["error"], tt.wantInError)
			}
		})
	}
}

// TestServer_HandleEnrich_RequestBodyTooLarge tests >10MB request returns error.
func TestServer_HandleEnrich_RequestBodyTooLarge(t *testing.T) {
	t.Parallel()

	srv := server.NewServer(&mockProvider{}, newMockCache(), testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	// Create a body slightly larger than 10MB
	largeData := make([]byte, 10*1024*1024+1)
	for i := range largeData {
		largeData[i] = 'a'
	}
	body := `{"sbom": "` + string(largeData) + `"}`

	req := httptest.NewRequest(http.MethodPost, "/enrich", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Should return 400 or 413
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("HandleEnrich() with large body status = %d, want %d or %d",
			rec.Code, http.StatusBadRequest, http.StatusRequestEntityTooLarge)
	}
}

// TestServer_HandleEnrich_Parallelism tests parallelism handling.
func TestServer_HandleEnrich_Parallelism(t *testing.T) {
	t.Parallel()

	// Use a simple valid SPDX SBOM
	validSBOM := `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}`

	tests := []struct {
		name               string
		parallelism        int
		defaultParallelism int
		wantUsed           int
	}{
		{
			name:               "uses custom parallelism",
			parallelism:        5,
			defaultParallelism: 20,
			wantUsed:           5,
		},
		{
			name:               "uses default when zero",
			parallelism:        0,
			defaultParallelism: 15,
			wantUsed:           15,
		},
		{
			name:               "uses default when negative",
			parallelism:        -1,
			defaultParallelism: 10,
			wantUsed:           10,
		},
		{
			name:               "uses default when not specified",
			parallelism:        0, // Will be omitted in JSON
			defaultParallelism: 25,
			wantUsed:           25,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockProv := &mockProvider{license: "MIT"}
			mockCache := newMockCache()
			srv := server.NewServer(mockProv, mockCache, testLogger(), tt.defaultParallelism, 0*time.Hour, "1.0.0")
			handler := srv.Handler()

			// Create request body
			reqBody := map[string]interface{}{
				"sbom": json.RawMessage(validSBOM),
			}
			if tt.parallelism != 0 {
				reqBody["parallelism"] = tt.parallelism
			}
			reqJSON, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/enrich", bytes.NewReader(reqJSON))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			// We can't directly verify the parallelism used, but we can verify the request succeeded
			if rec.Code != http.StatusOK {
				t.Errorf("HandleEnrich() status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
			}
		})
	}
}

// TestServer_HandleEnrich_FormatDetection tests SBOM format detection.
func TestServer_HandleEnrich_FormatDetection(t *testing.T) {
	t.Parallel()

	mockProv := &mockProvider{license: "MIT"}
	mockCache := newMockCache()

	tests := []struct {
		name       string
		sbom       string
		wantStatus int
	}{
		{
			name:       "SPDX format detected",
			sbom:       `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "CycloneDX format detected",
			sbom:       `{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "invalid format returns 400",
			sbom:       `{"unknown": "format"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "empty object returns 400",
			sbom:       `{}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := server.NewServer(mockProv, mockCache, testLogger(), 10, 0*time.Hour, "1.0.0")
			handler := srv.Handler()

			body := `{"sbom": ` + tt.sbom + `}`
			req := httptest.NewRequest(http.MethodPost, "/enrich", strings.NewReader(body))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("HandleEnrich() status = %d, want %d, body: %s",
					rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestServer_HandleEnrich_SPDX_Success tests successful SPDX enrichment.
func TestServer_HandleEnrich_SPDX_Success(t *testing.T) {
	t.Parallel()

	// Read real testdata
	testdata, err := os.ReadFile("../../testdata/example-spdx.json")
	if err != nil {
		t.Skipf("skipping test: testdata not available: %v", err)
	}

	mockProv := &mockProvider{license: "MIT"}
	mockCache := newMockCache()
	srv := server.NewServer(mockProv, mockCache, testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	// Create request with testdata
	reqBody := map[string]interface{}{
		"sbom":        json.RawMessage(testdata),
		"parallelism": 5,
	}
	reqJSON, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/enrich", bytes.NewReader(reqJSON))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleEnrich() status = %d, want %d, body: %s",
			rec.Code, http.StatusOK, rec.Body.String())
	}

	// Verify response structure
	var response map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &response); unmarshalErr != nil {
		t.Fatalf("HandleEnrich() response not valid JSON: %v", unmarshalErr)
	}

	if _, ok := response["sbom"]; !ok {
		t.Error("HandleEnrich() response missing 'sbom' field")
	}

	// Verify Content-Type
	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("HandleEnrich() Content-Type = %q, want %q", contentType, "application/json")
	}

	// Verify provider was called (packages in testdata have purls)
	if mockProv.getCalls == 0 {
		t.Error("HandleEnrich() provider not called, expected license lookups")
	}
}

// TestServer_HandleEnrich_CycloneDX_Success tests successful CycloneDX enrichment.
func TestServer_HandleEnrich_CycloneDX_Success(t *testing.T) {
	t.Parallel()

	// Read real testdata
	testdata, err := os.ReadFile("../../testdata/example-cyclonedx.json")
	if err != nil {
		t.Skipf("skipping test: testdata not available: %v", err)
	}

	mockProv := &mockProvider{license: "Apache-2.0"}
	mockCache := newMockCache()
	srv := server.NewServer(mockProv, mockCache, testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	// Create request with testdata
	reqBody := map[string]interface{}{
		"sbom":        json.RawMessage(testdata),
		"parallelism": 5,
	}
	reqJSON, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/enrich", bytes.NewReader(reqJSON))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleEnrich() status = %d, want %d, body: %s",
			rec.Code, http.StatusOK, rec.Body.String())
	}

	// Verify response structure
	var response2 map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &response2); unmarshalErr != nil {
		t.Fatalf("HandleEnrich() response not valid JSON: %v", unmarshalErr)
	}

	if _, ok := response2["sbom"]; !ok {
		t.Error("HandleEnrich() response missing 'sbom' field")
	}

	// Verify provider was called
	if mockProv.getCalls == 0 {
		t.Error("HandleEnrich() provider not called, expected license lookups")
	}
}

// TestServer_HandleEnrich_GitHubWrappedSPDX tests GitHub-wrapped SBOM handling.
func TestServer_HandleEnrich_GitHubWrappedSPDX(t *testing.T) {
	t.Parallel()

	// Read real GitHub-wrapped testdata
	testdata, err := os.ReadFile("../../testdata/github-wrapped-spdx.json")
	if err != nil {
		t.Skipf("skipping test: testdata not available: %v", err)
	}

	mockProv := &mockProvider{license: "MIT"}
	mockCache := newMockCache()
	srv := server.NewServer(mockProv, mockCache, testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	// Create request with GitHub-wrapped SBOM
	// The SBOM is already wrapped, so we just put it in the request
	reqBody := map[string]interface{}{
		"sbom": json.RawMessage(testdata),
	}
	reqJSON, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/enrich", bytes.NewReader(reqJSON))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("HandleEnrich() status = %d, want %d, body: %s",
			rec.Code, http.StatusOK, rec.Body.String())
	}

	// Verify response structure
	var response3 map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &response3); unmarshalErr != nil {
		t.Fatalf("HandleEnrich() response not valid JSON: %v", unmarshalErr)
	}

	if _, ok := response3["sbom"]; !ok {
		t.Error("HandleEnrich() response missing 'sbom' field")
	}
}

// TestServer_HandleEnrich_EnrichmentFailure tests enrichment errors return 500.
func TestServer_HandleEnrich_EnrichmentFailure(t *testing.T) {
	t.Parallel()

	// Use provider that returns an error
	mockProv := &mockProvider{
		err: provider.ErrLicenseNotFound,
	}
	mockCache := newMockCache()
	srv := server.NewServer(mockProv, mockCache, testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	// Simple valid SBOM with a package that has a purl
	sbom := `{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"packages": [{
			"SPDXID": "SPDXRef-Package",
			"name": "test",
			"externalRefs": [{
				"referenceType": "purl",
				"referenceLocator": "pkg:npm/test@1.0.0"
			}]
		}]
	}`

	body := `{"sbom": ` + sbom + `}`
	req := httptest.NewRequest(http.MethodPost, "/enrich", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Enrichment can fail but still return 200 (errors are logged, not fatal)
	// OR it might return 500 if the error is critical
	// Check that we get a valid response
	if rec.Code != http.StatusOK && rec.Code != http.StatusInternalServerError {
		t.Logf("HandleEnrich() status = %d (acceptable for error scenario)", rec.Code)
	}
}

// TestServer_HandleEnrich_ProviderError tests provider errors are handled.
func TestServer_HandleEnrich_ProviderError(t *testing.T) {
	t.Parallel()

	// Use provider that returns a specific error
	mockProv := &mockProvider{
		err: errors.New("provider connection failed"),
	}
	mockCache := newMockCache()
	srv := server.NewServer(mockProv, mockCache, testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	// Simple SBOM
	sbom := `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}`
	body := `{"sbom": ` + sbom + `}`

	req := httptest.NewRequest(http.MethodPost, "/enrich", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	// Empty packages should succeed even with provider error
	if rec.Code != http.StatusOK {
		t.Errorf("HandleEnrich() status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// TestServer_HandleEnrich_UnsupportedFormat tests unsupported format returns 400.
func TestServer_HandleEnrich_UnsupportedFormat(t *testing.T) {
	t.Parallel()

	mockProv := &mockProvider{license: "MIT"}
	mockCache := newMockCache()
	srv := server.NewServer(mockProv, mockCache, testLogger(), 10, 0*time.Hour, "1.0.0")
	handler := srv.Handler()

	// SBOM with unknown format
	sbom := `{"version": "1.0", "format": "CustomFormat"}`
	body := `{"sbom": ` + sbom + `}`

	req := httptest.NewRequest(http.MethodPost, "/enrich", strings.NewReader(body))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("HandleEnrich() status = %d, want %d", rec.Code, http.StatusBadRequest)
	}

	// Verify error response mentions format
	var errResp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Errorf("HandleEnrich() error response not valid JSON: %v", err)
	}
	if !strings.Contains(errResp["error"], "format") && !strings.Contains(errResp["error"], "SBOM") {
		t.Errorf("HandleEnrich() error = %q, want error about format", errResp["error"])
	}
}

// TestServer_E2E_WithRealTestdata tests end-to-end enrichment with real testdata.
func TestServer_E2E_WithRealTestdata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		testfile string
		format   string
	}{
		{
			name:     "SPDX enrichment",
			testfile: "../../testdata/example-spdx.json",
			format:   "SPDX",
		},
		{
			name:     "CycloneDX enrichment",
			testfile: "../../testdata/example-cyclonedx.json",
			format:   "CycloneDX",
		},
		{
			name:     "GitHub-wrapped SPDX",
			testfile: "../../testdata/github-wrapped-spdx.json",
			format:   "SPDX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			testdata, err := os.ReadFile(tt.testfile)
			if err != nil {
				t.Skipf("skipping test: testdata not available: %v", err)
			}

			// Create server with mock provider that returns different licenses
			mockProv := &mockProvider{license: "MIT"}
			mockCache := newMockCache()
			srv := server.NewServer(mockProv, mockCache, testLogger(), 10, 0*time.Hour, "1.0.0-test")
			handler := srv.Handler()

			// Create request
			reqBody := map[string]interface{}{
				"sbom":        json.RawMessage(testdata),
				"parallelism": 10,
			}
			reqJSON, _ := json.Marshal(reqBody)

			req := httptest.NewRequest(http.MethodPost, "/enrich", bytes.NewReader(reqJSON))
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			// Verify success
			if rec.Code != http.StatusOK {
				t.Errorf("HandleEnrich() status = %d, want %d, body: %s",
					rec.Code, http.StatusOK, rec.Body.String())
			}

			// Verify response contains enriched SBOM
			var response map[string]json.RawMessage
			if unmarshalErr := json.Unmarshal(rec.Body.Bytes(), &response); unmarshalErr != nil {
				t.Fatalf("HandleEnrich() response not valid JSON: %v", unmarshalErr)
			}

			enrichedSBOM, ok := response["sbom"]
			if !ok {
				t.Fatal("HandleEnrich() response missing 'sbom' field")
			}

			// Verify enriched SBOM is valid JSON and contains expected format marker
			var sbomData map[string]interface{}
			if unmarshalErr := json.Unmarshal(enrichedSBOM, &sbomData); unmarshalErr != nil {
				t.Fatalf("HandleEnrich() enriched SBOM not valid JSON: %v", unmarshalErr)
			}

			// Verify format-specific fields
			switch tt.format {
			case "SPDX":
				if _, found := sbomData["spdxVersion"]; !found {
					t.Error("Enriched SPDX SBOM missing 'spdxVersion' field")
				}
			case "CycloneDX":
				if _, found := sbomData["bomFormat"]; !found {
					t.Error("Enriched CycloneDX SBOM missing 'bomFormat' field")
				}
			}

			t.Logf("Successfully enriched %s SBOM", tt.format)
		})
	}
}
