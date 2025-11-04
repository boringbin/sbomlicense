//go:build integration

package enricher_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/enricher"
	"github.com/boringbin/sbomlicense/internal/sbom"
)

// TestCycloneDXEnricher_Integration_RealSBOM tests end-to-end enrichment with real CycloneDX SBOM file.
func TestCycloneDXEnricher_Integration_RealSBOM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Parallel()

	// Read real SBOM file from testdata
	testdataPath := filepath.Join("..", "..", "testdata", "example-cyclonedx.json")
	sbomData, err := os.ReadFile(testdataPath)
	if err != nil {
		t.Fatalf("Failed to read test SBOM: %v", err)
	}

	// Create mock provider with realistic license data
	licenses := map[string]string{
		"pkg:npm/express@4.18.2":                          "MIT",
		"pkg:npm/lodash@4.17.21":                          "MIT",
		"pkg:npm/react@18.2.0":                            "MIT",
		"pkg:pypi/requests@2.31.0":                        "Apache-2.0",
		"pkg:pypi/urllib3@2.0.7":                          "MIT",
		"pkg:golang/github.com/spf13/cobra@v1.8.0":        "Apache-2.0",
		"pkg:golang/github.com/spf13/pflag@v1.0.5":        "BSD-3-Clause",
		"pkg:maven/org.springframework/spring-core@6.0.0": "Apache-2.0",
	}

	provider := &mockProvider{
		getLicense: func(_ context.Context, purl string) (string, error) {
			if lic, ok := licenses[purl]; ok {
				return lic, nil
			}
			// Return MIT as fallback for unknown packages
			return "MIT", nil
		},
	}

	c := cache.NewMemoryCache()
	defer c.Close()

	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	opts := enricher.Options{
		SBOM:        sbomData,
		Parallelism: 4, // Test parallel processing
		Logger:      newTestLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// Verify result is valid JSON
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	// Verify CycloneDX structure is preserved
	if got := bom["bomFormat"]; got != "CycloneDX" {
		t.Errorf("bomFormat = %v, want CycloneDX", got)
	}

	// Verify components array exists
	components, ok := bom["components"].([]interface{})
	if !ok {
		t.Fatal("components field is not an array")
	}

	// Count how many components were enriched
	enrichedCount := 0
	for _, c := range components {
		comp, compOk := c.(map[string]interface{})
		if !compOk {
			continue
		}

		// Check if component has licenses
		if licenses, exists := comp["licenses"]; exists {
			if lics, licsOk := licenses.([]interface{}); licsOk && len(lics) > 0 {
				enrichedCount++
			}
		}
	}

	t.Logf("Enriched %d out of %d components", enrichedCount, len(components))

	// Verify at least some components were enriched (depends on test SBOM content)
	if enrichedCount == 0 && len(components) > 0 {
		t.Error("Expected at least some components to be enriched")
	}

	// Verify result can be parsed back into SBOM format
	format, err := sbom.DetectFormat(result)
	if err != nil {
		t.Fatalf("Result cannot be detected as SBOM: %v", err)
	}

	if format != "CycloneDX-1.4" && format != "CycloneDX-1.5" && format != "CycloneDX" {
		t.Errorf("Result format = %v, want CycloneDX", format)
	}
}

// TestCycloneDXEnricher_Integration_LargeSBOM tests performance with large SBOM.
func TestCycloneDXEnricher_Integration_LargeSBOM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Parallel()

	// Create a large BOM with 100 components
	components := make([]map[string]interface{}, 100)
	for i := range 100 {
		components[i] = map[string]interface{}{
			"type":    "library",
			"name":    "pkg" + string(rune(i)),
			"version": "1.0.0",
			"purl":    "pkg:npm/pkg" + string(rune(i)) + "@1.0.0",
		}
	}

	bom := map[string]interface{}{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.4",
		"components":  components,
	}

	sbomData, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("Failed to marshal test BOM: %v", err)
	}

	provider := &mockProvider{
		getLicense: func(_ context.Context, purl string) (string, error) {
			// Return different licenses based on package number
			if purl[len(purl)-5] == '0' {
				return "MIT", nil
			} else if purl[len(purl)-5] == '1' {
				return "Apache-2.0", nil
			}
			return "BSD-3-Clause", nil
		},
	}

	c := cache.NewMemoryCache()
	defer c.Close()

	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	opts := enricher.Options{
		SBOM:        sbomData,
		Parallelism: 10,           // High parallelism for large BOM
		Logger:      noopLogger(), // Reduce log noise
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// Verify all components were processed
	var resultBom map[string]interface{}
	err = json.Unmarshal(result, &resultBom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	resultComponents := resultBom["components"].([]interface{})
	if len(resultComponents) != 100 {
		t.Errorf("Expected 100 components, got %d", len(resultComponents))
	}

	// Verify all components have licenses
	enrichedCount := 0
	for _, c := range resultComponents {
		comp := c.(map[string]interface{})
		if lics, exists := comp["licenses"]; exists {
			if licenses, ok := lics.([]interface{}); ok && len(licenses) > 0 {
				enrichedCount++
			}
		}
	}

	if enrichedCount != 100 {
		t.Errorf("Expected all 100 components to be enriched, got %d", enrichedCount)
	}

	t.Logf("Successfully enriched all %d components in large BOM", enrichedCount)
}
