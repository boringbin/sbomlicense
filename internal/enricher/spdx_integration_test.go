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

// TestSPDXEnricher_Integration_RealSBOM tests end-to-end enrichment with real SPDX SBOM file.
func TestSPDXEnricher_Integration_RealSBOM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Parallel()

	// Read real SBOM file from testdata
	testdataPath := filepath.Join("..", "..", "testdata", "example-spdx.json")
	sbomData, err := os.ReadFile(testdataPath)
	if err != nil {
		t.Fatalf("Failed to read test SBOM: %v", err)
	}

	// Create mock provider with realistic license data
	licenses := map[string]string{
		"pkg:golang/github.com/spf13/cobra@v1.8.0":        "Apache-2.0",
		"pkg:golang/github.com/spf13/pflag@v1.0.5":        "BSD-3-Clause",
		"pkg:golang/golang.org/x/sys@v0.0.0":              "BSD-3-Clause",
		"pkg:golang/gopkg.in/yaml.v3@v3.0.1":              "MIT",
		"pkg:pypi/requests@2.31.0":                        "Apache-2.0",
		"pkg:pypi/urllib3@2.0.7":                          "MIT",
		"pkg:npm/express@4.18.2":                          "MIT",
		"pkg:npm/lodash@4.17.21":                          "MIT",
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

	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

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
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	// Verify SPDX structure is preserved
	if got := doc["spdxVersion"]; got == "" || got == nil {
		t.Error("spdxVersion missing from result")
	}

	// Verify packages array exists
	packages, ok := doc["packages"].([]interface{})
	if !ok {
		t.Fatal("packages field is not an array")
	}

	// Count how many packages were enriched
	enrichedCount := 0
	for _, p := range packages {
		pkg, pkgOk := p.(map[string]interface{})
		if !pkgOk {
			continue
		}

		// Check if package has license (either existing or newly added)
		if licenseConcluded, exists := pkg["licenseConcluded"]; exists {
			if lic, licOk := licenseConcluded.(string); licOk && lic != "" && lic != "NONE" && lic != "NOASSERTION" {
				enrichedCount++
			}
		}
	}

	t.Logf("Enriched %d out of %d packages", enrichedCount, len(packages))

	// Verify at least some packages were enriched (depends on test SBOM content)
	if enrichedCount == 0 && len(packages) > 0 {
		t.Error("Expected at least some packages to be enriched")
	}

	// Verify result can be parsed back into SBOM format
	format, err := sbom.DetectFormat(result)
	if err != nil {
		t.Fatalf("Result cannot be detected as SBOM: %v", err)
	}

	if format != "SPDX-2.3" && format != "SPDX-2.2" {
		t.Errorf("Result format = %v, want SPDX", format)
	}
}

// TestSPDXEnricher_Integration_LargeSBOM tests performance with large SBOM.
func TestSPDXEnricher_Integration_LargeSBOM(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Parallel()

	// Create a large SBOM with 100 packages
	packages := make([]map[string]interface{}, 100)
	for i := range 100 {
		packages[i] = map[string]interface{}{
			"SPDXID":      "SPDXRef-Package-" + string(rune(i)),
			"name":        "pkg" + string(rune(i)),
			"versionInfo": "1.0.0",
			"externalRefs": []map[string]interface{}{
				{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType":     "purl",
					"referenceLocator":  "pkg:npm/pkg" + string(rune(i)) + "@1.0.0",
				},
			},
		}
	}

	doc := map[string]interface{}{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID":      "SPDXRef-DOCUMENT",
		"name":        "large-test",
		"packages":    packages,
	}

	sbomData, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Failed to marshal test SBOM: %v", err)
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

	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	opts := enricher.Options{
		SBOM:        sbomData,
		Parallelism: 10,           // High parallelism for large SBOM
		Logger:      noopLogger(), // Reduce log noise
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// Verify all packages were processed
	var resultDoc map[string]interface{}
	err = json.Unmarshal(result, &resultDoc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	resultPackages := resultDoc["packages"].([]interface{})
	if len(resultPackages) != 100 {
		t.Errorf("Expected 100 packages, got %d", len(resultPackages))
	}

	// Verify all packages have licenses
	enrichedCount := 0
	for _, p := range resultPackages {
		pkg := p.(map[string]interface{})
		if lic, exists := pkg["licenseConcluded"]; exists && lic != "" {
			enrichedCount++
		}
	}

	if enrichedCount != 100 {
		t.Errorf("Expected all 100 packages to be enriched, got %d", enrichedCount)
	}

	t.Logf("Successfully enriched all %d packages in large SBOM", enrichedCount)
}
