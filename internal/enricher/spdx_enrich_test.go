package enricher_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/enricher"
)

// TestNewSPDXEnricher tests that the constructor initializes correctly.
func TestNewSPDXEnricher(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{}
	c := cache.NewMemoryCache()
	defer c.Close()

	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)
	if e == nil {
		t.Fatal("NewSPDXEnricher() returned nil")
	}
}

// TestSPDXEnricher_Enrich_SinglePackageWithoutLicense tests enrichment of a single package.
func TestSPDXEnricher_Enrich_SinglePackageWithoutLicense(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, purl string) (string, error) {
			if purl == "pkg:npm/express@4.17.1" {
				return "MIT", nil
			}
			return "", errors.New("unexpected purl")
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"versionInfo": "4.17.1",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/express@4.17.1"
					}
				]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// Parse result to verify license was added
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages, ok := doc["packages"].([]interface{})
	if !ok || len(packages) != 1 {
		t.Fatal("Expected 1 package in result")
	}

	pkg, ok := packages[0].(map[string]interface{})
	if !ok {
		t.Fatal("Package is not a map")
	}

	if got := pkg["licenseConcluded"]; got != "MIT" {
		t.Errorf("licenseConcluded = %v, want MIT", got)
	}
	if got := pkg["licenseDeclared"]; got != "MIT" {
		t.Errorf("licenseDeclared = %v, want MIT", got)
	}
}

// TestSPDXEnricher_Enrich_PreserveExistingLicenseConcluded tests that existing
// LicenseConcluded is preserved.
func TestSPDXEnricher_Enrich_PreserveExistingLicenseConcluded(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"licenseConcluded": "Apache-2.0",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/express@4.17.1"
					}
				]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	if providerCalled {
		t.Error("Provider should not have been called when license already exists")
	}

	// Verify license unchanged
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	pkg := packages[0].(map[string]interface{})

	if got := pkg["licenseConcluded"]; got != "Apache-2.0" {
		t.Errorf("licenseConcluded = %v, want Apache-2.0", got)
	}
}

// TestSPDXEnricher_Enrich_PreserveExistingLicenseDeclared tests that existing
// LicenseDeclared is preserved.
func TestSPDXEnricher_Enrich_PreserveExistingLicenseDeclared(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"licenseDeclared": "BSD-3-Clause",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/express@4.17.1"
					}
				]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	if providerCalled {
		t.Error("Provider should not have been called when license already exists")
	}

	// Verify license unchanged
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	pkg := packages[0].(map[string]interface{})

	if got := pkg["licenseDeclared"]; got != "BSD-3-Clause" {
		t.Errorf("licenseDeclared = %v, want BSD-3-Clause", got)
	}
}

// TestSPDXEnricher_Enrich_NONELicense tests enrichment of packages with "NONE" license.
func TestSPDXEnricher_Enrich_NONELicense(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"licenseConcluded": "NONE",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/express@4.17.1"
					}
				]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// Verify license was updated
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	pkg := packages[0].(map[string]interface{})

	if got := pkg["licenseConcluded"]; got != "MIT" {
		t.Errorf("licenseConcluded = %v, want MIT", got)
	}
	if got := pkg["licenseDeclared"]; got != "MIT" {
		t.Errorf("licenseDeclared = %v, want MIT", got)
	}
}

// TestSPDXEnricher_Enrich_NOASSERTIONLicense tests enrichment of packages with "NOASSERTION" license.
func TestSPDXEnricher_Enrich_NOASSERTIONLicense(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			return "Apache-2.0", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"licenseDeclared": "NOASSERTION",
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:npm/express@4.17.1"
					}
				]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// Verify license was updated
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	pkg := packages[0].(map[string]interface{})

	if got := pkg["licenseConcluded"]; got != "Apache-2.0" {
		t.Errorf("licenseConcluded = %v, want Apache-2.0", got)
	}
	if got := pkg["licenseDeclared"]; got != "Apache-2.0" {
		t.Errorf("licenseDeclared = %v, want Apache-2.0", got)
	}
}

// TestSPDXEnricher_Enrich_EmptySBOM tests that empty SBOMs are returned unchanged.
func TestSPDXEnricher_Enrich_EmptySBOM(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": []
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	if providerCalled {
		t.Error("Provider should not have been called for empty SBOM")
	}

	// Verify result is unchanged
	var inputDoc, resultDoc map[string]interface{}
	err = json.Unmarshal(input, &inputDoc)
	if err != nil {
		t.Fatalf("Failed to unmarshal input: %v", err)
	}
	err = json.Unmarshal(result, &resultDoc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if len(resultDoc["packages"].([]interface{})) != 0 {
		t.Error("Expected empty packages array in result")
	}
}

// TestSPDXEnricher_Enrich_MultiplePackages tests enrichment of multiple packages.
func TestSPDXEnricher_Enrich_MultiplePackages(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, purl string) (string, error) {
			licenses := map[string]string{
				"pkg:npm/express@4.17.1": "MIT",
				"pkg:npm/lodash@4.17.21": "MIT",
				"pkg:npm/react@18.0.0":   "MIT",
			}
			if lic, ok := licenses[purl]; ok {
				return lic, nil
			}
			return "", errors.New("unknown package")
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package1",
				"name": "express",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/express@4.17.1"}]
			},
			{
				"SPDXID": "SPDXRef-Package2",
				"name": "lodash",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}]
			},
			{
				"SPDXID": "SPDXRef-Package3",
				"name": "react",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/react@18.0.0"}]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 2,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// Verify all packages were enriched
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	if len(packages) != 3 {
		t.Fatalf("Expected 3 packages, got %d", len(packages))
	}

	for i, p := range packages {
		pkg := p.(map[string]interface{})
		if got := pkg["licenseConcluded"]; got != "MIT" {
			t.Errorf("Package %d: licenseConcluded = %v, want MIT", i, got)
		}
		if got := pkg["licenseDeclared"]; got != "MIT" {
			t.Errorf("Package %d: licenseDeclared = %v, want MIT", i, got)
		}
	}
}

// TestSPDXEnricher_Enrich_MixedLicenseStates tests handling of packages with mixed license states.
func TestSPDXEnricher_Enrich_MixedLicenseStates(t *testing.T) {
	t.Parallel()

	callCount := 0
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			callCount++
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package1",
				"name": "with-license",
				"licenseConcluded": "Apache-2.0",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/pkg1@1.0.0"}]
			},
			{
				"SPDXID": "SPDXRef-Package2",
				"name": "with-NONE",
				"licenseConcluded": "NONE",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/pkg2@1.0.0"}]
			},
			{
				"SPDXID": "SPDXRef-Package3",
				"name": "without-license",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/pkg3@1.0.0"}]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// Provider should be called only for packages 2 and 3 (not package 1)
	if callCount != 2 {
		t.Errorf("Provider called %d times, want 2", callCount)
	}

	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})

	// Package 1: should be unchanged
	pkg1 := packages[0].(map[string]interface{})
	if got := pkg1["licenseConcluded"]; got != "Apache-2.0" {
		t.Errorf("Package 1 licenseConcluded = %v, want Apache-2.0", got)
	}

	// Package 2: should be updated from NONE
	pkg2 := packages[1].(map[string]interface{})
	if got := pkg2["licenseConcluded"]; got != "MIT" {
		t.Errorf("Package 2 licenseConcluded = %v, want MIT", got)
	}

	// Package 3: should be enriched
	pkg3 := packages[2].(map[string]interface{})
	if got := pkg3["licenseConcluded"]; got != "MIT" {
		t.Errorf("Package 3 licenseConcluded = %v, want MIT", got)
	}
}

// TestSPDXEnricher_Enrich_ProviderError tests that provider errors are logged and processing continues.
func TestSPDXEnricher_Enrich_ProviderError(t *testing.T) {
	t.Parallel()

	callCount := 0
	provider := &mockProvider{
		getLicense: func(_ context.Context, purl string) (string, error) {
			callCount++
			if purl == "pkg:npm/pkg2@1.0.0" {
				return "", errors.New("API error")
			}
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package1",
				"name": "pkg1",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/pkg1@1.0.0"}]
			},
			{
				"SPDXID": "SPDXRef-Package2",
				"name": "pkg2",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/pkg2@1.0.0"}]
			},
			{
				"SPDXID": "SPDXRef-Package3",
				"name": "pkg3",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/pkg3@1.0.0"}]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      newTestLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	// All packages should be attempted
	if callCount != 3 {
		t.Errorf("Provider called %d times, want 3", callCount)
	}

	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})

	// Packages 1 and 3 should be enriched
	pkg1 := packages[0].(map[string]interface{})
	if got := pkg1["licenseConcluded"]; got != "MIT" {
		t.Errorf("Package 1 licenseConcluded = %v, want MIT", got)
	}

	pkg3 := packages[2].(map[string]interface{})
	if got := pkg3["licenseConcluded"]; got != "MIT" {
		t.Errorf("Package 3 licenseConcluded = %v, want MIT", got)
	}

	// Package 2 should not have license (provider error)
	pkg2 := packages[1].(map[string]interface{})
	if lic, exists := pkg2["licenseConcluded"]; exists && lic != "" && lic != nil {
		t.Errorf("Package 2 should not have licenseConcluded after provider error, got %v", lic)
	}
}

// TestSPDXEnricher_Enrich_ProviderReturnsEmpty tests that empty license strings are skipped.
func TestSPDXEnricher_Enrich_ProviderReturnsEmpty(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			return "", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/express@4.17.1"}]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	pkg := packages[0].(map[string]interface{})

	// License should not be set when provider returns empty string
	if lic, exists := pkg["licenseConcluded"]; exists && lic != "" && lic != nil {
		t.Errorf("licenseConcluded should not be set when provider returns empty string, got %v", lic)
	}
}

// TestSPDXEnricher_Enrich_Parallelism tests different parallelism levels.
func TestSPDXEnricher_Enrich_Parallelism(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		parallelism int
		expected    int // expected effective parallelism (defaults to 1)
	}{
		{"Single worker", 1, 1},
		{"Multiple workers", 5, 5},
		{"Zero defaults to 1", 0, 1},
		{"Negative defaults to 1", -5, 1},
		{"High parallelism", 100, 100},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider := &mockProvider{
				getLicense: func(_ context.Context, _ string) (string, error) {
					return "MIT", nil
				},
			}

			c := &mockCache{}
			e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

			// Create SBOM with 10 packages
			packages := make([]string, 10)
			for i := range 10 {
				packages[i] = `{
					"SPDXID": "SPDXRef-Package` + string(rune('0'+i)) + `",
					"name": "pkg` + string(rune('0'+i)) + `",
					"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/pkg` + string(rune('0'+i)) + `@1.0.0"}]
				}`
			}

			input := []byte(`{
				"spdxVersion": "SPDX-2.3",
				"dataLicense": "CC0-1.0",
				"SPDXID": "SPDXRef-DOCUMENT",
				"name": "test",
				"packages": [` + packages[0])
			for i := 1; i < len(packages); i++ {
				input = append(input, []byte(`,`+packages[i])...)
			}
			input = append(input, []byte(`]
			}`)...)

			opts := enricher.Options{
				SBOM:        input,
				Parallelism: tc.parallelism,
				Logger:      noopLogger(),
			}

			result, err := e.Enrich(context.Background(), opts)
			if err != nil {
				t.Fatalf("Enrich() error = %v", err)
			}

			// Verify all packages were enriched
			var doc map[string]interface{}
			err = json.Unmarshal(result, &doc)
			if err != nil {
				t.Fatalf("Failed to unmarshal result: %v", err)
			}

			pkgs := doc["packages"].([]interface{})
			if len(pkgs) != 10 {
				t.Fatalf("Expected 10 packages, got %d", len(pkgs))
			}

			for i, p := range pkgs {
				pkg := p.(map[string]interface{})
				if got := pkg["licenseConcluded"]; got != "MIT" {
					t.Errorf("Package %d: licenseConcluded = %v, want MIT", i, got)
				}
			}
		})
	}
}

// TestSPDXEnricher_Enrich_CacheHit tests that cache hits skip provider calls.
func TestSPDXEnricher_Enrich_CacheHit(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	c := &mockCache{
		getFunc: func(key string) (string, error) {
			if key == "pkg:npm/express@4.17.1" {
				return "Apache-2.0", nil
			}
			return "", cache.ErrCacheMiss
		},
	}

	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/express@4.17.1"}]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	if providerCalled {
		t.Error("Provider should not be called on cache hit")
	}

	// Verify license from cache was used
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	pkg := packages[0].(map[string]interface{})

	if got := pkg["licenseConcluded"]; got != "Apache-2.0" {
		t.Errorf("licenseConcluded = %v, want Apache-2.0 (from cache)", got)
	}
}

// TestSPDXEnricher_Enrich_CacheMiss tests that cache misses trigger provider calls.
func TestSPDXEnricher_Enrich_CacheMiss(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	cacheSetCalled := false
	c := &mockCache{
		getFunc: func(_ string) (string, error) {
			return "", cache.ErrCacheMiss
		},
		setWithTTLFunc: func(key string, value string, ttl time.Duration) error {
			cacheSetCalled = true
			if key != "pkg:npm/express@4.17.1" {
				t.Errorf("Cache key = %v, want pkg:npm/express@4.17.1", key)
			}
			if value != "MIT" {
				t.Errorf("Cache value = %v, want MIT", value)
			}
			if ttl != 24*time.Hour {
				t.Errorf("Cache TTL = %v, want 24h", ttl)
			}
			return nil
		},
	}

	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/express@4.17.1"}]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      noopLogger(),
	}

	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	if !providerCalled {
		t.Error("Provider should be called on cache miss")
	}

	if !cacheSetCalled {
		t.Error("Cache.SetWithTTL should be called after provider returns")
	}

	// Verify license from provider was used
	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	pkg := packages[0].(map[string]interface{})

	if got := pkg["licenseConcluded"]; got != "MIT" {
		t.Errorf("licenseConcluded = %v, want MIT", got)
	}
}

// Cache errors are logged but don't fail enrichment - this is by design
// for resilience. The enricher continues processing other packages.

// TestSPDXEnricher_Enrich_NilLogger tests that nil logger doesn't cause panics.
func TestSPDXEnricher_Enrich_NilLogger(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewSPDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"packages": [
			{
				"SPDXID": "SPDXRef-Package",
				"name": "express",
				"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/express@4.17.1"}]
			}
		]
	}`)

	opts := enricher.Options{
		SBOM:        input,
		Parallelism: 1,
		Logger:      nil, // Nil logger
	}

	// Should not panic
	result, err := e.Enrich(context.Background(), opts)
	if err != nil {
		t.Fatalf("Enrich() error = %v", err)
	}

	var doc map[string]interface{}
	err = json.Unmarshal(result, &doc)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	packages := doc["packages"].([]interface{})
	pkg := packages[0].(map[string]interface{})

	if got := pkg["licenseConcluded"]; got != "MIT" {
		t.Errorf("licenseConcluded = %v, want MIT", got)
	}
}

// Context cancellation stops individual provider calls but doesn't fail the
// overall enrichment - errors are logged. This is by design for resilience.
