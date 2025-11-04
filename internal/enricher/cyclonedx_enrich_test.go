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

// TestNewCycloneDXEnricher tests that the constructor initializes correctly.
func TestNewCycloneDXEnricher(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{}
	c := cache.NewMemoryCache()
	defer c.Close()

	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)
	if e == nil {
		t.Fatal("NewCycloneDXEnricher() returned nil")
	}
}

// TestCycloneDXEnricher_Enrich_SingleComponentWithoutLicense tests enrichment of a single component.
func TestCycloneDXEnricher_Enrich_SingleComponentWithoutLicense(t *testing.T) {
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
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"version": "4.17.1",
				"purl": "pkg:npm/express@4.17.1"
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
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components, ok := bom["components"].([]interface{})
	if !ok || len(components) != 1 {
		t.Fatal("Expected 1 component in result")
	}

	comp, ok := components[0].(map[string]interface{})
	if !ok {
		t.Fatal("Component is not a map")
	}

	licenses, ok := comp["licenses"].([]interface{})
	if !ok || len(licenses) != 1 {
		t.Fatal("Expected 1 license in component")
	}

	lic, ok := licenses[0].(map[string]interface{})
	if !ok {
		t.Fatal("License is not a map")
	}

	if got := lic["expression"]; got != "MIT" {
		t.Errorf("license expression = %v, want MIT", got)
	}
}

// TestCycloneDXEnricher_Enrich_PreserveExistingExpression tests that existing
// Expression licenses are preserved.
func TestCycloneDXEnricher_Enrich_PreserveExistingExpression(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1",
				"licenses": [
					{"expression": "Apache-2.0"}
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
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})
	licenses := comp["licenses"].([]interface{})
	lic := licenses[0].(map[string]interface{})

	if got := lic["expression"]; got != "Apache-2.0" {
		t.Errorf("license expression = %v, want Apache-2.0", got)
	}
}

// TestCycloneDXEnricher_Enrich_PreserveExistingLicenseID tests that existing
// License.ID is preserved.
func TestCycloneDXEnricher_Enrich_PreserveExistingLicenseID(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1",
				"licenses": [
					{"license": {"id": "BSD-3-Clause"}}
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
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})
	licenses := comp["licenses"].([]interface{})
	lic := licenses[0].(map[string]interface{})
	licObj := lic["license"].(map[string]interface{})

	if got := licObj["id"]; got != "BSD-3-Clause" {
		t.Errorf("license id = %v, want BSD-3-Clause", got)
	}
}

// TestCycloneDXEnricher_Enrich_PreserveExistingLicenseName tests that existing
// License.Name is preserved.
func TestCycloneDXEnricher_Enrich_PreserveExistingLicenseName(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1",
				"licenses": [
					{"license": {"name": "MIT License"}}
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
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})
	licenses := comp["licenses"].([]interface{})
	lic := licenses[0].(map[string]interface{})
	licObj := lic["license"].(map[string]interface{})

	if got := licObj["name"]; got != "MIT License" {
		t.Errorf("license name = %v, want MIT License", got)
	}
}

// TestCycloneDXEnricher_Enrich_EmptyBOM tests that empty BOMs are returned unchanged.
func TestCycloneDXEnricher_Enrich_EmptyBOM(t *testing.T) {
	t.Parallel()

	providerCalled := false
	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			providerCalled = true
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": []
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
		t.Error("Provider should not have been called for empty BOM")
	}

	// Verify result is unchanged
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	if len(bom["components"].([]interface{})) != 0 {
		t.Error("Expected empty components array in result")
	}
}

// TestCycloneDXEnricher_Enrich_MultipleComponents tests enrichment of multiple components.
func TestCycloneDXEnricher_Enrich_MultipleComponents(t *testing.T) {
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
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1"
			},
			{
				"type": "library",
				"name": "lodash",
				"purl": "pkg:npm/lodash@4.17.21"
			},
			{
				"type": "library",
				"name": "react",
				"purl": "pkg:npm/react@18.0.0"
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

	// Verify all components were enriched
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	if len(components) != 3 {
		t.Fatalf("Expected 3 components, got %d", len(components))
	}

	for i, c := range components {
		comp := c.(map[string]interface{})
		licenses := comp["licenses"].([]interface{})
		if len(licenses) != 1 {
			t.Errorf("Component %d: expected 1 license, got %d", i, len(licenses))
			continue
		}
		lic := licenses[0].(map[string]interface{})
		if got := lic["expression"]; got != "MIT" {
			t.Errorf("Component %d: expression = %v, want MIT", i, got)
		}
	}
}

// TestCycloneDXEnricher_Enrich_NilLicensesArray tests handling of components with nil licenses.
func TestCycloneDXEnricher_Enrich_NilLicensesArray(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1"
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

	// Verify licenses array was created and populated
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})
	licenses := comp["licenses"].([]interface{})

	if len(licenses) != 1 {
		t.Fatalf("Expected 1 license, got %d", len(licenses))
	}

	lic := licenses[0].(map[string]interface{})
	if got := lic["expression"]; got != "MIT" {
		t.Errorf("expression = %v, want MIT", got)
	}
}

// TestCycloneDXEnricher_Enrich_EmptyLicensesArray tests appending to empty licenses array.
func TestCycloneDXEnricher_Enrich_EmptyLicensesArray(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1",
				"licenses": []
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

	// Verify license was appended
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})
	licenses := comp["licenses"].([]interface{})

	if len(licenses) != 1 {
		t.Fatalf("Expected 1 license, got %d", len(licenses))
	}

	lic := licenses[0].(map[string]interface{})
	if got := lic["expression"]; got != "MIT" {
		t.Errorf("expression = %v, want MIT", got)
	}
}

// TestCycloneDXEnricher_Enrich_EmptyPURL tests handling of components with empty PURL.
func TestCycloneDXEnricher_Enrich_EmptyPURL(t *testing.T) {
	t.Parallel()

	callCount := 0
	provider := &mockProvider{
		getLicense: func(_ context.Context, purl string) (string, error) {
			callCount++
			if purl == "" {
				return "", errors.New("empty purl")
			}
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": ""
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

	// Provider should be called with empty purl
	if callCount != 1 {
		t.Errorf("Provider called %d times, want 1", callCount)
	}

	// Component should not be enriched due to provider error
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})

	if _, exists := comp["licenses"]; exists {
		t.Error("Component should not have licenses after provider error")
	}
}

// TestCycloneDXEnricher_Enrich_ProviderError tests that provider errors are logged and processing continues.
func TestCycloneDXEnricher_Enrich_ProviderError(t *testing.T) {
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
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "pkg1",
				"purl": "pkg:npm/pkg1@1.0.0"
			},
			{
				"type": "library",
				"name": "pkg2",
				"purl": "pkg:npm/pkg2@1.0.0"
			},
			{
				"type": "library",
				"name": "pkg3",
				"purl": "pkg:npm/pkg3@1.0.0"
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

	// All components should be attempted
	if callCount != 3 {
		t.Errorf("Provider called %d times, want 3", callCount)
	}

	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})

	// Components 1 and 3 should be enriched
	comp1 := components[0].(map[string]interface{})
	licenses1 := comp1["licenses"].([]interface{})
	if len(licenses1) != 1 {
		t.Errorf("Component 1: expected 1 license, got %d", len(licenses1))
	}

	comp3 := components[2].(map[string]interface{})
	licenses3 := comp3["licenses"].([]interface{})
	if len(licenses3) != 1 {
		t.Errorf("Component 3: expected 1 license, got %d", len(licenses3))
	}

	// Component 2 should not have license (provider error)
	comp2 := components[1].(map[string]interface{})
	if _, exists := comp2["licenses"]; exists {
		t.Error("Component 2 should not have licenses after provider error")
	}
}

// TestCycloneDXEnricher_Enrich_ProviderReturnsEmpty tests that empty license strings are skipped.
func TestCycloneDXEnricher_Enrich_ProviderReturnsEmpty(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			return "", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1"
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

	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})

	// License should not be set when provider returns empty string
	if lics, exists := comp["licenses"]; exists {
		if licenses, ok := lics.([]interface{}); ok && len(licenses) > 0 {
			t.Errorf("licenses should not be set when provider returns empty string, got %v", licenses)
		}
	}
}

// TestCycloneDXEnricher_Enrich_Parallelism tests different parallelism levels.
func TestCycloneDXEnricher_Enrich_Parallelism(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		parallelism int
	}{
		{"Single worker", 1},
		{"Multiple workers", 5},
		{"Zero defaults to 1", 0},
		{"Negative defaults to 1", -5},
		{"High parallelism", 100},
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
			e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

			// Create BOM with 10 components
			components := make([]string, 10)
			for i := range 10 {
				idx := string(rune('0' + i))
				components[i] = `{
					"type": "library",
					"name": "pkg` + idx + `",
					"purl": "pkg:npm/pkg` + idx + `@1.0.0"
				}`
			}

			input := []byte(`{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4",
				"components": [` + components[0])
			for i := 1; i < len(components); i++ {
				input = append(input, []byte(`,`+components[i])...)
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

			// Verify all components were enriched
			var bom map[string]interface{}
			err = json.Unmarshal(result, &bom)
			if err != nil {
				t.Fatalf("Failed to unmarshal result: %v", err)
			}

			comps := bom["components"].([]interface{})
			if len(comps) != 10 {
				t.Fatalf("Expected 10 components, got %d", len(comps))
			}

			for i, c := range comps {
				comp := c.(map[string]interface{})
				licenses := comp["licenses"].([]interface{})
				if len(licenses) != 1 {
					t.Errorf("Component %d: expected 1 license, got %d", i, len(licenses))
					continue
				}
				lic := licenses[0].(map[string]interface{})
				if got := lic["expression"]; got != "MIT" {
					t.Errorf("Component %d: expression = %v, want MIT", i, got)
				}
			}
		})
	}
}

// TestCycloneDXEnricher_Enrich_CacheHit tests that cache hits skip provider calls.
func TestCycloneDXEnricher_Enrich_CacheHit(t *testing.T) {
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

	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1"
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
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})
	licenses := comp["licenses"].([]interface{})
	lic := licenses[0].(map[string]interface{})

	if got := lic["expression"]; got != "Apache-2.0" {
		t.Errorf("expression = %v, want Apache-2.0 (from cache)", got)
	}
}

// TestCycloneDXEnricher_Enrich_CacheMiss tests that cache misses trigger provider calls.
func TestCycloneDXEnricher_Enrich_CacheMiss(t *testing.T) {
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

	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1"
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
	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})
	licenses := comp["licenses"].([]interface{})
	lic := licenses[0].(map[string]interface{})

	if got := lic["expression"]; got != "MIT" {
		t.Errorf("expression = %v, want MIT", got)
	}
}

// Cache errors are logged but don't fail enrichment - this is by design
// for resilience. The enricher continues processing other components.

// TestCycloneDXEnricher_Enrich_NilLogger tests that nil logger doesn't cause panics.
func TestCycloneDXEnricher_Enrich_NilLogger(t *testing.T) {
	t.Parallel()

	provider := &mockProvider{
		getLicense: func(_ context.Context, _ string) (string, error) {
			return "MIT", nil
		},
	}

	c := &mockCache{}
	e := enricher.NewCycloneDXEnricher(provider, c, 24*time.Hour)

	input := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"type": "library",
				"name": "express",
				"purl": "pkg:npm/express@4.17.1"
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

	var bom map[string]interface{}
	err = json.Unmarshal(result, &bom)
	if err != nil {
		t.Fatalf("Failed to unmarshal result: %v", err)
	}

	components := bom["components"].([]interface{})
	comp := components[0].(map[string]interface{})
	licenses := comp["licenses"].([]interface{})
	lic := licenses[0].(map[string]interface{})

	if got := lic["expression"]; got != "MIT" {
		t.Errorf("expression = %v, want MIT", got)
	}
}

// Context cancellation stops individual provider calls but doesn't fail the
// overall enrichment - errors are logged. This is by design for resilience.
