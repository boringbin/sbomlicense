package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/provider"
)

// See https://github.com/CycloneDX/cyclonedx-go

// BOM represents a minimal CycloneDX Bill of Materials with only the fields we need.
type BOM struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Components  []Component `json:"components,omitempty"`
}

// Component represents a minimal CycloneDX component with only the fields we need.
type Component struct {
	BOMRef             string              `json:"bom-ref"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	Purl               string              `json:"purl"`
	Licenses           Licenses            `json:"licenses,omitempty"`
	ExternalReferences []ExternalReference `json:"externalReferences"`
}

// ExternalReference represents an external reference with a URL and type.
type ExternalReference struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

// Licenses represents the licenses field which can be structured in different ways.
type Licenses []LicenseChoice

// LicenseChoice represents a single license choice.
type LicenseChoice struct {
	License    *License `json:"license,omitempty"`
	Expression string   `json:"expression,omitempty"`
}

// License represents a license with various identification methods.
type License struct {
	ID         string       `json:"id,omitempty"`
	Name       string       `json:"name,omitempty"`
	Expression string       `json:"expression,omitempty"`
	Text       *LicenseText `json:"text,omitempty"`
}

// LicenseText represents license text content.
type LicenseText struct {
	Content string `json:"content"`
}

// ParseCycloneDXFile parses the CycloneDX file into a CycloneDX BOM.
func ParseCycloneDXFile(data []byte) (*BOM, error) {
	// Parse the JSON into a CycloneDX BOM
	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("failed to parse CycloneDX JSON: %w", err)
	}
	return &bom, nil
}

// GetCycloneDXComponentPurl extracts the purl from the CycloneDX component.
func GetCycloneDXComponentPurl(component *Component) string {
	return component.Purl
}

// HasComponentLicense checks if a component already has a license in any format.
func HasComponentLicense(component *Component) bool {
	if len(component.Licenses) == 0 {
		return false
	}

	// Check if any license choice has a non-empty value
	for _, choice := range component.Licenses {
		// Check for expression format
		if choice.Expression != "" {
			return true
		}
		// Check for license object format
		if choice.License != nil {
			if choice.License.ID != "" ||
				choice.License.Name != "" ||
				choice.License.Expression != "" {
				return true
			}
		}
	}

	return false
}

// CycloneDXEnricher is the service for enriching CycloneDX SBOMs with license information.
type CycloneDXEnricher struct {
	provider provider.Provider
	cache    cache.Cache
	cacheTTL time.Duration
}

var _ Enricher = (*CycloneDXEnricher)(nil)

// NewCycloneDXEnricher creates a new CycloneDXEnricher.
func NewCycloneDXEnricher(
	provider provider.Provider,
	cache cache.Cache,
	cacheTTL time.Duration,
) *CycloneDXEnricher {
	return &CycloneDXEnricher{
		provider: provider,
		cache:    cache,
		cacheTTL: cacheTTL,
	}
}

// Enrich enriches the CycloneDX SBOM with license information.
//
//nolint:gocognit // Complexity is inherent to parallel enrichment with worker pool pattern
func (s *CycloneDXEnricher) Enrich(ctx context.Context, opts Options) ([]byte, error) {
	// Parse the SBOM file into a CycloneDX BOM
	bom, err := ParseCycloneDXFile(opts.SBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SBOM file: %w", err)
	}

	if len(bom.Components) == 0 {
		// No components to enrich, return original SBOM
		return opts.SBOM, nil
	}

	// Determine parallelism
	parallelism := opts.Parallelism
	if parallelism <= 0 {
		parallelism = 1
	}

	// Use provided logger or create a no-op logger
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Create a channel for components to enrich
	type job struct {
		component *Component
		purl      string
	}

	jobs := make(chan job, len(bom.Components))
	var wg sync.WaitGroup

	// Spawn workers
	for range parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Check if component already has licenses (in any format)
				hasLicense := HasComponentLicense(j.component)

				if hasLicense {
					continue
				}

				// Get the license from the service
				lic, licErr := provider.Get(ctx, provider.GetOptions{
					Purl:     j.purl,
					Provider: s.provider,
					Cache:    s.cache,
					CacheTTL: s.cacheTTL,
				})
				if licErr != nil {
					// Log error but continue processing other components
					logger.ErrorContext(ctx, "failed to get license for component",
						"purl", j.purl,
						"bom_ref", j.component.BOMRef,
						"error", licErr)
					continue
				}
				if lic != "" {
					// Add license using Expression format (simpler and more common)
					j.component.Licenses = append(j.component.Licenses, LicenseChoice{
						Expression: lic,
					})
				}
			}
		}()
	}

	// Queue all components
	for i := range bom.Components {
		component := &bom.Components[i]
		// Get the purl for the component if it exists
		purl := GetCycloneDXComponentPurl(component)

		jobs <- job{component: component, purl: purl}
	}

	// Close the channel and wait for workers to finish
	close(jobs)
	wg.Wait()

	return json.Marshal(bom)
}
