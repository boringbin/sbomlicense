package enricher

import (
	"context"
	"encoding/json"
	"fmt"
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

// GetPurl extracts the purl from the CycloneDX component.
func (c *Component) GetPurl() (string, error) {
	return GetCycloneDXComponentPurl(c), nil
}

// HasLicense returns true if the component already has license information.
func (c *Component) HasLicense() bool {
	return HasComponentLicense(c)
}

// SetLicense updates the component with the provided license string.
// Adds license using Expression format (simpler and more common).
func (c *Component) SetLicense(license string) {
	c.Licenses = append(c.Licenses, LicenseChoice{
		Expression: license,
	})
}

// GetLogID returns the BOM reference for logging purposes.
func (c *Component) GetLogID() string {
	return c.BOMRef
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
func (s *CycloneDXEnricher) Enrich(ctx context.Context, opts Options) ([]byte, error) {
	// Parse the SBOM file into a CycloneDX BOM
	bom, err := ParseCycloneDXFile(opts.SBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SBOM file: %w", err)
	}

	// Convert []Component to []*Component for interface satisfaction
	components := make([]*Component, len(bom.Components))
	for i := range bom.Components {
		components[i] = &bom.Components[i]
	}

	// Enrich and marshal using common helper
	return enrichDocument(
		ctx,
		opts,
		bom,
		components,
		s.provider,
		s.cache,
		s.cacheTTL,
		func(b *BOM) ([]byte, error) {
			return json.Marshal(b)
		},
	)
}
