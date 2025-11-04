package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/provider"
)

const (
	// spdxLicenseNone represents the NONE value in SPDX license fields.
	spdxLicenseNone = "NONE"
	// spdxLicenseNoAssertion represents the NOASSERTION value in SPDX license fields.
	spdxLicenseNoAssertion = "NOASSERTION"
)

// See https://github.com/spdx/tools-golang

// Document represents a minimal SPDX document with only the fields we need.
type Document struct {
	SPDXVersion string    `json:"spdxVersion"`
	SPDXID      string    `json:"SPDXID"`
	Packages    []Package `json:"packages"`
}

// Package represents a minimal SPDX package with only the fields we need.
type Package struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	VersionInfo      string        `json:"versionInfo"`
	Homepage         string        `json:"homepage"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	ExternalRefs     []ExternalRef `json:"externalRefs"`
}

// ExternalRef represents an external reference (like purl).
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// GetPurl extracts the purl from the SPDX package's external references.
func (p *Package) GetPurl() (string, error) {
	return GetSPDXPackagePurl(p)
}

// HasLicense returns true if the package already has license information.
// Checks both LicenseConcluded and LicenseDeclared fields.
func (p *Package) HasLicense() bool {
	return (p.LicenseConcluded != "" &&
		p.LicenseConcluded != spdxLicenseNone &&
		p.LicenseConcluded != spdxLicenseNoAssertion) ||
		(p.LicenseDeclared != "" &&
			p.LicenseDeclared != spdxLicenseNone &&
			p.LicenseDeclared != spdxLicenseNoAssertion)
}

// SetLicense updates the package with the provided license string.
// Sets LicenseConcluded as the primary field and also updates LicenseDeclared if it's empty.
func (p *Package) SetLicense(license string) {
	// Set LicenseConcluded (primary field)
	p.LicenseConcluded = license
	// Also set LicenseDeclared if it's empty
	if p.LicenseDeclared == "" ||
		p.LicenseDeclared == spdxLicenseNone ||
		p.LicenseDeclared == spdxLicenseNoAssertion {
		p.LicenseDeclared = license
	}
}

// GetLogID returns the SPDX ID for logging purposes.
func (p *Package) GetLogID() string {
	return p.SPDXID
}

// UnwrapGitHubSBOM checks if the data is wrapped in GitHub's {"sbom": {...}} format and returns the unwrapped SPDX
// data if so, or the original data otherwise.
func UnwrapGitHubSBOM(data []byte) ([]byte, error) {
	// Try to unmarshal as a map to check for GitHub wrapper
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	// Check for GitHub wrapper format: {"sbom": {...}}
	if sbomData, hasWrapper := wrapper["sbom"]; hasWrapper {
		return sbomData, nil
	}

	// Not wrapped, return original data
	return data, nil
}

// ParseSBOMFile parses the SBOM file into an SPDX document.
func ParseSBOMFile(sbom []byte) (*Document, error) {
	// Unwrap GitHub format if present
	unwrapped, err := UnwrapGitHubSBOM(sbom)
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap GitHub SBOM: %w", err)
	}

	// Parse the JSON into an SPDX document
	var doc Document
	if unmarshalErr := json.Unmarshal(unwrapped, &doc); unmarshalErr != nil {
		return nil, fmt.Errorf("failed to parse SBOM JSON: %w", unmarshalErr)
	}

	return &doc, nil
}

// GetSPDXPackagePurl extracts the purl from the SPDX package.
func GetSPDXPackagePurl(pkg *Package) (string, error) {
	// Extract PURL from external references
	for _, ref := range pkg.ExternalRefs {
		if ref.ReferenceType == "purl" {
			return ref.ReferenceLocator, nil
		}
	}

	return "", fmt.Errorf("no PURL found for package with SPDX ID %s", pkg.SPDXID)
}

// SPDXEnricher is the service for enriching SPDX SBOMs with license information.
type SPDXEnricher struct {
	provider provider.Provider
	cache    cache.Cache
	cacheTTL time.Duration
}

var _ Enricher = (*SPDXEnricher)(nil)

// NewSPDXEnricher creates a new SPDXEnricher.
func NewSPDXEnricher(provider provider.Provider, cache cache.Cache, cacheTTL time.Duration) *SPDXEnricher {
	return &SPDXEnricher{
		provider: provider,
		cache:    cache,
		cacheTTL: cacheTTL,
	}
}

// Enrich enriches the SPDX SBOM with license information.
func (s *SPDXEnricher) Enrich(ctx context.Context, opts Options) ([]byte, error) {
	// Parse the SBOM file into an SPDX document
	doc, err := ParseSBOMFile(opts.SBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SBOM file: %w", err)
	}

	// Convert []Package to []*Package for interface satisfaction
	pkgs := make([]*Package, len(doc.Packages))
	for i := range doc.Packages {
		pkgs[i] = &doc.Packages[i]
	}

	// Enrich and marshal using common helper
	return enrichDocument(
		ctx,
		opts,
		doc,
		pkgs,
		s.provider,
		s.cache,
		s.cacheTTL,
		func(d *Document) ([]byte, error) {
			return json.Marshal(d)
		},
	)
}
