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
//
//nolint:gocognit // Complexity is inherent to parallel enrichment with worker pool pattern
func (s *SPDXEnricher) Enrich(ctx context.Context, opts Options) ([]byte, error) {
	// Parse the SBOM file into an SPDX document
	doc, err := ParseSBOMFile(opts.SBOM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SBOM file: %w", err)
	}

	if len(doc.Packages) == 0 {
		// No packages to enrich, return original SBOM
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

	// Create a channel for packages to enrich
	type job struct {
		pkg  *Package
		purl string
	}

	jobs := make(chan job, len(doc.Packages))
	var wg sync.WaitGroup

	// Spawn workers
	for range parallelism {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				// Check if package already has a license
				// Try LicenseConcluded first, fallback to LicenseDeclared
				hasLicense := (j.pkg.LicenseConcluded != "" &&
					j.pkg.LicenseConcluded != spdxLicenseNone &&
					j.pkg.LicenseConcluded != spdxLicenseNoAssertion) ||
					(j.pkg.LicenseDeclared != "" &&
						j.pkg.LicenseDeclared != spdxLicenseNone &&
						j.pkg.LicenseDeclared != spdxLicenseNoAssertion)

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
					// Log error but continue processing other packages
					logger.ErrorContext(ctx, "failed to get license for package",
						"purl", j.purl,
						"spdx_id", j.pkg.SPDXID,
						"error", licErr)
					continue
				}
				if lic != "" {
					// Set LicenseConcluded (primary field)
					j.pkg.LicenseConcluded = lic
					// Also set LicenseDeclared if it's empty
					if j.pkg.LicenseDeclared == "" ||
						j.pkg.LicenseDeclared == spdxLicenseNone ||
						j.pkg.LicenseDeclared == spdxLicenseNoAssertion {
						j.pkg.LicenseDeclared = lic
					}
				}
			}
		}()
	}

	// Queue all packages
	for i := range doc.Packages {
		pkg := &doc.Packages[i]
		// Get the purl for the package if it exists
		purl, purlErr := GetSPDXPackagePurl(pkg)
		if purlErr != nil {
			// Log error but continue processing other packages
			logger.ErrorContext(ctx, "failed to get purl for package",
				"spdx_id", pkg.SPDXID,
				"error", purlErr)
			continue
		}

		jobs <- job{pkg: pkg, purl: purl}
	}

	// Close the channel and wait for workers to finish
	close(jobs)
	wg.Wait()

	return json.Marshal(doc)
}
