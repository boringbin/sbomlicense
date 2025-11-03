package enricher_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/boringbin/sbomlicense/internal/enricher"
)

// TestUnwrapGitHubSBOM tests the UnwrapGitHubSBOM function.
func TestUnwrapGitHubSBOM(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		want        string
		wantErr     bool
		errContains string
	}{
		{
			name:  "unwraps GitHub wrapped SBOM",
			input: `{"sbom": {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}}`,
			want:  `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}`,
		},
		{
			name:  "returns original for non-wrapped SBOM",
			input: `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}`,
			want:  `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}`,
		},
		{
			name:  "handles empty SBOM object in wrapper",
			input: `{"sbom": {}}`,
			want:  `{}`,
		},
		{
			name:        "returns error for invalid JSON",
			input:       `{invalid json}`,
			wantErr:     true,
			errContains: "failed to parse JSON",
		},
		{
			name:  "handles SBOM with nested objects",
			input: `{"sbom": {"packages": [{"name": "test"}]}}`,
			want:  `{"packages": [{"name": "test"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := enricher.UnwrapGitHubSBOM([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Errorf("unwrapGitHubSBOM() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("unwrapGitHubSBOM() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("unwrapGitHubSBOM() unexpected error: %v", err)
				return
			}

			// Compare as JSON to ignore whitespace differences
			var gotJSON, wantJSON interface{}
			if unmarshalErr := json.Unmarshal(got, &gotJSON); unmarshalErr != nil {
				t.Errorf("unwrapGitHubSBOM() returned invalid JSON: %v", unmarshalErr)
				return
			}
			if unmarshalErr := json.Unmarshal([]byte(tt.want), &wantJSON); unmarshalErr != nil {
				t.Fatalf("test case has invalid JSON in want: %v", unmarshalErr)
			}

			gotStr, _ := json.Marshal(gotJSON)
			wantStr, _ := json.Marshal(wantJSON)

			if string(gotStr) != string(wantStr) {
				t.Errorf("unwrapGitHubSBOM() = %s, want %s", gotStr, wantStr)
			}
		})
	}
}

// TestParseSBOMFile tests the ParseSBOMFile function.
func TestParseSBOMFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		input        string
		wantPackages int
		wantVersion  string
		wantErr      bool
		errContains  string
	}{
		{
			name: "parses valid SPDX document",
			input: `{
				"spdxVersion": "SPDX-2.3",
				"SPDXID": "SPDXRef-DOCUMENT",
				"packages": [
					{
						"SPDXID": "SPDXRef-Package",
						"name": "express",
						"versionInfo": "4.18.2"
					}
				]
			}`,
			wantPackages: 1,
			wantVersion:  "SPDX-2.3",
		},
		{
			name: "parses GitHub wrapped SBOM",
			input: `{
				"sbom": {
					"spdxVersion": "SPDX-2.3",
					"SPDXID": "SPDXRef-DOCUMENT",
					"packages": [
						{
							"SPDXID": "SPDXRef-Package-1",
							"name": "pkg1"
						},
						{
							"SPDXID": "SPDXRef-Package-2",
							"name": "pkg2"
						}
					]
				}
			}`,
			wantPackages: 2,
			wantVersion:  "SPDX-2.3",
		},
		{
			name: "handles empty packages array",
			input: `{
				"spdxVersion": "SPDX-2.3",
				"SPDXID": "SPDXRef-DOCUMENT",
				"packages": []
			}`,
			wantPackages: 0,
			wantVersion:  "SPDX-2.3",
		},
		{
			name:        "returns error for invalid JSON",
			input:       `{invalid json`,
			wantErr:     true,
			errContains: "failed to parse",
		},
		{
			name:        "returns error for malformed wrapped SBOM",
			input:       `{"sbom": "not an object"}`,
			wantErr:     true,
			errContains: "failed to parse SBOM JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := enricher.ParseSBOMFile([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseSBOMFile() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("parseSBOMFile() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("parseSBOMFile() unexpected error: %v", err)
				return
			}

			if len(got.Packages) != tt.wantPackages {
				t.Errorf("parseSBOMFile() got %d packages, want %d", len(got.Packages), tt.wantPackages)
			}

			if got.SPDXVersion != tt.wantVersion {
				t.Errorf("parseSBOMFile() version = %s, want %s", got.SPDXVersion, tt.wantVersion)
			}
		})
	}
}

// TestParseSBOMFile_WithRealTestdata tests the ParseSBOMFile function with real testdata.
func TestParseSBOMFile_WithRealTestdata(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../testdata/example-spdx.json")
	if err != nil {
		t.Skipf("skipping test: testdata not available: %v", err)
	}

	doc, err := enricher.ParseSBOMFile(data)
	if err != nil {
		t.Fatalf("parseSBOMFile() failed with testdata: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("parseSBOMFile() version = %s, want SPDX-2.3", doc.SPDXVersion)
	}

	if len(doc.Packages) == 0 {
		t.Error("parseSBOMFile() returned no packages from testdata")
	}
}

// TestGetSPDXPackagePurl tests the GetSPDXPackagePurl function.
func TestGetSPDXPackagePurl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		pkg         enricher.Package
		want        string
		wantErr     bool
		errContains string
	}{
		{
			name: "extracts purl from external refs",
			pkg: enricher.Package{
				SPDXID: "SPDXRef-Package",
				Name:   "express",
				ExternalRefs: []enricher.ExternalRef{
					{
						ReferenceCategory: "PACKAGE-MANAGER",
						ReferenceType:     "purl",
						ReferenceLocator:  "pkg:npm/express@4.18.2",
					},
				},
			},
			want: "pkg:npm/express@4.18.2",
		},
		{
			name: "finds purl among multiple refs",
			pkg: enricher.Package{
				SPDXID: "SPDXRef-Package",
				Name:   "test",
				ExternalRefs: []enricher.ExternalRef{
					{
						ReferenceCategory: "OTHER",
						ReferenceType:     "website",
						ReferenceLocator:  "https://example.com",
					},
					{
						ReferenceCategory: "PACKAGE-MANAGER",
						ReferenceType:     "purl",
						ReferenceLocator:  "pkg:golang/github.com/test/pkg@v1.0.0",
					},
					{
						ReferenceCategory: "SECURITY",
						ReferenceType:     "cpe23Type",
						ReferenceLocator:  "cpe:2.3:a:test:pkg:1.0.0",
					},
				},
			},
			want: "pkg:golang/github.com/test/pkg@v1.0.0",
		},
		{
			name: "returns error when no purl found",
			pkg: enricher.Package{
				SPDXID: "SPDXRef-Package",
				Name:   "test",
				ExternalRefs: []enricher.ExternalRef{
					{
						ReferenceCategory: "OTHER",
						ReferenceType:     "website",
						ReferenceLocator:  "https://example.com",
					},
				},
			},
			wantErr:     true,
			errContains: "no PURL found",
		},
		{
			name: "returns error when external refs empty",
			pkg: enricher.Package{
				SPDXID:       "SPDXRef-Package",
				Name:         "test",
				ExternalRefs: []enricher.ExternalRef{},
			},
			wantErr:     true,
			errContains: "no PURL found",
		},
		{
			name: "handles package with nil external refs",
			pkg: enricher.Package{
				SPDXID:       "SPDXRef-Package",
				Name:         "test",
				ExternalRefs: nil,
			},
			wantErr:     true,
			errContains: "no PURL found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := enricher.GetSPDXPackagePurl(&tt.pkg)

			if tt.wantErr {
				if err == nil {
					t.Errorf("getSPDXPackagePurl() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("getSPDXPackagePurl() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("getSPDXPackagePurl() unexpected error: %v", err)
				return
			}

			if got != tt.want {
				t.Errorf("getSPDXPackagePurl() = %s, want %s", got, tt.want)
			}
		})
	}
}
