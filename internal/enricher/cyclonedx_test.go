package enricher_test

import (
	"os"
	"strings"
	"testing"

	"github.com/boringbin/sbomlicense/internal/enricher"
)

// TestParseCycloneDXFile tests the ParseCycloneDXFile function.
func TestParseCycloneDXFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          string
		wantComponents int
		wantBOMFormat  string
		wantErr        bool
		errContains    string
	}{
		{
			name: "parses valid CycloneDX BOM",
			input: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4",
				"components": [
					{
						"bom-ref": "pkg:npm/express@4.18.2",
						"name": "express",
						"version": "4.18.2",
						"purl": "pkg:npm/express@4.18.2"
					}
				]
			}`,
			wantComponents: 1,
			wantBOMFormat:  "CycloneDX",
		},
		{
			name: "parses BOM with multiple components",
			input: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.5",
				"components": [
					{
						"bom-ref": "pkg:npm/pkg1@1.0.0",
						"name": "pkg1",
						"purl": "pkg:npm/pkg1@1.0.0"
					},
					{
						"bom-ref": "pkg:npm/pkg2@2.0.0",
						"name": "pkg2",
						"purl": "pkg:npm/pkg2@2.0.0"
					},
					{
						"bom-ref": "pkg:npm/pkg3@3.0.0",
						"name": "pkg3",
						"purl": "pkg:npm/pkg3@3.0.0"
					}
				]
			}`,
			wantComponents: 3,
			wantBOMFormat:  "CycloneDX",
		},
		{
			name: "handles empty components array",
			input: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4",
				"components": []
			}`,
			wantComponents: 0,
			wantBOMFormat:  "CycloneDX",
		},
		{
			name: "handles BOM with no components field",
			input: `{
				"bomFormat": "CycloneDX",
				"specVersion": "1.4"
			}`,
			wantComponents: 0,
			wantBOMFormat:  "CycloneDX",
		},
		{
			name:        "returns error for invalid JSON",
			input:       `{invalid json`,
			wantErr:     true,
			errContains: "failed to parse CycloneDX JSON",
		},
		{
			name:        "returns error for malformed BOM",
			input:       `{"bomFormat": 123}`,
			wantErr:     true,
			errContains: "failed to parse CycloneDX JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := enricher.ParseCycloneDXFile([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCycloneDXFile() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ParseCycloneDXFile() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseCycloneDXFile() unexpected error: %v", err)
				return
			}

			if len(got.Components) != tt.wantComponents {
				t.Errorf("ParseCycloneDXFile() got %d components, want %d", len(got.Components), tt.wantComponents)
			}

			if got.BOMFormat != tt.wantBOMFormat {
				t.Errorf("ParseCycloneDXFile() bomFormat = %s, want %s", got.BOMFormat, tt.wantBOMFormat)
			}
		})
	}
}

// TestParseCycloneDXFile_WithRealTestdata tests the ParseCycloneDXFile function with real testdata.
func TestParseCycloneDXFile_WithRealTestdata(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../testdata/example-cyclonedx.json")
	if err != nil {
		t.Skipf("skipping test: testdata not available: %v", err)
	}

	bom, err := enricher.ParseCycloneDXFile(data)
	if err != nil {
		t.Fatalf("ParseCycloneDXFile() failed with testdata: %v", err)
	}

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("ParseCycloneDXFile() bomFormat = %s, want CycloneDX", bom.BOMFormat)
	}

	if len(bom.Components) == 0 {
		t.Error("ParseCycloneDXFile() returned no components from testdata")
	}
}

// TestGetCycloneDXComponentPurl tests the GetCycloneDXComponentPurl function.
func TestGetCycloneDXComponentPurl(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		component enricher.Component
		want      string
	}{
		{
			name: "returns purl from component",
			component: enricher.Component{
				BOMRef:  "pkg:npm/express@4.18.2",
				Name:    "express",
				Version: "4.18.2",
				Purl:    "pkg:npm/express@4.18.2",
			},
			want: "pkg:npm/express@4.18.2",
		},
		{
			name: "returns empty string when purl is empty",
			component: enricher.Component{
				BOMRef:  "some-ref",
				Name:    "test",
				Version: "1.0.0",
				Purl:    "",
			},
			want: "",
		},
		{
			name: "handles golang purl",
			component: enricher.Component{
				BOMRef:  "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
				Name:    "gin",
				Version: "v1.9.1",
				Purl:    "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			},
			want: "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
		},
		{
			name: "handles maven purl",
			component: enricher.Component{
				BOMRef:  "pkg:maven/org.springframework/spring-core@6.0.11",
				Name:    "spring-core",
				Version: "6.0.11",
				Purl:    "pkg:maven/org.springframework/spring-core@6.0.11",
			},
			want: "pkg:maven/org.springframework/spring-core@6.0.11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := enricher.GetCycloneDXComponentPurl(&tt.component)

			if got != tt.want {
				t.Errorf("GetCycloneDXComponentPurl() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestHasComponentLicense tests the HasComponentLicense function.
func TestHasComponentLicense(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		component enricher.Component
		want      bool
	}{
		{
			name: "returns false for component with no licenses",
			component: enricher.Component{
				Name:     "test",
				Licenses: nil,
			},
			want: false,
		},
		{
			name: "returns false for component with empty licenses array",
			component: enricher.Component{
				Name:     "test",
				Licenses: []enricher.LicenseChoice{},
			},
			want: false,
		},
		{
			name: "returns true for component with expression license",
			component: enricher.Component{
				Name: "test",
				Licenses: []enricher.LicenseChoice{
					{Expression: "MIT"},
				},
			},
			want: true,
		},
		{
			name: "returns true for component with license ID",
			component: enricher.Component{
				Name: "test",
				Licenses: []enricher.LicenseChoice{
					{
						License: &enricher.License{
							ID: "Apache-2.0",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "returns true for component with license name",
			component: enricher.Component{
				Name: "test",
				Licenses: []enricher.LicenseChoice{
					{
						License: &enricher.License{
							Name: "MIT License",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "returns true for component with license expression in object",
			component: enricher.Component{
				Name: "test",
				Licenses: []enricher.LicenseChoice{
					{
						License: &enricher.License{
							Expression: "MIT OR Apache-2.0",
						},
					},
				},
			},
			want: true,
		},
		{
			name: "returns false for component with empty license object",
			component: enricher.Component{
				Name: "test",
				Licenses: []enricher.LicenseChoice{
					{
						License: &enricher.License{},
					},
				},
			},
			want: false,
		},
		{
			name: "returns true when any license choice has value",
			component: enricher.Component{
				Name: "test",
				Licenses: []enricher.LicenseChoice{
					{
						License: &enricher.License{},
					},
					{
						Expression: "MIT",
					},
				},
			},
			want: true,
		},
		{
			name: "returns false for multiple empty license choices",
			component: enricher.Component{
				Name: "test",
				Licenses: []enricher.LicenseChoice{
					{
						License: &enricher.License{},
					},
					{
						Expression: "",
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := enricher.HasComponentLicense(&tt.component)

			if got != tt.want {
				t.Errorf("HasComponentLicense() = %v, want %v", got, tt.want)
			}
		})
	}
}
