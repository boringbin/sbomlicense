package sbom_test

import (
	"os"
	"testing"

	"github.com/boringbin/sbomlicense/internal/sbom"
)

// TestDetectFormat_SPDX tests detection of standard SPDX format.
func TestDetectFormat_SPDX(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../testdata/example-spdx.json")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	format, err := sbom.DetectFormat(data)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}

	if format != "SPDX-2.3" {
		t.Errorf("Expected format 'SPDX-2.3', got '%s'", format)
	}
}

// TestDetectFormat_GitHubWrappedSPDX tests detection of GitHub-wrapped SPDX format.
func TestDetectFormat_GitHubWrappedSPDX(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../testdata/github-wrapped-spdx.json")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	format, err := sbom.DetectFormat(data)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}

	if format != "SPDX-2.3" {
		t.Errorf("Expected format 'SPDX-2.3', got '%s'", format)
	}
}

// TestDetectFormat_CycloneDX tests detection of CycloneDX format.
func TestDetectFormat_CycloneDX(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../testdata/example-cyclonedx.json")
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	format, err := sbom.DetectFormat(data)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}

	if format != "CycloneDX-1.4" {
		t.Errorf("Expected format 'CycloneDX-1.4', got '%s'", format)
	}
}

// TestDetectFormat_InvalidJSON tests that invalid JSON returns an error.
func TestDetectFormat_InvalidJSON(t *testing.T) {
	t.Parallel()

	invalidData := []byte("not valid json")

	_, err := sbom.DetectFormat(invalidData)
	if err == nil {
		t.Fatal("Expected error for invalid JSON, got nil")
	}
}

// TestDetectFormat_UnknownFormat tests that unknown format returns an error.
func TestDetectFormat_UnknownFormat(t *testing.T) {
	t.Parallel()

	unknownData := []byte(`{"unknown": "format"}`)

	_, err := sbom.DetectFormat(unknownData)
	if err == nil {
		t.Fatal("Expected error for unknown format, got nil")
	}
}

// TestDetectFormat_SPDXWithID tests SPDX detection via SPDXID when no version field.
func TestDetectFormat_SPDXWithID(t *testing.T) {
	t.Parallel()

	data := []byte(`{"SPDXID": "SPDXRef-DOCUMENT"}`)

	format, err := sbom.DetectFormat(data)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}

	if format != "SPDX-2.3" {
		t.Errorf("Expected format 'SPDX-2.3', got '%s'", format)
	}
}

// TestDetectFormat_GitHubWrappedSPDXWithID tests GitHub-wrapped SPDX detection via SPDXID.
func TestDetectFormat_GitHubWrappedSPDXWithID(t *testing.T) {
	t.Parallel()

	data := []byte(`{"sbom": {"SPDXID": "SPDXRef-DOCUMENT"}}`)

	format, err := sbom.DetectFormat(data)
	if err != nil {
		t.Fatalf("DetectFormat failed: %v", err)
	}

	if format != "SPDX-2.3" {
		t.Errorf("Expected format 'SPDX-2.3', got '%s'", format)
	}
}

// TestDetectFormat_GitHubWrappedEmptySBOM tests GitHub wrapper with empty SBOM.
func TestDetectFormat_GitHubWrappedEmptySBOM(t *testing.T) {
	t.Parallel()

	data := []byte(`{"sbom": {}}`)

	_, err := sbom.DetectFormat(data)
	if err == nil {
		t.Fatal("Expected error for empty SBOM, got nil")
	}
}
