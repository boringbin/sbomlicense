package sbom

import (
	"encoding/json"
	"errors"
	"fmt"
)

// DetectFormat analyzes the SBOM data and returns the detected format string.
// It returns format strings like "SPDX-2.3" or "CycloneDX-1.4" based on format-specific markers in the JSON data.
// It supports both standard formats and GitHub-wrapped formats (e.g., {"sbom": {...}}).
func DetectFormat(data []byte) (string, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}

	// Check for GitHub wrapper format and unwrap if present
	if sbomData, hasWrapper := raw["sbom"]; hasWrapper {
		if sbomMap, ok := sbomData.(map[string]interface{}); ok {
			raw = sbomMap
		}
	}

	// Check for SPDX markers
	if spdxVersion, ok := raw["spdxVersion"].(string); ok {
		return spdxVersion, nil
	}
	if spdxID, ok := raw["SPDXID"].(string); ok && spdxID != "" {
		// Fallback to default SPDX version if SPDXID is present but no version field
		return "SPDX-2.3", nil
	}

	// Check for CycloneDX markers
	if bomFormat, ok := raw["bomFormat"].(string); ok && bomFormat == "CycloneDX" {
		if specVersion, versionOk := raw["specVersion"].(string); versionOk {
			return fmt.Sprintf("CycloneDX-%s", specVersion), nil
		}
		// Default to CycloneDX 1.4 if no version specified
		return "CycloneDX-1.4", nil
	}

	return "", errors.New("unknown SBOM format: could not detect SPDX or CycloneDX markers")
}
