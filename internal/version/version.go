// Package version provides version information for sbomlicense.
package version

// Version is the version of `sbomlicense` and `sbomlicensed`.
// Set to "dev" by default for local builds.
// Overridden by goreleaser.
var version = "dev"

// Get returns the version of `sbomlicense` and `sbomlicensed`.
func Get() string {
	return version
}
