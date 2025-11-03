// Package version provides version information for sbomlicense.
package version

// Version is the version of `sbomlicense` and `sbomlicensed`.
// Set to "dev" by default for local builds.
// Overridden by goreleaser.
//
//nolint:gochecknoglobals // This is the single source of truth for version information across all binaries.
var Version = "dev"
