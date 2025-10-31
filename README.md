# sbomlicense

Two tools, `sbomlicense` and `sbomlicensed`, that enrich SBOM files with license information.

Uses the [Ecosyste.ms](https://ecosyste.ms/) API to get information about a package.

## Usage

```text
Usage: sbomlicense [OPTIONS] <sbom-file>

Enrich SBOM files with license information.

The enriched SBOM is written to stdout.

This CLI tool is designed for local, one-off enrichment with in-memory caching.
For high-volume or distributed use cases, see 'sbomlicensed' daemon.

Arguments:
  sbom-file           Path to a single SBOM file (SPDX or CycloneDX JSON format)

Options:
  -email string
        Email for polite pool (optional)
  -parallel int
        Number of concurrent workers for enrichment (default 10)
  -timeout duration
        Timeout for enrichment operation (default 5m0s)
  -v    Verbose output (debug mode)
  -version
        Show version and exit
```

```text
Usage of sbomlicensed:
  -cache-path string
        Path to bbolt cache database file (default "./data/cache.db")
  -cache-ttl duration
        Cache TTL for enrichment results
  -email string
        Email for polite pool (required)
  -parallel int
        Default number of concurrent workers for enrichment (default 20)
  -port int
        HTTP port to listen on (default 8080)
  -v    Verbose output (debug mode)
```

## License

[MIT](LICENSE)
