package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/enricher"
	"github.com/boringbin/sbomlicense/internal/provider"
	"github.com/boringbin/sbomlicense/internal/sbom"
	"github.com/boringbin/sbomlicense/internal/version"
)

const (
	// cacheTTL is the time-to-live duration for the cache.
	// This is disabled for the CLI too, since it's not persistent.
	cacheTTL = 0 * time.Hour
	// exitSuccess is the exit code for success.
	exitSuccess = 0
	// exitInvalidArgs is the exit code for invalid arguments.
	exitInvalidArgs = 1
	// exitRuntimeError is the exit code for runtime error.
	exitRuntimeError = 3
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		verbose     = flag.Bool("v", false, "Verbose output (debug mode)")
		showVersion = flag.Bool("version", false, "Show version and exit")
		parallel    = flag.Int("parallel", 10, "Number of concurrent workers for enrichment")
		email       = flag.String("email", "", "Email for polite pool (optional)")
		timeout     = flag.Duration("timeout", 5*time.Minute, "Timeout for enrichment operation")
	)

	// Customize usage message
	flag.CommandLine.Usage = printUsage

	flag.Parse()

	// Handle version flag
	if *showVersion {
		fmt.Fprintf(os.Stdout, "sbomlicense version %s\n", version.Get())
		return exitSuccess
	}

	// Setup logger based on verbose flag
	logger := setupLogger(*verbose)

	// Get the input paths from the arguments
	args := flag.Args()

	// Validate arguments
	if len(args) == 0 {
		logger.Error("no SBOM files or directories provided")
		printUsage()
		return exitInvalidArgs
	}

	// Expand paths to get list of files
	files := expandPaths(args, logger)

	if len(files) == 0 {
		logger.Error("no SBOM files found")
		return exitInvalidArgs
	}

	// Setup signal handling for graceful cancellation
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Setup signal handler to cancel context on SIGINT/SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)
	go func() {
		sig := <-sigChan
		logger.Info("received signal, cancelling operation", "signal", sig)
		cancel()
	}()

	// Validate that we only have one file
	if len(files) > 1 {
		logger.Error("only one SBOM file is supported at a time")
		return exitInvalidArgs
	}

	// Use in-memory cache for local enrichment
	cacheInstance := cache.NewMemoryCache()
	logger.Debug("using in-memory cache")

	// Initialize the ecosystems provider
	service := provider.NewClient(provider.ClientOptions{
		Email: *email,
	})

	// Process the file
	enrichedSBOM, err := processFile(ctx, files[0], service, cacheInstance, *parallel, logger)
	if err != nil {
		logger.Error("failed to process file", "file", files[0], "error", err)
		return exitRuntimeError
	}

	// Write enriched SBOM to stdout
	if _, writeErr := os.Stdout.Write(enrichedSBOM); writeErr != nil {
		logger.Error("failed to write output", "error", writeErr)
		return exitRuntimeError
	}

	return exitSuccess
}

// printUsage prints the usage message.
func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] <sbom-file>\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Enrich SBOM files with license information.\n\n")
	fmt.Fprintf(os.Stderr, "The enriched SBOM is written to stdout.\n\n")
	fmt.Fprintf(os.Stderr, "This CLI tool is designed for local, one-off enrichment with in-memory caching.\n")
	fmt.Fprintf(os.Stderr, "For high-volume or distributed use cases, see 'sbomlicensed' daemon.\n\n")
	fmt.Fprintf(os.Stderr, "Arguments:\n")
	fmt.Fprintf(
		os.Stderr,
		"  sbom-file           Path to a single SBOM file (SPDX or CycloneDX JSON format)\n\n",
	)
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
}

// setupLogger sets up the logger based on the verbose flag.
func setupLogger(verbose bool) *slog.Logger {
	logLevel := slog.LevelError
	if verbose {
		// If verbose is true, set the log level to debug
		// This will log all messages, including debug messages
		logLevel = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
}

// expandPaths takes a mix of files and directories and returns a list of SBOM file paths.
func expandPaths(paths []string, logger *slog.Logger) []string {
	var files []string

	for _, path := range paths {
		info, statErr := os.Stat(path)
		if statErr != nil {
			logger.Error("cannot access path", "path", path, "error", statErr)
			continue
		}

		if info.IsDir() {
			// Read directory (non-recursive)
			entries, readErr := os.ReadDir(path)
			if readErr != nil {
				logger.Error("cannot read directory", "path", path, "error", readErr)
				continue
			}

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				// Only consider JSON files (SBOM files are typically JSON)
				if strings.HasSuffix(entry.Name(), ".json") {
					files = append(files, filepath.Join(path, entry.Name()))
				}
			}
		} else {
			// Regular file
			files = append(files, path)
		}
	}

	return files
}

// processFile reads, detects format, parses, and enriches a single SBOM file.
func processFile(
	ctx context.Context,
	filename string,
	provider provider.Provider,
	cacheInstance cache.Cache,
	parallelism int,
	logger *slog.Logger,
) ([]byte, error) {
	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	// Detect format
	format, err := sbom.DetectFormat(data)
	if err != nil {
		return nil, fmt.Errorf("detect format: %w", err)
	}

	logger.DebugContext(ctx, "detected SBOM format", "file", filename, "format", format)

	// Select license enrichment service based on format
	var licenseEnrichmentService enricher.Enricher

	switch {
	case strings.HasPrefix(format, "SPDX"):
		licenseEnrichmentService = enricher.NewSPDXEnricher(provider, cacheInstance, cacheTTL)
	case strings.HasPrefix(format, "CycloneDX"):
		licenseEnrichmentService = enricher.NewCycloneDXEnricher(provider, cacheInstance, cacheTTL)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}

	// Enrich the SBOM
	enriched, err := licenseEnrichmentService.Enrich(ctx, enricher.Options{
		SBOM:        data,
		Logger:      logger,
		Parallelism: parallelism,
	})
	if err != nil {
		return nil, fmt.Errorf("enrich SBOM: %w", err)
	}

	return enriched, nil
}
