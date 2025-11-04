package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.etcd.io/bbolt"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/provider"
	"github.com/boringbin/sbomlicense/internal/server"
	"github.com/boringbin/sbomlicense/internal/version"
)

const (
	// defaultPort is the default HTTP port.
	defaultPort = 8080
	// defaultCachePath is the default path for the bbolt cache database.
	defaultCachePath = "./data/cache.db"
	// dbFileMode is the file mode for the bbolt database file.
	dbFileMode = 0600
	// defaultParallelism is the default number of parallel workers.
	defaultParallelism = 20
	// readHeaderTimeout is the timeout for reading request headers.
	readHeaderTimeout = 10 * time.Second
	// readTimeout is the timeout for reading the entire request.
	readTimeout = 30 * time.Second
	// writeTimeout is the timeout for writing the response.
	writeTimeout = 60 * time.Second
	// shutdownTimeout is the timeout for graceful shutdown.
	shutdownTimeout = 10 * time.Second
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		port      = flag.Int("port", defaultPort, "HTTP port to listen on")
		cachePath = flag.String("cache-path", defaultCachePath, "Path to bbolt cache database file")
		parallel  = flag.Int("parallel", defaultParallelism, "Default number of concurrent workers for enrichment")
		cacheTTL  = flag.Duration("cache-ttl", 0*time.Hour, "Cache TTL for enrichment results")
		verbose   = flag.Bool("v", false, "Verbose output (debug mode)")
		email     = flag.String("email", "", "Email for polite pool (required)")
	)

	flag.Parse()

	// Setup logger
	logger := setupLogger(*verbose)

	// Get cache path from flag or environment variable
	cacheFilePath := *cachePath
	if cacheEnv := os.Getenv("CACHE_PATH"); cacheEnv != "" {
		cacheFilePath = cacheEnv
	}

	// Get port from flag or environment variable
	portNum := *port
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		if portFromEnv, err := strconv.Atoi(portEnv); err == nil {
			portNum = portFromEnv
		}
	}

	// Get email from flag or environment variable
	emailAddr := *email
	if emailEnv := os.Getenv("EMAIL"); emailEnv != "" {
		emailAddr = emailEnv
	}

	// Validate that email is provided
	// Email is REQUIRED for daemon mode to access the ecosyste.ms API "polite pool",
	if emailAddr == "" {
		logger.Error("email is required for ecosyste.ms API polite pool access")
		logger.Error("provide via -email flag or EMAIL environment variable")
		logger.Error("example: sbomlicensed -email your@example.com")
		return 1
	}

	// Open bbolt database
	db, err := bbolt.Open(cacheFilePath, dbFileMode, nil)
	if err != nil {
		logger.Error("failed to open cache database", "path", cacheFilePath, "error", err)
		return 1
	}
	defer db.Close()
	logger.Info("opened cache database", "path", cacheFilePath)

	// Initialize cache
	cacheInstance, err := cache.NewBboltCache(db)
	if err != nil {
		logger.Error("failed to initialize cache", "error", err)
		return 1
	}

	// Initialize ecosystems provider
	service := provider.NewClient(provider.ClientOptions{
		Email: emailAddr,
	})

	// Create server
	srv := server.NewServer(service, cacheInstance, logger, *parallel, *cacheTTL, version.Get())

	// Create HTTP server
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", portNum),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
	}

	// Start server in a goroutine
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("starting HTTP server", "port", portNum)
		serverErrors <- httpServer.ListenAndServe()
	}()

	// Wait for interrupt signal or server error
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)

	select {
	case serverErr := <-serverErrors:
		logger.Error("server error", "error", serverErr)
		return 1
	case sig := <-shutdown:
		logger.Info("received shutdown signal", "signal", sig.String())

		// Graceful shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
			logger.Error("graceful shutdown failed", "error", shutdownErr)
			if closeErr := httpServer.Close(); closeErr != nil {
				logger.Error("forced shutdown failed", "error", closeErr)
			}
			return 1
		}

		logger.Info("server stopped gracefully")
		return 0
	}
}

// setupLogger sets up the logger based on the verbose flag.
func setupLogger(verbose bool) *slog.Logger {
	logLevel := slog.LevelInfo
	if verbose {
		logLevel = slog.LevelDebug
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
}
