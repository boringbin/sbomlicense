package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/boringbin/sbomlicense/internal/cache"
	"github.com/boringbin/sbomlicense/internal/enricher"
	"github.com/boringbin/sbomlicense/internal/provider"
	"github.com/boringbin/sbomlicense/internal/sbom"
)

const (
	// maxRequestSize is the maximum request body size (10MB).
	maxRequestSize = 10 * 1024 * 1024
	// enrichmentTimeout is the maximum time allowed for enrichment operations.
	enrichmentTimeout = 10 * time.Minute
)

// Server is the HTTP server for the SBOM enrichment daemon.
type Server struct {
	provider           provider.Provider
	cache              cache.Cache
	logger             *slog.Logger
	defaultParallelism int
	cacheTTL           time.Duration
	version            string
}

// enrichRequest is the request body for POST /enrich.
type enrichRequest struct {
	// SBOM is the SBOM file to enrich.
	SBOM json.RawMessage `json:"sbom"`
	// Parallelism is the number of concurrent workers to use for enrichment.
	//
	// If <= 0, defaults to 1 (sequential processing).
	Parallelism int `json:"parallelism,omitempty"`
}

// enrichResponse is the response body for POST /enrich.
type enrichResponse struct {
	// SBOM is the enriched SBOM file.
	SBOM json.RawMessage `json:"sbom"`
}

// errorResponse is the error response body.
type errorResponse struct {
	// Error is the error message.
	Error string `json:"error"`
}

// NewServer creates a new Server instance.
func NewServer(
	provider provider.Provider,
	cache cache.Cache,
	logger *slog.Logger,
	defaultParallelism int,
	cacheTTL time.Duration,
	version string,
) *Server {
	return &Server{
		provider:           provider,
		cache:              cache,
		logger:             logger,
		defaultParallelism: defaultParallelism,
		cacheTTL:           cacheTTL,
		version:            version,
	}
}

// Handler returns an http.Handler for the server.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/enrich", s.handleEnrich)
	mux.HandleFunc("/health", s.handleHealth)
	return mux
}

// handleEnrich handles POST /enrich requests.
func (s *Server) handleEnrich(w http.ResponseWriter, r *http.Request) {
	// Wrap request context with enrichment timeout
	ctx, cancel := context.WithTimeout(r.Context(), enrichmentTimeout)
	defer cancel()

	// Only accept POST
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "only POST method is allowed")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)

	// Parse request
	var req enrichRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.logger.Error("failed to decode request", "error", err)
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: %v", err))
		return
	}

	// Validate SBOM
	if len(req.SBOM) == 0 {
		s.writeError(w, http.StatusBadRequest, "sbom field is required")
		return
	}

	// Detect format
	format, err := sbom.DetectFormat(req.SBOM)
	if err != nil {
		s.logger.Error("failed to detect SBOM format", "error", err)
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid SBOM format: %v", err))
		return
	}

	s.logger.Info("processing SBOM", "format", format)

	// Determine parallelism
	parallelism := req.Parallelism
	if parallelism <= 0 {
		parallelism = s.defaultParallelism
	}

	// Select license enrichment service based on format
	var licenseEnrichmentService enricher.Enricher

	switch {
	case strings.HasPrefix(format, "SPDX"):
		licenseEnrichmentService = enricher.NewSPDXEnricher(s.provider, s.cache, s.cacheTTL)
	case strings.HasPrefix(format, "CycloneDX"):
		licenseEnrichmentService = enricher.NewCycloneDXEnricher(s.provider, s.cache, s.cacheTTL)
	default:
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported SBOM format: %s", format))
		return
	}

	// Enrich the SBOM
	enriched, err := licenseEnrichmentService.Enrich(ctx, enricher.Options{
		SBOM:        req.SBOM,
		Logger:      s.logger,
		Parallelism: parallelism,
	})
	if err != nil {
		s.logger.Error("failed to enrich SBOM", "error", err)
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("enrichment failed: %v", err))
		return
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	response := enrichResponse{SBOM: enriched}
	if encodeErr := json.NewEncoder(w).Encode(response); encodeErr != nil {
		s.logger.Error("failed to encode response", "error", encodeErr)
	}
}

// handleHealth handles GET /health requests.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Only accept GET
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "only GET method is allowed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode("OK"); err != nil {
		s.logger.Error("failed to encode health response", "error", err)
	}
}

// writeError writes an error response.
func (s *Server) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := errorResponse{Error: message}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		s.logger.Error("failed to encode error response", "error", err)
	}
}
