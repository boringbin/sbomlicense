package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/boringbin/sbomlicense/internal/version"
)

const (
	// ecosystemsBaseURL is the base URL for the Ecosystems API.
	//
	// See https://packages.ecosyste.ms/docs/index.html
	ecosystemsBaseURL = "https://packages.ecosyste.ms"
	// ecosystemsAPIPath is the API path for package lookup.
	ecosystemsAPIPath = "/api/v1/packages/lookup"
	// defaultHTTPTimeout is the default timeout for HTTP requests.
	defaultHTTPTimeout = 30 * time.Second
)

// Client is the client for the Ecosystems API.
type Client struct {
	baseURL string
	client  *http.Client
	email   string
}

var _ Provider = (*Client)(nil)

// ClientOptions are the options for the Client.
type ClientOptions struct {
	// BaseURL is the base URL for the Ecosystems API.
	// If empty, defaults to the public Ecosystems API.
	BaseURL string
	// Client is the HTTP client to use for the Ecosystems API.
	// If nil, defaults to http.DefaultClient.
	Client *http.Client
	// Email is the email address for the polite pool.
	// If empty, requests will not include polite pool identification.
	Email string
}

// NewClient creates a new Client.
func NewClient(opts ClientOptions) *Client {
	// Default to the Ecosystems API base URL.
	baseURL := ecosystemsBaseURL
	if opts.BaseURL != "" {
		baseURL = opts.BaseURL
	}
	// Default to an HTTP client with timeout.
	client := opts.Client
	if client == nil {
		client = &http.Client{
			Timeout: defaultHTTPTimeout,
		}
	}

	return &Client{
		baseURL: baseURL,
		client:  client,
		email:   opts.Email,
	}
}

// ecosystemsPackagesLookupResponse is the response from the Ecosystems API.
type ecosystemsPackagesLookupResponse struct {
	NormalizedLicenses []string `json:"normalized_licenses"`
}

// Get gets the license for a package from the Ecosystems API.
func (s *Client) Get(ctx context.Context, purl string) (string, error) {
	apiURL := fmt.Sprintf("%s%s?purl=%s", s.baseURL, ecosystemsAPIPath, url.QueryEscape(purl))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set User-Agent header
	userAgent := fmt.Sprintf("sbomlicense/%s", version.Get())
	if s.email != "" {
		// See https://ecosyste.ms/api
		userAgent = fmt.Sprintf("sbomlicense/%s (mailto:%s)", version.Get(), s.email)
	}
	req.Header.Set("User-Agent", userAgent)

	response, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		switch response.StatusCode {
		case http.StatusNotFound:
			return "", fmt.Errorf("%w: HTTP 404", ErrLicenseNotFound)
		case http.StatusTooManyRequests:
			return "", errors.New("rate limited by API: HTTP 429")
		case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			return "", fmt.Errorf("API service unavailable: HTTP %d", response.StatusCode)
		default:
			return "", fmt.Errorf("API error: HTTP %d", response.StatusCode)
		}
	}

	// Parse the response (it's an array)
	var results []ecosystemsPackagesLookupResponse
	err = json.NewDecoder(response.Body).Decode(&results)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}

	// Check if we got any results and if the first result has licenses
	if len(results) == 0 || len(results[0].NormalizedLicenses) == 0 {
		return "", fmt.Errorf("%w: no licenses found for %s", ErrLicenseNotFound, purl)
	}

	// Return the first normalized license
	return results[0].NormalizedLicenses[0], nil
}
