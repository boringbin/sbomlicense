# Hosting sbomlicensed

This guide covers how to securely deploy `sbomlicensed` for production use, including CI/CD pipelines like GitHub Actions.

## Deployment Philosophy

`sbomlicensed` follows the Unix philosophy: **do one thing well**. The daemon focuses solely on SBOM enrichment, while security concerns (TLS, authentication, rate limiting) are handled by infrastructure layers.

```
Internet → Reverse Proxy (Caddy/nginx) → sbomlicensed
           ↓
           - TLS termination
           - Authentication
           - Rate limiting
           - Request logging
```

## Deployment Scenarios

### 1. Local Development (No Auth)

For local use, run the daemon directly:

```bash
./bin/sbomlicensed -email=you@example.com -cache-path ./cache.db
```

Or via Docker Compose:

```bash
docker compose up -d
```

Access at `http://localhost:8080`. **Do not expose this to the internet.**

---

### 2. CI/CD with Bearer Token Auth

For GitHub Actions or other CI/CD systems that need remote access.

#### Caddy Configuration

Create `Caddyfile`:

```caddy
# Production endpoint with automatic HTTPS
sbomlicensed.example.com {
    # Automatic TLS via Let's Encrypt

    # Rate limiting: 100 requests per minute per IP
    rate_limit {
        zone sbom_api {
            key {remote_host}
            events 100
            window 1m
        }
    }

    # Health check is public (for load balancers)
    handle /health {
        reverse_proxy localhost:8080
    }

    # Enrich endpoint requires bearer token
    handle /enrich {
        @authenticated {
            header Authorization "Bearer {env.SBOM_AUTH_TOKEN}"
        }

        handle @authenticated {
            reverse_proxy localhost:8080
        }

        # Return 401 for unauthenticated requests
        respond "Unauthorized" 401
    }

    # Log requests
    log {
        output file /var/log/caddy/sbom-access.log
        format json
    }
}
```

#### Environment Setup

```bash
# Set your secret token
export SBOM_AUTH_TOKEN="your-secret-token-here-use-openssl-rand-base64-32"

# Start Caddy
caddy run --config Caddyfile

# In another terminal, start daemon
./bin/sbomlicensed -email=you@example.com -cache-path ./cache.db
```

#### GitHub Actions Usage

In your GitHub workflow:

```yaml
# .github/workflows/enrich-sbom.yml
name: Enrich SBOM

on: [push]

jobs:
  enrich:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Generate SBOM
        run: |
          # Your SBOM generation step
          # Produces sbom.json

      - name: Enrich SBOM with licenses
        env:
          SBOM_TOKEN: ${{ secrets.SBOM_AUTH_TOKEN }}
        run: |
          jq -n --slurpfile sbom sbom.json '{sbom: $sbom[0]}' \
            | curl -X POST https://sbomlicensed.example.com/enrich \
              -H "Content-Type: application/json" \
              -H "Authorization: Bearer $SBOM_TOKEN" \
              -d @- \
            | jq '.sbom' > enriched-sbom.json

      - name: Upload enriched SBOM
        uses: actions/upload-artifact@v4
        with:
          name: enriched-sbom
          path: enriched-sbom.json
```

---

### 3. Docker Compose with Caddy

Run both daemon and Caddy together:

```yaml
# docker-compose.production.yml
version: '3.8'

services:
  sbomlicensed:
    image: ghcr.io/boringbin/sbomlicensed:latest
    container_name: sbomlicensed
    restart: unless-stopped
    environment:
      - EMAIL=${EMAIL}
      - CACHE_PATH=/app/data/cache.db
    volumes:
      - cache-data:/app/data
    # No port exposure - only accessible via Caddy
    networks:
      - sbom-internal
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 3s
      retries: 3

  caddy:
    image: caddy:2-alpine
    container_name: caddy
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    environment:
      - SBOM_AUTH_TOKEN=${SBOM_AUTH_TOKEN}
    networks:
      - sbom-internal
    depends_on:
      - sbomlicensed

volumes:
  cache-data:
  caddy-data:
  caddy-config:

networks:
  sbom-internal:
    driver: bridge
```

**Caddyfile for Docker Compose:**

```caddy
{
    # Global options
    admin off
}

:80 {
    # Health check (public)
    handle /health {
        reverse_proxy sbomlicensed:8080
    }

    # Enrich endpoint (authenticated)
    handle /enrich {
        @authenticated {
            header Authorization "Bearer {env.SBOM_AUTH_TOKEN}"
        }

        handle @authenticated {
            reverse_proxy sbomlicensed:8080
        }

        respond "Unauthorized" 401
    }

    # Default response
    respond "Not Found" 404
}
```

**Start the stack:**

```bash
# Set environment variables
export EMAIL=you@example.com
export SBOM_AUTH_TOKEN=$(openssl rand -base64 32)

# Start services
docker compose -f docker-compose.production.yml up -d

# Check status
docker compose -f docker-compose.production.yml ps
docker compose -f docker-compose.production.yml logs -f
```

---

### 4. Self-Hosted GitHub Actions Runners

If you run self-hosted GitHub Actions runners on the same network as the daemon:

```yaml
# docker-compose.yml (simple, no auth needed)
services:
  sbomlicensed:
    image: ghcr.io/boringbin/sbomlicensed:latest
    restart: unless-stopped
    environment:
      - EMAIL=${EMAIL}
    ports:
      - "127.0.0.1:8080:8080"  # Only localhost
    volumes:
      - cache-data:/app/data

volumes:
  cache-data:
```

GitHub Actions workflow:

```yaml
jobs:
  enrich:
    runs-on: self-hosted  # Your runner has network access to daemon
    steps:
      - name: Enrich SBOM
        run: |
          # Daemon accessible via Docker internal network or localhost
          curl -X POST http://localhost:8080/enrich \
            -H "Content-Type: application/json" \
            -d @request.json
```

**No auth needed** since runners are in trusted network.
