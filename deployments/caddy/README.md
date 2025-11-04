# Caddy Configuration Files

This directory contains example Caddy configurations for deploying sbomlicensed in production.

## Files

- **`Caddyfile.example`** - Production configuration with automatic HTTPS
- **`Caddyfile.docker`** - Docker Compose configuration

## Quick Start

### Standalone Deployment

1. Copy the example file:
   ```bash
   cp Caddyfile.example Caddyfile
   ```

2. Edit `Caddyfile` and replace `sbomlicensed.example.com` with your domain

3. Generate authentication token:
   ```bash
   export SBOM_AUTH_TOKEN=$(openssl rand -base64 32)
   echo "Save this token: $SBOM_AUTH_TOKEN"
   ```

4. Start Caddy:
   ```bash
   caddy run --config Caddyfile
   ```

### Docker Compose Deployment

Use the pre-configured `docker-compose.production.yml` in the project root:

```bash
export EMAIL=your@example.com
export SBOM_AUTH_TOKEN=$(openssl rand -base64 32)
docker compose -f docker-compose.production.yml up -d
```

## Documentation

See **[HOSTING.md](../../HOSTING.md)** in the project root for complete deployment instructions, security best practices, and troubleshooting.
