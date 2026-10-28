# DjangoAPI Guard Simple Example

Single-project Django application demonstrating all djapi-guard security features.

___

## Quick Start

```bash
export IPINFO_TOKEN=<your token>  # required: free at https://ipinfo.io/signup
docker compose up --build
```

___

## Testing

```bash
curl http://localhost:8000/
curl http://localhost:8000/health
curl http://localhost:8000/basic/ip
curl http://localhost:8000/basic/echo -X POST -H "Content-Type: application/json" -d '{"test": true}'
curl http://localhost:8000/test/xss-test -X POST -H "Content-Type: application/json" -d '"<script>alert(1)</script>"'
for i in $(seq 1 5); do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8000/rate/strict-limit; done
```

___

## Endpoints

### Root

- `GET /` - Application overview with all endpoint groups
- `GET /health` - Health check (excluded from security)

### Basic (`/basic/`)

- `GET /basic/` - Basic features root
- `GET /basic/ip` - Client IP information
- `GET /basic/health` - Health check
- `POST /basic/echo` - Echo request data back

### Access Control (`/access/`)

- `GET /access/ip-whitelist` - IP whitelist demo (127.0.0.1, 10.0.0.0/8)
- `GET /access/ip-blacklist` - IP blacklist demo (192.168.1.0/24, 172.16.0.0/12)
- `GET /access/country-block` - Block countries (CN, RU, KP)
- `GET /access/country-allow` - Allow countries (US, CA, GB, AU)
- `GET /access/no-cloud` - Block all cloud providers
- `GET /access/no-aws` - Block AWS only
- `GET /access/bypass-demo` - Bypass rate_limit and ip

### Authentication (`/auth/`)

- `GET /auth/https-only` - Require HTTPS
- `GET /auth/bearer-auth` - Require Bearer token
- `GET /auth/api-key` - Require X-API-Key header
- `GET /auth/custom-headers` - Require X-Custom-Header and X-Client-ID

### Rate Limiting (`/rate/`)

- `GET /rate/custom-limit` - 5 requests per 60 seconds
- `GET /rate/strict-limit` - 1 request per 10 seconds
- `GET /rate/geo-rate-limit` - Country-based rate limits

### Behavioral Analysis (`/behavior/`)

- `GET /behavior/usage-monitor` - Usage monitoring (10 calls/300s)
- `GET /behavior/return-monitor/<status_code>` - Return code monitoring
- `GET /behavior/suspicious-frequency` - Frequency detection
- `POST /behavior/behavior-rules` - Combined behavior rules

### Security Headers (`/headers/`)

- `GET /headers/` - Security headers information
- `GET /headers/test-page` - HTML page with security headers
- `POST /headers/csp-report` - CSP violation report endpoint
- `GET /headers/frame-test` - X-Frame-Options test page
- `GET /headers/hsts-info` - HSTS configuration
- `GET /headers/security-analysis` - Request header analysis

### Content Filtering (`/content/`)

- `GET /content/no-bots` - Block bot user agents
- `POST /content/json-only` - Accept only application/json
- `POST /content/size-limit` - 100KB request size limit
- `GET /content/referrer-check` - Require specific referrers
- `GET /content/custom-validation` - Custom user agent validation

### Advanced (`/advanced/`)

- `GET /advanced/business-hours` - 09:00-17:00 UTC access only
- `GET /advanced/weekend-only` - 00:00-23:59 UTC access
- `POST /advanced/honeypot` - Honeypot field detection
- `GET /advanced/suspicious-patterns` - Suspicious pattern detection

### Administration (`/admin/`)

- `POST /admin/unban-ip` - Unban an IP address
- `GET /admin/stats` - Security statistics
- `POST /admin/clear-cache` - Clear security cache
- `PUT /admin/emergency-mode` - Toggle emergency mode
- `GET /admin/cloud-status` - Cloud provider IP range status

### Security Testing (`/test/`)

- `POST /test/xss-test` - XSS detection test
- `GET /test/sql-injection` - SQL injection detection test
- `GET /test/path-traversal/<file_path>` - Path traversal detection test
- `POST /test/command-injection` - Command injection detection test
- `POST /test/mixed-attack` - Mixed attack detection test

___

## Environment Variables

- `REDIS_URL` - Redis connection string (default: `redis://localhost:6379`)
- `REDIS_PREFIX` - Key prefix for Redis (default: `djangoapi_guard:`)
- `IPINFO_TOKEN` - IPInfo API token for geolocation (required: the country routes need a GeoIP source; the example stops at startup without it, and `docker compose` refuses to start)

___

## Configuration

See `example_project/settings.py` for the full `GUARD_SECURITY_CONFIG` with all security features configured.

___

## Cleanup

```bash
docker compose down -v
```
