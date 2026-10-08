# AGENTS.md

Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

DjAPI Guard (repo name `djangoapi-guard`, distribution name `djapi-guard`) is a production-ready security library for Django applications that provides:

- IP control and rate limiting
- Request logging and monitoring
- Penetration attempt detection
- Security headers management
- Redis-based distributed caching
- Route-level security decorators
- Behavioral analysis and anomaly detection

It is a direct port of [FlaskAPI Guard](https://github.com/Guard-Core/flaskapi-guard) to the Django middleware model, with the same feature set adapted to Django's synchronous request/response cycle.

- **PyPI Package**: `djapi-guard`
- **Import Name**: `djangoapi_guard`
- **Python Support**: 3.10, 3.11, 3.12, 3.13
- **Package Manager**: uv
- **Build System**: Docker + Make

## Ecosystem Position

DjAPI Guard is a **thin adapter** over [guard-core](https://github.com/Guard-Core/guard-core). All security logic (models, handlers, decorators, detection engine, protocols, utilities) lives in the `guard_core` package; this repo contains only the Django integration layer.

```text
guard-core (engine, PyPI dependency >=3.15.0)   <- all security logic
└── djangoapi-guard (this repo)                 <- Django middleware adapter
    ├── fastapi-guard                           <- sibling adapter (ASGI middleware)
    ├── flaskapi-guard                          <- sibling adapter (Flask extension)
    └── tornadoapi-guard                        <- sibling adapter (Tornado handler/middleware)
```

Because Django is synchronous, this adapter imports the unasync-generated sync mirror `guard_core.sync.*` (not the async `guard_core.*` tree): the pipeline (`guard_core.sync.core.checks.pipeline.SecurityCheckPipeline`), handlers, decorators, protocols, and utilities all come from `guard_core.sync`. This adapter implements guard-core's `SyncGuardMiddlewareProtocol`.

### Package Components

- **`djangoapi_guard/middleware.py`** - `DjangoAPIGuard`, a standard Django middleware (`__init__(get_response)` / `__call__(request)`). It reads `settings.GUARD_SECURITY_CONFIG`, initializes handlers lazily, builds the `SecurityCheckPipeline` from the config, and exposes `set_decorator_handler` (so the pipeline is derived from registered route config), `guard_response_factory`, and `agent_stats`.
- **`djangoapi_guard/adapters.py`** - Protocol adapters bridging Django types to guard-core protocols: `DjangoGuardRequest` (wraps `django.http.HttpRequest`), `DjangoHeadersMapping` (case-insensitive header mapping), `DjangoGuardResponse`, and `DjangoResponseFactory` (creates blocked/redirect responses).
- **`djangoapi_guard/__init__.py`** - Public exports: `DjangoAPIGuard` plus re-exports from `guard_core` and `guard_core.sync` so users never import guard-core directly.

### Request Flow

1. Middleware extracts the client IP (proxy-aware), resolves route config from decorators via `_guard_route_id` on view functions, and populates guard state on the request (including `guard_route_id` on the guard request's state).
2. The `SecurityCheckPipeline` runs the 17 checks in order; the first non-`None` `HttpResponse` short-circuits and blocks.
3. On pass-through, the response is finalized through the response factory (behavioral return rules, metrics, security headers, CORS).

CORS preflight (`OPTIONS`) is handled explicitly before the pipeline.

### Passive Mode

All blocking checks respect `config.passive_mode`: when `True`, violations are logged and evented but never blocked (checks return `None` instead of an error response).

## Boundary Rules

- **This repo MUST NOT** contain security logic (checks, handlers, models, detection patterns, `SecurityConfig`). Those belong in [guard-core](https://github.com/Guard-Core/guard-core); a security fix belongs upstream, not here.
- **This repo MUST** bridge Django native types to guard-core's `GuardRequest` / `GuardResponse` / response-factory protocols through `djangoapi_guard/adapters.py`, and use the `guard_core.sync.*` mirror (never the async tree) because Django is synchronous.
- **This repo MUST** keep `DjangoAPIGuard` a thin orchestrator that delegates to `SecurityCheckPipeline`; do not fork or reimplement pipeline behavior.
- **This repo MUST** re-export new guard-core public surface from `djangoapi_guard/__init__.py` when it becomes part of the adapter's user-facing API.
- This repo should only change when:
  - The Django adapter layer needs updates
  - New guard-core exports need to be re-exported from `djangoapi_guard/__init__.py`
  - Django-specific middleware orchestration changes

## Quick Start

```bash
# Install dependencies with uv
make install-dev

# Run tests locally (needs Redis at localhost:6379, or set REDIS_URL)
make local-test

# Start example application
make start-example

# Run linting and formatting
make fix
```

Wire the middleware early in `MIDDLEWARE` and configure it in settings:

```python
# settings.py
from djangoapi_guard import SecurityConfig

MIDDLEWARE = [
    "djangoapi_guard.middleware.DjangoAPIGuard",
    "django.middleware.security.SecurityMiddleware",
    # ...
]

GUARD_SECURITY_CONFIG = SecurityConfig(
    whitelist=["192.168.1.1"],
    blacklist=["10.0.0.1"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
)
```

`GUARD_SECURITY_CONFIG` must be a `SecurityConfig` instance; when the setting is absent the middleware falls back to `SecurityConfig()` defaults.

## Development Commands

### Package Management (uv)

- `make install` - Install core dependencies
- `make install-dev` - Install with dev dependencies
- `make lock` - Update lock file
- `make upgrade` - Upgrade lock dependencies and install

### Testing

- `make test` - Run tests in Docker (Python 3.10)
- `make test-all` - Test all Python versions (3.10-3.13)
- `make test-3.12` - Test specific Python version
- `make local-test` - Run tests locally with uv

```bash
# Run a single test file
uv run pytest tests/test_middleware.py -v

# Run a single test
uv run pytest tests/test_middleware.py::test_name -v

# Coverage report
uv run pytest tests/ --cov=djangoapi_guard --cov-report=term-missing -q
```

### Code Quality

Run all of these before committing:

```bash
uv run ruff format .
uv run ruff check .
uv run mypy .
uv run vulture vulture_whitelist.py
```

- `make lint` - Run all linters in Docker (ruff, mypy)
- `make fix` - Auto-fix formatting with ruff
- `make vulture` - Find dead code
- `make bandit` - Security scan
- `make safety` - Check dependency vulnerabilities
- `make pip-audit` - Audit dependencies
- `make radon` - Analyze code complexity
- `make xenon` - Check complexity thresholds
- `make deptry` - Analyze dependencies
- `make security` - Run all security checks (bandit, safety, pip-audit)
- `make quality` - Run all quality checks (lint, vulture, radon, xenon)
- `make analysis` - Run analysis tools (deptry)
- `make check-all` - Run everything (lint, security, quality, analysis)

### Documentation

- `make serve-docs` - Serve MkDocs locally

### Docker Operations

- `make start-example` - Start example app with Docker
- `make run-example` - Build and run example
- `make stop` - Stop all containers
- `make restart` - Restart services
- `make prune` - Clean Docker resources
- `make clean` - Clean Python cache files and containers

Environment variables:

- `PYTHON_VERSION` - Python version (3.10-3.13)
- `REDIS_URL` - Redis connection string
- `REDIS_PREFIX` - Key prefix for Redis
- `IPINFO_TOKEN` - IPInfo API token

### Version Management

- `make bump-version VERSION=x.y.z` - Bump package version

## Project Structure

```text
djangoapi-guard/
├── djangoapi_guard/           # Adapter package (thin layer over guard-core)
│   ├── __init__.py            # Public exports + guard_core/guard_core.sync re-exports
│   ├── middleware.py          # DjangoAPIGuard (Django middleware)
│   ├── adapters.py            # DjangoGuardRequest / DjangoHeadersMapping / DjangoGuardResponse / DjangoResponseFactory
│   └── py.typed               # PEP 561 marker
├── tests/                     # Test suite
│   ├── conftest.py            # request_factory, security_config, make_request, singleton cleanup
│   ├── settings.py            # Django settings used by pytest (DJANGO_SETTINGS_MODULE)
│   ├── urls.py
│   ├── test_adapters.py
│   ├── test_middleware.py
│   ├── test_middleware_lifecycle.py
│   ├── test_middleware_wiring.py
│   ├── test_decorators/       # Route-level decorator behaviors
│   ├── test_extension/        # Middleware wiring and integration
│   ├── test_cors_through_pipeline.py
│   └── test_reexports.py      # Public API surface contract
├── examples/                  # Example Django applications
├── docs/                      # MkDocs documentation
├── Makefile                   # Build automation
├── compose.yml                # Docker Compose config
├── Dockerfile                 # Docker image definition
├── pyproject.toml             # Project metadata & config
├── uv.lock                    # Locked dependencies
└── vulture_whitelist.py       # Vulture false positive suppressions
```

### Configuration Files

- **pyproject.toml** - Project metadata and dependencies; tool configurations for ruff, mypy, pytest (including `DJANGO_SETTINGS_MODULE = "tests.settings"`), vulture, bandit, radon, xenon, deptry
- **uv.lock** - Locked dependency versions, updated with `make lock`
- **compose.yml / Dockerfile** - Multi-version Python support (3.10-3.13) and a Redis service for testing
- **.pre-commit-config.yaml** - ruff format, ruff check, mypy, vulture, bandit, safety, radon, xenon, deptry

## Technology Stack

### Core Dependencies

- **Django** - Web framework (synchronous middleware model)
- **guard-core** - Framework-agnostic security engine (all security logic, `>=3.15.0`)

### Development Tools

- **uv** - Fast Python package manager
- **pytest** - Testing framework
- **pytest-django** - Django test integration (`DJANGO_SETTINGS_MODULE` from pyproject)
- **pytest-cov** - Coverage reporting
- **pytest-mock** - Mock fixtures
- **ruff** - Fast Python linter/formatter
- **mypy** - Static type checker
- **vulture** - Dead code detection
- **bandit** - Security linter
- **radon/xenon** - Complexity analysis
- **deptry** - Dependency analysis
- **pre-commit** - Git hooks
- **mkdocs** / **mkdocs-material** - Documentation

## Testing Guidelines

### Running Tests

```bash
# Local testing with coverage
make local-test

# Docker testing (default Python 3.10)
make test

# Test all Python versions
make test-all

# Specific Python version
make test-3.12
```

### Test Configuration (pyproject.toml)

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "--cov=djangoapi_guard --cov-branch --cov-report=term-missing --ignore=tests/test_agent"
DJANGO_SETTINGS_MODULE = "tests.settings"
```

Tests need a reachable Redis at `localhost:6379` (or set `REDIS_URL`).

### Testing Patterns

- Django is configured through pytest's `DJANGO_SETTINGS_MODULE` (`tests.settings`); do not call `django.setup()` by hand in tests.
- Fixtures in `tests/conftest.py`: `request_factory` (`django.test.RequestFactory`), `security_config` (a `SecurityConfig`), `make_request`, plus autouse singleton-cleanup fixtures for the IP-ban and suspicious-patterns singletons.
- All test methods need a `-> None` return annotation (mypy strict mode).
- E402 (module-level import not at top) can appear in test modules because of the Django settings/bootstrap pattern; it is expected there.

## Code Quality Standards

### Ruff Configuration

- Target Python 3.10+
- Selected rules: E, F, UP, B, I; line length 88
- `tests/` and `examples/` are excluded from some rules

### MyPy Configuration

- Strict mode (`disallow_untyped_defs`, `strict_optional`, `warn_unreachable`)
- `TYPE_CHECKING` imports use `# pragma: no cover`

### Pre-commit Workflow

1. Automatic formatting with ruff
2. Linting checks with ruff
3. Type checking with mypy
4. Dead code detection with vulture
5. Security scanning with bandit
6. Dependency vulnerability checking with safety
7. Complexity analysis with radon/xenon
8. Dependency analysis with deptry

## Best Practices

1. **Always use uv** for package management
2. **Run tests** before committing
3. **Use Make commands** for consistency
4. **Test multiple Python versions** for compatibility
5. **Keep dependencies updated** with `make upgrade`
6. **Use type hints** and run mypy
7. **Follow ruff** formatting standards
8. **Document changes** in appropriate docs/

### Sync-Only Code

- All custom callables (custom checks, validators, modifiers, `auth_verifier`) are **synchronous**; the adapter runs on the `guard_core.sync` mirror
- Per-request state lives on attributes attached to the Django request object; route identity is carried by `_guard_route_id` on view functions
- IP extraction is proxy-aware from `request.META` (`REMOTE_ADDR` / `X-Forwarded-For`)
- Redis and outbound HTTP use synchronous clients (`redis.Redis`, `httpx.Client`)

### Security Considerations

- This is a security library - all code must be defensive
- Validate all inputs with Pydantic
- Use Redis for distributed rate limiting
- Implement proper error handling
- Log security events appropriately
- Never expose sensitive data in logs
- All regex patterns must be ReDoS-safe (guard-core's `PatternCompiler` validates this)

## Related Projects

- **guard-core** - Framework-agnostic security engine (the engine this adapter wraps): <https://github.com/Guard-Core/guard-core>
- **fastapi-guard** - FastAPI/Starlette adapter (async reference implementation): <https://github.com/Guard-Core/fastapi-guard>
- **flaskapi-guard** - Flask extension adapter (sync mirror): <https://github.com/Guard-Core/flaskapi-guard>
- **tornadoapi-guard** - Tornado handler/middleware adapter: <https://github.com/Guard-Core/tornadoapi-guard>
- **guard-agent** - Telemetry and monitoring agent: <https://github.com/Guard-Core/guard-agent>
- **guard-core-mcp** - MCP server for config validation and docs search: <https://github.com/Guard-Core/guard-core-mcp>
- **guard-core-app** - SaaS platform (API, dashboard, playground): <https://github.com/Guard-Core/guard-core-app>
