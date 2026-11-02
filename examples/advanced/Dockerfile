FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /build

COPY pyproject.toml README.md ./
COPY djangoapi_guard/ djangoapi_guard/

COPY examples/advanced/pyproject.toml /app/pyproject.toml

WORKDIR /app

RUN uv venv .venv && \
    uv pip install --python .venv/bin/python /build && \
    uv pip install --python .venv/bin/python gunicorn

FROM python:3.12-slim

RUN groupadd --system guard && \
    useradd --system --uid 10001 --gid guard --create-home guard

WORKDIR /app

COPY --from=builder --chown=guard:guard /app/.venv /app/.venv

COPY --chown=guard:guard examples/advanced/advanced_app/ /app/advanced_app/
COPY --chown=guard:guard examples/advanced/advanced_project/ /app/advanced_project/
COPY --chown=guard:guard examples/advanced/gunicorn.conf.py /app/gunicorn.conf.py
COPY --chown=guard:guard examples/advanced/manage.py /app/manage.py

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10001

EXPOSE 8000

# Same probe as the compose services: /health must answer 2xx.
HEALTHCHECK --interval=10s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

CMD ["gunicorn", "-c", "gunicorn.conf.py", "advanced_project.wsgi:application"]
