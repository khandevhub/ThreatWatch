FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.17 /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY --chown=10001:10001 . /app
RUN mkdir -p /data && chown 10001:10001 /data

ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 5000
USER 10001:10001
CMD ["waitress-serve", "--listen=0.0.0.0:5000", "app:app"]
