FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Production default: signature ingress on. The dev compose file overrides this to 0.
    ALES_ENV=production \
    ALES_REQUIRE_SIGNATURES=1 \
    ALES_MAX_BODY=1048576 \
    ALES_SNAPSHOT_LEASE=60 \
    ALES_OUTBOX_INTERVAL=5

WORKDIR /app

COPY . /app

# Runtime dependencies plus the `postgres` extra (psycopg driver; required for DATABASE_URL=postgresql+psycopg://)
# and the purge-target extras. No dev/test toolchain in the production image.
# The Python package includes the Alembic migration files needed at server startup.
RUN pip install ".[postgres,qdrant,pgvector,connectors]" && \
    addgroup --system --gid 10001 ales && \
    adduser --system --uid 10001 --ingroup ales --no-create-home ales

USER 10001:10001

EXPOSE 8787

CMD ["uvicorn", "ales_server.main:app", "--host", "0.0.0.0", "--port", "8787"]
