FROM python:3.12-slim@sha256:85ae3b09fa7b2fbfd15dd3c57ca420aa36fa63c4d1ae0ce9f08c3466273a40fb AS builder

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir build && \
    python -m build --wheel && \
    pip install --no-cache-dir dist/*.whl

FROM python:3.12-slim@sha256:85ae3b09fa7b2fbfd15dd3c57ca420aa36fa63c4d1ae0ce9f08c3466273a40fb

LABEL org.opencontainers.image.source="https://github.com/kirankotari/ossguard"
LABEL org.opencontainers.image.description="One CLI to guard any OSS project with OpenSSF security best practices"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/ossguard /usr/local/bin/ossguard

RUN useradd --create-home ossguard
USER ossguard
WORKDIR /project

ENTRYPOINT ["ossguard"]
CMD ["--help"]
