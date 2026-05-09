FROM golang:1.22-alpine AS builder

WORKDIR /build

# Clone ossguard-go and build static binary
ARG OSSGUARD_VERSION=main
RUN apk add --no-cache git && \
    git clone --depth 1 --branch ${OSSGUARD_VERSION} \
      https://github.com/kirankotari/ossguard-go.git . && \
    CGO_ENABLED=0 go build -ldflags="-s -w" -o ossguard ./cmd/ossguard

FROM alpine:3.20

LABEL org.opencontainers.image.source="https://github.com/kirankotari/ossguard"
LABEL org.opencontainers.image.description="One CLI to guard any OSS project with OpenSSF security best practices"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache git && \
    adduser -D -h /home/ossguard ossguard

COPY --from=builder /build/ossguard /usr/local/bin/ossguard

USER ossguard
WORKDIR /project

ENTRYPOINT ["ossguard"]
CMD ["--help"]
