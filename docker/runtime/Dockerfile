# Sanctuary runtime image: the gateway and realm binaries, and nothing else.
#
# Unlike docker/dev (passwordless sudo, compilers, Claude Code), this is what
# a server runs: no shell, no package manager, no build tools, an
# unprivileged user. Build from the repository root:
#
#   docker build -f docker/runtime/Dockerfile -t sanctuary-runtime:dev .
#
# compose.yaml builds it for you.

# The build stage reuses the development image, so the Go toolchain is the
# same pinned, checksum-verified one the code is developed and tested with.
ARG DEV_IMAGE=ghcr.io/megacosm-entertainment/sanctuary:dev_02
FROM ${DEV_IMAGE} AS build
USER root
WORKDIR /build
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
# Static binaries (no cgo, so no libc), without local paths or debug
# symbols. GOTOOLCHAIN=local comes from the dev image: the build fails
# rather than downloading a different Go.
RUN CGO_ENABLED=0 GOFLAGS=-buildvcs=false \
    go build -trimpath -ldflags="-s -w" -o /out/sanctuary-gateway ./cmd/sanctuary-gateway && \
    CGO_ENABLED=0 GOFLAGS=-buildvcs=false \
    go build -trimpath -ldflags="-s -w" -o /out/sanctuary-realm ./cmd/sanctuary-realm && \
    mkdir -p /state/data && chown 65532:65532 /state/data && chmod 700 /state/data

FROM scratch
LABEL org.opencontainers.image.title="Sanctuary runtime" \
      org.opencontainers.image.source="https://github.com/megacosm-entertainment/sanctuary" \
      org.opencontainers.image.authors="Ryan Hanson <hamartia@sanctuary-roleplay.org>"
COPY --from=build /out/ /
# DATA_DIR for accounts: owned by the runtime user, so a fresh named volume
# mounted here (compose.yaml) starts out writable by it and nobody else.
COPY --from=build --chown=65532:65532 /state/data /data
# 65532 is the conventional "nonroot" id; compose.yaml may override it so
# mounted key files owned by you are readable.
USER 65532:65532
EXPOSE 9000 9010 9020
CMD ["/sanctuary-gateway"]
