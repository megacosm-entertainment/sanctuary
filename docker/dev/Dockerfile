# Sanctuary development image.
#
# Only what the Go engine needs. The old C engine's toolchain lives in the
# separate legacy image. Build (both architectures, so Apple Silicon runs it
# natively). The Dockerfile is self-contained, so any directory works as the
# build context:
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/megacosm-entertainment/sanctuary:<tag> --push docker/dev
#
# Nothing secret goes into this image: no keys, tokens or credentials. The
# devcontainer forwards your SSH agent for git; builds that need a secret
# use BuildKit --secret mounts, which never land in a layer.

FROM debian:trixie-slim

LABEL org.opencontainers.image.title="Sanctuary dev environment" \
      org.opencontainers.image.authors="Ryan Hanson <hamartia@sanctuary-roleplay.org>"

ARG DEBIAN_FRONTEND=noninteractive

# Base packages. Upgrade first so every rebuild picks up Debian security
# fixes. gcc + libc6-dev: the race detector needs cgo. gnupg: verifying the
# Claude Code repository key below. telnet: manual protocol testing.
RUN apt-get update && apt-get -y upgrade && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg git openssh-client \
      gcc libc6-dev \
      bash sudo less vim procps ripgrep jq telnet locales tzdata && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen && locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8 LANGUAGE=en_US:en LC_ALL=en_US.UTF-8

# Go from go.dev, pinned and checksum-verified (checksums from
# https://go.dev/dl/?mode=json). Keep GO_VERSION at or above the go line in
# go.mod, which is the security floor; raise both when scripts/vulncheck.sh
# reports a fix.
ARG GO_VERSION=1.27.4
ARG GO_SHA256_AMD64=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
ARG GO_SHA256_ARM64=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
ARG TARGETARCH
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) sha="$GO_SHA256_AMD64" ;; \
      arm64) sha="$GO_SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz"; \
    echo "${sha}  /tmp/go.tgz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz

# Claude Code from Anthropic's signed apt repository (stable channel). The
# key is checked against the fingerprint published in the Claude Code docs
# before apt trusts it. Updates arrive by rebuilding the image.
ARG CLAUDE_REPO_FPR=31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE
RUN set -eux; \
    install -d -m 0755 /etc/apt/keyrings; \
    curl -fsSLo /etc/apt/keyrings/claude-code.asc https://downloads.claude.ai/keys/claude-code.asc; \
    fpr="$(gpg --show-keys --with-colons /etc/apt/keyrings/claude-code.asc | awk -F: '$1=="fpr"{print $10; exit}')"; \
    [ "$fpr" = "$CLAUDE_REPO_FPR" ] || { echo "Claude Code key fingerprint mismatch: $fpr" >&2; exit 1; }; \
    echo "deb [signed-by=/etc/apt/keyrings/claude-code.asc] https://downloads.claude.ai/claude-code/apt/stable stable main" \
      > /etc/apt/sources.list.d/claude-code.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends claude-code; \
    apt-get clean; rm -rf /var/lib/apt/lists/*

# User: the same uid/gid (9000) as the legacy image, so files on the shared
# workspace mount keep their ownership; ownership follows the numeric ids,
# not the name.
RUN groupadd -g 9000 sanctuary && \
    useradd -s /bin/bash -c "Sanctuary developer" -m -u 9000 -g sanctuary sanctuary && \
    echo "sanctuary ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/sanctuary && \
    chmod 0440 /etc/sudoers.d/sanctuary && \
    visudo -cf /etc/sudoers.d/sanctuary

USER sanctuary
# GOTOOLCHAIN=local: the image is the only source of Go. If go.mod's floor
# ever passes the image's Go, builds fail with a clear error instead of
# quietly downloading a toolchain; that is the signal to bump GO_VERSION.
ENV GOPATH=/home/sanctuary/go \
    PATH=/usr/local/go/bin:/home/sanctuary/go/bin:/home/sanctuary/.local/bin:$PATH \
    GOTOOLCHAIN=local
WORKDIR /sanctuary/src
CMD ["/bin/bash"]
