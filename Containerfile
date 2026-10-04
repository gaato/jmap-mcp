# Multi-arch build: podman build --platform linux/amd64,linux/arm64 --manifest jmap-mcp .
#
# Base images are pinned by multi-arch index digest (looked up 2026-10-05 with
# `skopeo inspect --format '{{.Digest}}' docker://<image>`). To update, rerun
# that command for the tag in the comment and replace the digest.
# golang:1.27
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27@sha256:e0174e51e81218523251d85d248a90d24c3d5e81543b4f07a5d66229397db190 AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X github.com/gaato/jmap-mcp/internal/server.Version=${VERSION}" \
    -o /out/jmap-mcp ./cmd/jmap-mcp

# distroless/static ships CA certificates and a nonroot user (65532), nothing else.
# distroless/static:nonroot
FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/jmap-mcp /usr/local/bin/jmap-mcp
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/jmap-mcp"]
