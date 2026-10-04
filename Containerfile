# Multi-arch build: podman build --platform linux/amd64,linux/arm64 --manifest jmap-mcp .
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.27 AS build
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
FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/jmap-mcp /usr/local/bin/jmap-mcp
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/jmap-mcp"]
