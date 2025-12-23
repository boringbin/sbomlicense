FROM golang:1.25.5@sha256:36b4f45d2874905b9e8573b783292629bcb346d0a70d8d7150b6df545234818f AS builder

WORKDIR /app

# Download and install dependencies
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

# Build the binary
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -v -ldflags="-w -s" -o sbomlicensed ./cmd/sbomlicensed

FROM alpine:latest@sha256:4b7ce07002c69e8f3d704a9c5d6fd3053be500b7f1c69fc0d80990c2ad8dd412 AS runner

RUN apk --no-cache add ca-certificates

WORKDIR /app
COPY --from=builder /app/sbomlicensed /usr/local/bin/sbomlicensed
# The data/ directory is the default cache path
COPY data/ ./data/
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["sbomlicensed"]
