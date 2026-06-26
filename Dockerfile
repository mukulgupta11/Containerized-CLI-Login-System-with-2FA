# ==============================================================================
# Builder Stage
# ==============================================================================
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy dependency manifests
COPY go.mod ./
# Note: we will let go mod download fetch the packages.
RUN go mod download

# Copy the source code
COPY . .

# Build the statically linked Go binary
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o /app/cli-login \
    ./cmd/cli/main.go

# ==============================================================================
# Runner Stage
# ==============================================================================
FROM alpine:3.18

RUN apk add --no-cache ca-certificates tzdata

# Create a non-root system user and group for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /home/appuser

# Copy compile binary from builder
COPY --from=builder /app/cli-login /usr/local/bin/cli-login

# Change ownership of the home directory to appuser
RUN chown -R appuser:appgroup /home/appuser

# Switch to the non-root user
USER appuser

# Set the interactive CLI as entrypoint
ENTRYPOINT ["cli-login"]
