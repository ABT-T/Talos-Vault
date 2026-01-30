FROM golang:alpine AS builder

WORKDIR /app

# Copy modules first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build Controller and Sidecar (Statically linked)
RUN CGO_ENABLED=0 go build -o /bin/controller ./cmd/controller
RUN CGO_ENABLED=0 go build -o /bin/sidecar ./cmd/sidecar

# Stage 2: Create secure runtime image (Distroless)
FROM gcr.io/distroless/static-debian12

WORKDIR /

# Copy binaries from builder
COPY --from=builder /bin/controller /controller
COPY --from=builder /bin/sidecar /sidecar

# Copy default config
COPY config/policies.json /config/policies.json

# Expose gRPC port
EXPOSE 8443

# Default entrypoint
ENTRYPOINT ["/controller"]
