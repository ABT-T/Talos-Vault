# Stage 1: Builder
FROM golang:1.25 AS builder

WORKDIR /src
COPY . .
RUN go mod download

# Build directly to a file named "server"
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o server cmd/controller/main.go

# Stage 2: Runner
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# Copy "server" binary to root
COPY --from=builder /src/server /server

# Explicit entrypoint
ENTRYPOINT ["/server"]