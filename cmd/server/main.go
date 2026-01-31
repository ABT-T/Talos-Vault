package main

import (
    "crypto/tls"
    "crypto/x509"
    "fmt"
    "log"
    "net"
    "os"

    "github.com/example/talos-vault/internal/admin"
    pb "github.com/example/talos-vault/proto"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    port := ":50051"
    lis, err := net.Listen("tcp", port)
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }

    // 1. Load the CA certificate (to verify the Agent/Client)
    pemClientCA, err := os.ReadFile("certs/ca.crt")
    if err != nil {
        log.Fatalf("Failed to load CA cert: %v", err)
    }

    certPool := x509.NewCertPool()
    if !certPool.AppendCertsFromPEM(pemClientCA) {
        log.Fatalf("Failed to append CA cert to pool")
    }

    // 2. Load Server's certificate and private key
    serverCert, err := tls.LoadX509KeyPair("certs/server.crt", "certs/server.key")
    if err != nil {
        log.Fatalf("Failed to load server certs: %v", err)
    }

    // 3. Configure mTLS
    config := &tls.Config{
        Certificates: []tls.Certificate{serverCert},
        ClientAuth:   tls.RequireAndVerifyClientCert, // <--- CRITICAL: Enforce mTLS
        ClientCAs:    certPool,                       // Trust clients signed by our CA
    }
    
    creds := credentials.NewTLS(config)
    s := grpc.NewServer(grpc.Creds(creds))

    // Register Services
    adminServer := admin.NewServer()
    pb.RegisterAdminServiceServer(s, adminServer)

    fmt.Printf("[Control Plane] Server listening on %s (mTLS Enabled)\n", port)
    if err := s.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}