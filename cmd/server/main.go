package main

import (
    "crypto/tls"
    "crypto/x509"
    "flag"
    "io/ioutil"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"

    "talos-vault/internal/admin"
    pb "talos-vault/proto"
)

func main() {
    // Flags
    port := flag.String("port", ":50051", "gRPC server port")
    dbPath := flag.String("db", ":memory:", "Path to SQLite DB (default: in-memory)")
    
    // Cert Flags
    certFile := flag.String("cert", "certs/server.crt", "Server Cert file")
    keyFile := flag.String("key", "certs/server.key", "Server Key file")
    caFile := flag.String("ca", "certs/ca.crt", "CA Cert file")

    flag.Parse()

    // 1. Initialize Control Plane (Logic + DB + Auth)
    // Note: CGO is disabled, so SQLite acts as in-memory or pure Go fallback if configured
    controlPlane, err := admin.NewControlPlane(*dbPath)
    if err != nil {
        log.Fatalf("Failed to initialize Control Plane: %v", err)
    }

    // 2. Setup mTLS
    // Load server's certificate and private key
    serverCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
    if err != nil {
        log.Fatalf("Failed to load server certs: %v", err)
    }

    // Load CA certificate to verify agents
    caCert, err := ioutil.ReadFile(*caFile)
    if err != nil {
        log.Fatalf("Failed to load CA cert: %v", err)
    }
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{serverCert},
        ClientCAs:    caCertPool,
        ClientAuth:   tls.RequireAndVerifyClientCert, // Enforce mTLS
    }
    creds := credentials.NewTLS(tlsConfig)

    // 3. Start Listener
    lis, err := net.Listen("tcp", *port)
    if err != nil {
        log.Fatalf("failed to listen: %v", err)
    }

    // 4. Create gRPC Server
    grpcServer := grpc.NewServer(grpc.Creds(creds))
    
    // Register the service
    pb.RegisterAdminServiceServer(grpcServer, controlPlane)

    // Graceful Shutdown Handling
    go func() {
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
        <-sigCh
        log.Println("Shutting down server...")
        grpcServer.GracefulStop()
    }()

    log.Printf("Talos Control Plane running on %s (DB: %s)", *port, *dbPath)
    if err := grpcServer.Serve(lis); err != nil {
        log.Fatalf("failed to serve: %v", err)
    }
}