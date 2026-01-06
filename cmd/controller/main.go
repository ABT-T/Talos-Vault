package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"talos-vault/internal/admin"
	"talos-vault/internal/mtls"
	"talos-vault/internal/storage"
	pb "talos-vault/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

func main() {
	// 1. Setup mTLS
	tlsConfig, err := mtls.LoadServerTLS(mtls.Config{
		CertFile: "certs/server-cert.pem",
		KeyFile:  "certs/server-key.pem",
		CAFile:   "certs/ca-cert.pem",
	})
	if err != nil {
		log.Fatalf("Failed to load TLS: %v", err)
	}
	creds := credentials.NewTLS(tlsConfig)

	// 2. Initialize Storage
	store, err := storage.NewSQLiteStore("talos.db")
	if err != nil {
		log.Fatalf("Failed to init storage: %v", err)
	}
	defer store.Close()

	// 3. Initialize Control Plane
	controlPlane := admin.NewControlPlane(store)

	// 4. Start Secure gRPC Server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Passing TLS credentials here
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	
	pb.RegisterAdminServiceServer(grpcServer, controlPlane)
	reflection.Register(grpcServer)

	log.Println("🔒 Talos Vault Control Plane running (mTLS Enabled) on :50051")

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	<-stop
	log.Println("Shutting down...")
	grpcServer.GracefulStop()
}
