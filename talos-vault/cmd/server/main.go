package main

import (
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
	
	"talos-vault/internal/auth"
	"talos-vault/internal/evidence"
	"talos-vault/internal/middleware"
	"talos-vault/internal/policy"
	"talos-vault/internal/sidecar"
)

func main() {
	fmt.Println("Starting Talos Vault (Hardened Mode)...")

	// 1. Initialize Components
	// Note: In production, handle errors gracefully rather than panicking.
	
	// Policy Engine (Task 1)
	policyEngine := policy.NewEngine()
	// Load some default policies for testing
	policyEngine.LoadPolicies(map[string][]policy.Policy{
		"system:serviceaccount:default:workload-a": {
			{Resource: "/SecretService/GetSecret", Action: "execute", Effect: "allow"},
		},
	})

	// K8s Verifier (Task 2)
	// Warning: This requires running inside a K8s cluster or having KUBECONFIG set.
	// For local dev without K8s, you might need a mock implementation.
	k8sVerifier, err := auth.NewK8sVerifier()
	if err != nil {
		log.Printf("Warning: Could not init K8s verifier (running local?): %v", err)
		// Proceeding with potential nil verifier for compilation check, 
		// but in prod this should fatal exit.
	}

	// Audit Ledger (Task 3)
	auditLedger := evidence.NewLedger()

	// Revocation List (Task 4)
	revocationList := sidecar.NewRevocationList()

	// 2. Setup Security Interceptor
	securityInterceptor := middleware.NewSecurityInterceptor(
		k8sVerifier,
		policyEngine,
		revocationList,
		auditLedger,
	)

	// 3. Start gRPC Server with Interceptor
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(securityInterceptor.UnaryInterceptor),
	)

	// Register your actual services here (IdentityService, PolicyService)
	// pb.RegisterSecretServiceServer(grpcServer, &mySecretService{})

	fmt.Printf("Talos Vault listening on :50051\n")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
