package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"talos-vault/internal/mtls"
	pb "talos-vault/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	// 1. Define Command Line Flags
	subject := flag.String("sub", "", "Subject (e.g., user:alice)")
	action := flag.String("act", "", "Action (e.g., read)")
	effect := flag.String("eff", "deny", "Effect (allow/deny)")
	serverAddr := flag.String("server", "localhost:50051", "Control Plane Address")
	
	flag.Parse()

	if *subject == "" || *action == "" {
		log.Fatal("Error: -sub and -act are required. Usage: talosctl -sub user:1 -act read -eff allow")
	}

	// 2. Load mTLS Credentials
	// In a real env, admins might have different certs than agents, 
	// but for this MVP we reuse the client certs.
	tlsConfig, err := mtls.LoadClientTLS(mtls.Config{
		CertFile: "certs/client-cert.pem",
		KeyFile:  "certs/client-key.pem",
		CAFile:   "certs/ca-cert.pem",
	})
	if err != nil {
		log.Fatalf("Failed to load TLS config: %v", err)
	}
	creds := credentials.NewTLS(tlsConfig)

	// 3. Connect Securely
	conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewAdminServiceClient(conn)

	// 4. Send Request
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	req := &pb.UpdatePolicyRequest{
		Subject: *subject,
		Action:  *action,
		Effect:  *effect,
	}

	resp, err := client.UpdatePolicy(ctx, req)
	if err != nil {
		log.Fatalf("Error updating policy: %v", err)
	}

	if resp.Success {
		fmt.Printf("✅ [SECURE] Policy applied successfully!\nSubject: %s\nAction:  %s\nEffect:  %s\n", 
			*subject, *action, *effect)
	} else {
		fmt.Printf("❌ Policy failed: %s\n", resp.ErrorMessage)
	}
}
