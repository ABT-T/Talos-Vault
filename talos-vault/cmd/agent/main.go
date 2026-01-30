package main

import (
    "context"
    "flag"
    "log"
    "time"

    "talos-vault/internal/mtls"
    pb "talos-vault/proto"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    serverAddr := flag.String("server", "127.0.0.1:50051", "Control Plane Address")
    subject := flag.String("sub", "user:alice", "Subject")
    action := flag.String("act", "read", "Action")
    flag.Parse()

    // 1. Setup mTLS
    tlsConfig, err := mtls.LoadClientTLS(mtls.Config{
        CertFile: "certs/client-cert.pem",
        KeyFile:  "certs/client-key.pem",
        CAFile:   "certs/ca-cert.pem",
    })
    if err != nil {
        log.Fatalf("TLS Error: %v", err)
    }

    // 2. Connect
    conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
    if err != nil {
        log.Fatalf("Connect Error: %v", err)
    }
    defer conn.Close()

    client := pb.NewAdminServiceClient(conn)
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    // 3. Sync Policies (Watch)
    stream, err := client.WatchPolicies(ctx, &pb.WatchRequest{NodeId: "agent-local-1"})
    if err != nil {
        log.Fatalf("Failed to watch policies: %v", err)
    }

    update, err := stream.Recv()
    if err != nil {
        log.Fatalf("Failed to receive policy snapshot: %v", err)
    }

    // 4. Local Decision
    allowed := false
    for _, p := range update.Policies {
        if p.Subject == *subject && p.Action == *action && p.Effect == "allow" {
            allowed = true
            break
        }
    }

    if allowed {
        log.Printf("✅ ACCESS GRANTED (Local Decision) | Subject=%s | Action=%s", *subject, *action)
    } else {
        log.Printf("⛔ ACCESS DENIED (Local Decision) | Subject=%s | Action=%s", *subject, *action)
    }
}