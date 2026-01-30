package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "flag"
    "io/ioutil"
    "log"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    pb "talos-vault/proto"
)

func main() {
    subject := flag.String("sub", "user:alice", "Subject")
    action := flag.String("act", "read", "Action")
    effect := flag.String("eff", "allow", "Effect")
    flag.Parse()

    // mTLS Setup (Admin acts like a client)
    cert, _ := tls.LoadX509KeyPair("certs/agent.crt", "certs/agent.key") // Using agent certs for simplicity
    caCert, _ := ioutil.ReadFile("certs/ca.crt")
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    creds := credentials.NewTLS(&tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
    })

    conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Fatalf("Fail to dial: %v", err)
    }
    defer conn.Close()

    client := pb.NewAdminServiceClient(conn)

    log.Printf("Adding Policy: %s can %s -> %s", *subject, *action, *effect)

    // In a real system, we would send a token here too, 
    // but for now UpdatePolicy doesn't enforce Auth in the proto (simplification)
    _, err = client.UpdatePolicy(context.Background(), &pb.UpdatePolicyRequest{
        Subject: *subject,
        Action:  *action,
        Effect:  *effect,
    })

    if err != nil {
        log.Fatalf("Update failed: %v", err)
    }
    log.Println("✅ Policy Added Successfully!")
}