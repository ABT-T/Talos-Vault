package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "flag"
    "io/ioutil"
    "log"
    "os"
    // "time" REMOVED
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    pb "talos-vault/proto"
)

const k8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

func getToken(flagToken string) string {
    if flagToken != "" {
        return flagToken
    }
    if envToken := os.Getenv("K8S_TOKEN"); envToken != "" {
        return envToken
    }
    data, err := ioutil.ReadFile(k8sTokenPath)
    if err == nil {
        log.Printf("[Auth] Loaded token from %s", k8sTokenPath)
        return string(data)
    }
    return ""
}

func main() {
    serverAddr := flag.String("server", "localhost:50051", "Server address")
    nodeID := flag.String("node", "agent-win-01", "Node ID")
    tokenFlag := flag.String("token", "", "Manually provide a JWT token (Dev Mode)")
    
    certFile := flag.String("cert", "certs/agent.crt", "Cert file")
    keyFile := flag.String("key", "certs/agent.key", "Key file")
    caFile := flag.String("ca", "certs/ca.crt", "CA file")
    
    flag.Parse()

    // mTLS Setup
    clientCert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
    if err != nil {
        log.Printf("[mTLS] Failed to load client certs: %v", err)
    }
    caCert, err := ioutil.ReadFile(*caFile)
    if err != nil {
        log.Printf("[mTLS] Failed to load CA cert: %v", err)
    }
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{clientCert},
        RootCAs:      caCertPool,
        // InsecureSkipVerify: true, // Only use if hostnames don't match exactly
    }
    creds := credentials.NewTLS(tlsConfig)

    // Connect
    conn, err := grpc.Dial(*serverAddr, grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Fatalf("did not connect: %v", err)
    }
    defer conn.Close()

    client := pb.NewAdminServiceClient(conn)
    token := getToken(*tokenFlag)

    log.Printf("Connecting to %s as node %s...", *serverAddr, *nodeID)
    
    // Send Token in WatchRequest
    stream, err := client.WatchPolicies(context.Background(), &pb.WatchRequest{
        NodeId:    *nodeID,
        AuthToken: token,
    })
    if err != nil {
        log.Fatalf("Error calling WatchPolicies: %v", err)
    }

    log.Println("--- Connected. Waiting for Policy Updates ---")

    for {
        update, err := stream.Recv()
        if err != nil {
            log.Fatalf("Stream closed by server: %v", err)
        }
        log.Printf("\n[Policy Update Received] Count: %d", len(update.Policies))
        for _, p := range update.Policies {
            log.Printf("   ALLOW: %s -> %s (Effect: %s)", p.Subject, p.Action, p.Effect)
        }
    }
}