package main

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "net/http"
    "os"
    "sync"
    "time"

    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    pb "talos-vault/proto"
)

// --- Global State ---
var (
    auditChannel = make(chan *pb.AuditLog, 100)
    
    // Policy Store protected by RWMutex for thread safety
    policyStore []*pb.Policy
    policyMu    sync.RWMutex
)

const (
    serverAddr    = "localhost:50051"
    certFile      = "certs/client.crt"
    keyFile       = "certs/client.key"
    caFile        = "certs/ca.crt"
    policyCacheFile = "policy_cache.json"
)

// --- Policy Management ---

// loadPolicies attempts to fetch from Server, falls back to Cache
func loadPolicies(client pb.AdminServiceClient) {
    log.Println("Attempting to fetch policies from Control Plane...")
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    resp, err := client.GetPolicy(ctx, &pb.Empty{})
    if err == nil {
        // Success: Update memory and cache to disk
        updatePolicyMemory(resp.Policies)
        savePoliciesToCache(resp.Policies)
        log.Printf("Successfully fetched %d policies from Server.", len(resp.Policies))
        return
    }

    log.Printf("Failed to connect to Server: %v. Switching to Offline Mode.", err)
    loadPoliciesFromCache()
}

// updatePolicyMemory updates the in-memory slice safely
func updatePolicyMemory(policies []*pb.Policy) {
    policyMu.Lock()
    defer policyMu.Unlock()
    policyStore = policies
}

// savePoliciesToCache writes policies to a JSON file
func savePoliciesToCache(policies []*pb.Policy) {
    data, err := json.MarshalIndent(policies, "", "  ")
    if err != nil {
        log.Printf("Error marshaling policies for cache: %v", err)
        return
    }
    err = ioutil.WriteFile(policyCacheFile, data, 0644)
    if err != nil {
        log.Printf("Error writing policy cache file: %v", err)
    } else {
        log.Println("Policies cached to disk.")
    }
}

// loadPoliciesFromCache reads policies from the JSON file
func loadPoliciesFromCache() {
    data, err := ioutil.ReadFile(policyCacheFile)
    if err != nil {
        log.Printf("No local policy cache found or readable (%v). Defaulting to DENY ALL.", err)
        updatePolicyMemory([]*pb.Policy{}) // Empty list effectively denies everything
        return
    }

    var policies []*pb.Policy
    if err := json.Unmarshal(data, &policies); err != nil {
        log.Printf("Error parsing policy cache: %v. Defaulting to DENY ALL.", err)
        updatePolicyMemory([]*pb.Policy{})
        return
    }

    updatePolicyMemory(policies)
    log.Printf("Loaded %d policies from local cache.", len(policies))
}

// checkPolicy iterates through loaded policies to find a match
func checkPolicy(subject, resource, action string) (bool, string) {
    policyMu.RLock()
    defer policyMu.RUnlock()

    for _, p := range policyStore {
        // Simple exact match logic (can be expanded to regex later)
        // Wildcard '*' handling for Resource and Action
        resourceMatch := (p.Resource == resource) || (p.Resource == "*")
        actionMatch := (p.Action == action) || (p.Action == "*")
        
        if p.Subject == subject && resourceMatch && actionMatch {
            if p.Effect == "Allow" {
                return true, "Allowed by policy"
            }
            return false, "Explicitly Denied by policy"
        }
    }
    return false, "No matching policy found (Default Deny)"
}

// --- HTTP Handler (PEP) ---

func pepHandler(w http.ResponseWriter, r *http.Request) {
    user := r.Header.Get("X-User")
    if user == "" {
        user = "guest"
    }
    
    resource := r.URL.Path
    action := r.Method

    // Dynamic Policy Decision
    allowed, reason := checkPolicy(user, resource, action)

    decision := "Block"
    if allowed {
        decision = "Allow"
        w.WriteHeader(http.StatusOK)
        fmt.Fprintf(w, "Access Granted to %s for user %s\n", resource, user)
    } else {
        w.WriteHeader(http.StatusForbidden)
        fmt.Fprintf(w, "Access Denied: %s\n", reason)
    }

    // Async Audit Log
    auditChannel <- &pb.AuditLog{
        RequestId: fmt.Sprintf("%d", time.Now().UnixNano()),
        User:      user,
        Resource:  resource,
        Action:    action,
        Decision:  decision,
    }
}

// --- Background Workers ---

func auditWorker(client pb.AdminServiceClient) {
    for logEntry := range auditChannel {
        ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        _, err := client.ReportAudit(ctx, logEntry)
        if err != nil {
            log.Printf("Failed to send audit log: %v", err)
            // In a real system, we might buffer these locally if sending fails
        }
        cancel()
    }
}

// --- Main ---

func main() {
    // 1. Setup mTLS Credentials
    cert, err := tls.LoadX509KeyPair(certFile, keyFile)
    if err != nil {
        log.Fatalf("Failed to load client certs: %v", err)
    }

    caCert, err := ioutil.ReadFile(caFile)
    if err != nil {
        log.Fatalf("Failed to read CA cert: %v", err)
    }
    caCertPool := x509.NewCertPool()
    caCertPool.AppendCertsFromPEM(caCert)

    creds := credentials.NewTLS(&tls.Config{
        Certificates: []tls.Certificate{cert},
        RootCAs:      caCertPool,
        ServerName:   "localhost", // Must match Server's cert CN
    })

    // 2. Connect to Control Plane (gRPC)
    conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Printf("Startup Warning: Could not connect to gRPC server: %v", err)
        // We do NOT fatal here, so we can try offline mode
    } else {
        defer conn.Close()
    }

    // Create Client
    // Note: If connection failed, conn is not nil but state is transient. 
    // The client calls will fail, triggering our fail-safe logic.
    client := pb.NewAdminServiceClient(conn)

    // 3. Initial Policy Load (Fail-Safe)
    loadPolicies(client)

    // 4. Start Background Workers
    go auditWorker(client)

    // 5. Start HTTP Server (Data Plane)
    http.HandleFunc("/", pepHandler)
    log.Println("Agent (Data Plane) listening on :8080 (HTTPS/mTLS not enforced on entry yet, just logic)")
    
    // For this phase, we use simple HTTP for the entry point as per previous context
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatalf("Failed to start HTTP server: %v", err)
    }
}
