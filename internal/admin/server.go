package admin

import (
    "context"
    "encoding/json"
    "fmt"
    // "io/ioutil" removed - causing compile error
    "log"
    "os"
    "sync"
    "time"

    "talos-vault/internal/auth"
    pb "talos-vault/proto"
)

const dbFile = "policies.json"

type ControlPlane struct {
    pb.UnimplementedAdminServiceServer
    policies    []*pb.Policy
    clients     map[string]chan []*pb.Policy 
    mu          sync.RWMutex
    auth        *auth.Authenticator
}

func NewControlPlane(dbPath string) (*ControlPlane, error) {
    // Initialize Mock Auth
    k8sAuth, err := auth.NewK8sAuthenticator()
    if err != nil {
        log.Printf("[WARNING] Auth init failed: %v", err)
    }

    cp := &ControlPlane{
        policies: make([]*pb.Policy, 0),
        clients:  make(map[string]chan []*pb.Policy),
        auth:     k8sAuth,
    }

    // Load existing policies from JSON file
    if err := cp.loadFromDisk(); err != nil {
        log.Printf("[Storage] No existing DB found. Created new: %s", dbFile)
    } else {
        log.Printf("[Storage] Loaded %d policies from %s", len(cp.policies), dbFile)
    }

    return cp, nil
}

// loadFromDisk reads policies.json
func (s *ControlPlane) loadFromDisk() error {
    file, err := os.Open(dbFile)
    if err != nil {
        return err // File likely doesn't exist yet
    }
    defer file.Close()

    decoder := json.NewDecoder(file)
    return decoder.Decode(&s.policies)
}

// saveToDisk writes policies.json
func (s *ControlPlane) saveToDisk() error {
    file, err := os.Create(dbFile)
    if err != nil {
        return err
    }
    defer file.Close()

    encoder := json.NewEncoder(file)
    encoder.SetIndent("", "  ") // Make it pretty/readable
    return encoder.Encode(s.policies)
}

func (s *ControlPlane) WatchPolicies(req *pb.WatchRequest, stream pb.AdminService_WatchPoliciesServer) error {
    log.Printf("[Connection] Agent Connecting: %s", req.NodeId)

    // Auth Check
    if s.auth != nil {
        if req.AuthToken == "" {
            return fmt.Errorf("authentication required")
        }
        sa, err := s.auth.VerifyToken(stream.Context(), req.AuthToken)
        if err != nil {
            log.Printf("[Auth Failed] %s: %v", req.NodeId, err)
            return fmt.Errorf("invalid token")
        }
        log.Printf("[Auth Success] %s authenticated as %s", req.NodeId, sa)
    }

    updateChan := make(chan []*pb.Policy, 1)
    s.mu.Lock()
    s.clients[req.NodeId] = updateChan
    s.mu.Unlock()

    defer func() {
        s.mu.Lock()
        delete(s.clients, req.NodeId)
        s.mu.Unlock()
        close(updateChan)
    }()

    // Send current state immediately
    s.mu.RLock()
    initial := make([]*pb.Policy, len(s.policies))
    copy(initial, s.policies)
    s.mu.RUnlock()

    if err := stream.Send(&pb.PolicyUpdate{Policies: initial}); err != nil {
        return err
    }

    // Keep stream alive
    ctx := stream.Context()
    for {
        select {
        case <-ctx.Done():
            return nil
        case policies := <-updateChan:
            if err := stream.Send(&pb.PolicyUpdate{Policies: policies}); err != nil {
                return err
            }
        case <-time.After(30 * time.Second):
            // heartbeat
        }
    }
}

func (s *ControlPlane) UpdatePolicy(ctx context.Context, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    newPolicy := &pb.Policy{
        Subject: req.Subject,
        Action:  req.Action,
        Effect:  req.Effect,
    }
    s.policies = append(s.policies, newPolicy)

    // Save to JSON file immediately
    if err := s.saveToDisk(); err != nil {
        log.Printf("[Storage Error] Failed to save: %v", err)
        return &pb.UpdatePolicyResponse{Success: false, ErrorMessage: "Failed to persist"}, nil
    }

    log.Printf("[Policy] Added & Saved: %s", req.Subject)

    // Broadcast
    policiesCopy := make([]*pb.Policy, len(s.policies))
    copy(policiesCopy, s.policies)

    for _, ch := range s.clients {
        select {
        case ch <- policiesCopy:
        default:
        }
    }

    return &pb.UpdatePolicyResponse{Success: true}, nil
}

func (s *ControlPlane) getAllPolicies() ([]*pb.Policy, error) {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    policiesCopy := make([]*pb.Policy, len(s.policies))
    copy(policiesCopy, s.policies)
    
    return policiesCopy, nil
}