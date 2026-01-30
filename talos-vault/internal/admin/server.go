package admin

import (
    "context"
    "log"
    "time"

    "talos-vault/internal/storage"
    pb "talos-vault/proto"
)

type ControlPlane struct {
    pb.UnimplementedAdminServiceServer
    Store storage.Store
}

func NewControlPlane(store storage.Store) *ControlPlane {
    return &ControlPlane{Store: store}
}

// UpdatePolicy: Admin adds a new rule
func (s *ControlPlane) UpdatePolicy(ctx context.Context, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error) {
    log.Printf("[Audit] Update Policy Request: %s wants to %s", req.Subject, req.Action)
    
    p := storage.Policy{
        Subject: req.Subject,
        Action:  req.Action,
        Effect:  req.Effect,
    }

    if err := s.Store.SavePolicy(req.Subject, p); err != nil {
        return &pb.UpdatePolicyResponse{Success: false, ErrorMessage: err.Error()}, nil
    }

    return &pb.UpdatePolicyResponse{Success: true}, nil
}

// WatchPolicies: Agents sync policies
func (s *ControlPlane) WatchPolicies(req *pb.WatchRequest, stream pb.AdminService_WatchPoliciesServer) error {
    log.Printf("[Connection] New Agent Connected: %s", req.NodeId)

    // 1. Fetch all policies
    allData, err := s.Store.GetAllPolicies()
    if err != nil {
        log.Printf("Error fetching policies: %v", err)
        return err
    }

    // 2. Convert to Proto
    var protoPolicies []*pb.Policy
    for _, rules := range allData {
        for _, r := range rules {
            protoPolicies = append(protoPolicies, &pb.Policy{
                Subject: r.Subject,
                Action:  r.Action,
                Effect:  r.Effect,
            })
        }
    }

    // 3. Send Snapshot
    update := &pb.PolicyUpdate{
        Policies: protoPolicies,
    }
    if err := stream.Send(update); err != nil {
        return err
    }

    // 4. Keep Stream Open (MVP)
    select {
    case <-stream.Context().Done():
        log.Printf("[Connection] Agent %s disconnected", req.NodeId)
        return nil
    case <-time.After(1 * time.Hour):
        return nil
    }
}