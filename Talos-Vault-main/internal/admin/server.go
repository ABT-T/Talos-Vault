package admin

import (
	"context"
	"log"
	"sync"

	"talos-vault/internal/storage"
	pb "talos-vault/proto"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ControlPlane implements the gRPC service for Admin and Sidecars
type ControlPlane struct {
	pb.UnimplementedAdminServiceServer
	store storage.Store

	// Streaming management
	mu          sync.RWMutex
	subscribers map[string]chan []*pb.Policy // Map of connected sidecar ID to their channel
}

// NewControlPlane creates the server instance
func NewControlPlane(store storage.Store) *ControlPlane {
	return &ControlPlane{
		store:       store,
		subscribers: make(map[string]chan []*pb.Policy),
	}
}

// UpdatePolicy is called by Admin CLI/API
func (s *ControlPlane) UpdatePolicy(ctx context.Context, req *pb.UpdatePolicyRequest) (*pb.UpdatePolicyResponse, error) {
	// 1. Persist to SQLite
	p := storage.Policy{
		Subject: req.Subject,
		Action:  req.Action,
		Effect:  req.Effect,
	}

	if err := s.store.SavePolicy(req.Subject, p); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save policy: %v", err)
	}

	// 2. Broadcast to all active Sidecars
	go s.broadcastUpdates()

	log.Printf("[ControlPlane] Policy updated for subject: %s", req.Subject)
	return &pb.UpdatePolicyResponse{Success: true}, nil
}

// WatchPolicies is the stream endpoint for Sidecars
func (s *ControlPlane) WatchPolicies(req *pb.WatchRequest, stream pb.AdminService_WatchPoliciesServer) error {
	sidecarID := req.NodeId
	updateChan := make(chan []*pb.Policy, 1) // Buffer 1 to prevent blocking

	// Register subscriber
	s.mu.Lock()
	s.subscribers[sidecarID] = updateChan
	s.mu.Unlock()

	log.Printf("[ControlPlane] Sidecar connected: %s", sidecarID)

	// Send initial snapshot immediately
	initialPolicies, _ := s.convertPoliciesToProto()
	if err := stream.Send(&pb.PolicyUpdate{Policies: initialPolicies}); err != nil {
		return err
	}

	// Keep stream open and listen for updates
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, sidecarID)
		close(updateChan)
		s.mu.Unlock()
		log.Printf("[ControlPlane] Sidecar disconnected: %s", sidecarID)
	}()

	for {
		select {
		case policies := <-updateChan:
			// Push update to Sidecar
			if err := stream.Send(&pb.PolicyUpdate{Policies: policies}); err != nil {
				return status.Errorf(codes.Unavailable, "stream broken")
			}
		case <-stream.Context().Done():
			return status.Error(codes.Canceled, "connection closed")
		}
	}
}

// broadcastUpdates fetches all policies and pushes to channels
func (s *ControlPlane) broadcastUpdates() {
	policies, err := s.convertPoliciesToProto()
	if err != nil {
		log.Printf("Error fetching policies for broadcast: %v", err)
		return
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for id, ch := range s.subscribers {
		select {
		case ch <- policies:
			// Sent
		default:
			log.Printf("Sidecar %s is lagging, skipping update", id)
		}
	}
}

// Helper to convert internal storage types to Protobuf types
func (s *ControlPlane) convertPoliciesToProto() ([]*pb.Policy, error) {
	stored, err := s.store.GetAllPolicies()
	if err != nil {
		return nil, err
	}

	var pbPolicies []*pb.Policy
	for subj, list := range stored {
		for _, p := range list {
			pbPolicies = append(pbPolicies, &pb.Policy{
				Subject: subj,
				Action:  p.Action,
				Effect:  p.Effect,
			})
		}
	}
	return pbPolicies, nil
}
