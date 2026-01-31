package admin

import (
    "context"
    "log"
    "os"
    "sync"

    pb "talos-vault/proto"
)

// Server implements the AdminService
type Server struct {
    pb.UnimplementedAdminServiceServer
    mu sync.Mutex // Mutex for file writing safety
}

// NewServer creates a new Admin Server instance
func NewServer() *Server {
    return &Server{}
}

// GetPolicy returns a list of sample policies for the agent
func (s *Server) GetPolicy(ctx context.Context, req *pb.Empty) (*pb.PolicyResponse, error) {
    log.Println("Received GetPolicy request")

    // Define dynamic policies (Mock Database)
    policies := []*pb.Policy{
        {Subject: "admin", Resource: "/dashboard", Action: "GET", Effect: "Allow"},
        {Subject: "admin", Resource: "/settings", Action: "POST", Effect: "Allow"},
        {Subject: "guest", Resource: "/public", Action: "GET", Effect: "Allow"},
        {Subject: "stranger", Resource: "*", Action: "*", Effect: "Deny"},
    }

    return &pb.PolicyResponse{Policies: policies}, nil
}

// ReportAudit handles receiving audit logs from agents and writing them to a file
func (s *Server) ReportAudit(ctx context.Context, req *pb.AuditLog) (*pb.Empty, error) {
    s.mu.Lock()
    defer s.mu.Unlock()

    // Append log to a local file
    f, err := os.OpenFile("central_audit.log", os.O_APPEND|os.O_CREATE|os.O_WRITING, 0644)
    if err != nil {
        log.Printf("Failed to open audit log file: %v", err)
        return &pb.Empty{}, nil
    }
    defer f.Close()

    logEntry := "RequestId: " + req.RequestId + " | User: " + req.User + " | Action: " + req.Action + " | Decision: " + req.Decision + "\n"
    if _, err := f.WriteString(logEntry); err != nil {
        log.Printf("Failed to write to audit log: %v", err)
    }

    log.Printf("Audit logged: %s", logEntry)
    return &pb.Empty{}, nil
}
