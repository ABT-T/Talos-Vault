package policy

import (
	"context"
	"log"

	v1 "github.com/yourorg/talos-vault/api/v1"
)

// PolicyService implements v1.PolicyServiceServer
type PolicyService struct {
	v1.UnimplementedPolicyServiceServer
	engine *Engine
}

// NewPolicyService creates a new policy service
func NewPolicyService(engine *Engine) *PolicyService {
	return &PolicyService{
		engine: engine,
	}
}

// Check implements the Check RPC for policy evaluation
func (s *PolicyService) Check(ctx context.Context, req *v1.CheckRequest) (*v1.CheckResponse, error) {
	log.Printf("[PolicyService] Check request - Subject: %s, Action: %s, Target: %s", req.Subject, req.Action, req.Target)

	// Evaluate the policy
	allowed := s.engine.Evaluate(req.Subject, req.Action, req.Target, req.Context)

	reason := ""
	if !allowed {
		reason = "policy evaluation denied the request"
	} else {
		reason = "policy evaluation allowed the request"
	}

	log.Printf("[PolicyService] Check result - Allowed: %v, Reason: %s", allowed, reason)

	return &v1.CheckResponse{
		Allowed: allowed,
		Reason:  reason,
	}, nil
}
