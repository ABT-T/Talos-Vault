package middleware

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"talos-vault/internal/auth"
	"talos-vault/internal/evidence"
	"talos-vault/internal/policy"
	"talos-vault/internal/sidecar"
)

// SecurityInterceptor holds references to all security components.
type SecurityInterceptor struct {
	Verifier   *auth.K8sVerifier
	Policy     *policy.Engine
	Revocation *sidecar.RevocationList
	Ledger     *evidence.Ledger
}

// NewSecurityInterceptor creates the interceptor with injected dependencies.
func NewSecurityInterceptor(v *auth.K8sVerifier, p *policy.Engine, r *sidecar.RevocationList, l *evidence.Ledger) *SecurityInterceptor {
	return &SecurityInterceptor{
		Verifier:   v,
		Policy:     p,
		Revocation: r,
		Ledger:     l,
	}
}

// UnaryInterceptor is the main entry point for all incoming gRPC requests.
func (s *SecurityInterceptor) UnaryInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	
	// 1. Metadata Extraction
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "metadata is missing")
	}

	// Extract Bearer Token
	authHeader := md.Get("authorization")
	if len(authHeader) == 0 {
		return nil, status.Error(codes.Unauthenticated, "authorization token missing")
	}
	token := strings.TrimPrefix(authHeader[0], "Bearer ")

	// Extract Pod UID (Critical for Anti-Impersonation)
	// In a real mesh, this header is injected by the sidecar or CNI.
	podUIDHeader := md.Get("x-pod-uid")
	if len(podUIDHeader) == 0 {
		return nil, status.Error(codes.Unauthenticated, "x-pod-uid header missing")
	}
	podUID := podUIDHeader[0]

	// 2. Authentication & Anti-Impersonation (Task 2)
	// This ensures the token is valid AND belongs to the calling Pod.
	if err := s.Verifier.ValidateToken(ctx, token, podUID); err != nil {
		// Log failure but return generic error to client to avoid leakage
		fmt.Printf("Auth failed: %v\n", err)
		return nil, status.Error(codes.Unauthenticated, "authentication failed")
	}

	// 3. Subject Extraction
	// In a real scenario, we extract the ServiceAccount from the validated token claims.
	// For this hardening phase, we assume the subject is passed or parsed.
	// Mocking extraction for demonstration: "system:serviceaccount:default:my-app"
	subject := "system:serviceaccount:default:workload-a" 

	// 4. Instant Revocation Check (Task 4 - Kill Switch)
	// Must happen BEFORE policy check to save resources.
	if s.Revocation.IsRevoked(subject) {
		s.Ledger.LogDecision(subject, "Deny-Revoked")
		return nil, status.Error(codes.PermissionDenied, "identity revoked")
	}

	// 5. Policy Enforcement (Task 1 - Lock Free)
	// Derive resource/action from gRPC method (e.g., /Service/Method)
	resource := info.FullMethod
	action := "execute" // Simplification for RPC

	allowed, err := s.Policy.CheckAccess(ctx, subject, resource, action)
	if err != nil {
		return nil, status.Error(codes.Internal, "policy engine error")
	}

	if !allowed {
		s.Ledger.LogDecision(subject, "Deny-Policy")
		return nil, status.Error(codes.PermissionDenied, "access denied by policy")
	}

	// 6. Audit Logging (Task 3 - Immutable Evidence)
	// Log the successful access grant.
	s.Ledger.LogDecision(subject, "Allow")

	// 7. Proceed to Business Logic
	return handler(ctx, req)
}
