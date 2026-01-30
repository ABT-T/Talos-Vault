package auth

import (
    "context"
    "fmt"
    "log"
)

// Authenticator acts as a mock for development.
type Authenticator struct {}

// NewK8sAuthenticator returns a lightweight mock.
func NewK8sAuthenticator() (*Authenticator, error) {
    log.Println("[Auth] Running in LIGHTWEIGHT MOCK mode (No K8s connection)")
    return &Authenticator{}, nil
}

// VerifyToken simulates the TokenReview API.
func (a *Authenticator) VerifyToken(ctx context.Context, token string) (string, error) {
    // Simple Logic for Dev:
    if token == "fake-token" {
        return "user:alice", nil
    }
    if token == "agent-token" {
        return "system:serviceaccount:default:my-agent", nil
    }
    return "", fmt.Errorf("invalid token (mock)")
}