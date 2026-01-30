package auth

import (
	"errors"
	"fmt"
	"log"
)

// TokenReviewer mimics the K8s TokenReview API interface.
type TokenReviewer interface {
	Review(token string) (string, string, error) // Returns (serviceAccount, namespace, error)
}

// K8sTokenValidator implements actual validation logic.
type K8sTokenValidator struct {
	// In a real implementation, this holds the K8s ClientSet
}

// NewK8sValidator creates a validator.
func NewK8sValidator() *K8sTokenValidator {
	return &K8sTokenValidator{}
}

// Validate mimics checking the token against the K8s API server.
// SECURITY NOTE: In production, this MUST call the K8s TokenReview API.
// For this standalone implementation, we simulate validation of a "valid" mock token.
func (v *K8sTokenValidator) Review(token string) (string, string, error) {
	// SIMULATION: If token starts with "valid-jwt", we accept it.
	// Real code would use `clientset.AuthenticationV1().TokenReviews().Create(...)`
	if token == "valid-jwt-token-for-demo" {
		log.Println("Validating simulated K8s token...")
		return "ai-agent", "default", nil
	}
	return "", "", errors.New("invalid service account token")
}

// GenerateSPIFFEID creates the standardized ID string.
func GenerateSPIFFEID(namespace, serviceAccount string) string {
	return fmt.Sprintf("spiffe://cluster.local/ns/%s/sa/%s", namespace, serviceAccount)
}
