package auth

import (
	"context"
	"fmt"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// K8sVerifier handles secure token verification against the Kubernetes API.
type K8sVerifier struct {
	client kubernetes.Interface
}

// NewK8sVerifier creates a verifier using in-cluster configuration.
func NewK8sVerifier() (*K8sVerifier, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load in-cluster config: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	return &K8sVerifier{client: clientset}, nil
}

// ValidateToken performs a rigorous check of the ServiceAccount token.
// It verifies validity via TokenReview AND prevents impersonation by checking Pod UID.
func (k *K8sVerifier) ValidateToken(ctx context.Context, token string, claimedPodUID string) error {
	tr := &authv1.TokenReview{
		Spec: authv1.TokenReviewSpec{
			Token: token,
		},
	}

	// 1. Call K8s API to verify signature and expiration.
	result, err := k.client.AuthenticationV1().TokenReviews().Create(ctx, tr, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("token review failed: %w", err)
	}

	if !result.Status.Authenticated {
		return fmt.Errorf("token invalid: %s", result.Status.Error)
	}

	// 2. CRITICAL: Anti-Impersonation Check.
	// We must verify that the token actually belongs to the specific Pod instance
	// that is making the request.
	
	// The extra fields usually contain: authentication.kubernetes.io/pod-uid
	userInfo := result.Status.User
	extractedUIDs, ok := userInfo.Extra["authentication.kubernetes.io/pod-uid"]
	
	if !ok || len(extractedUIDs) == 0 {
		return fmt.Errorf("security alert: token does not contain pod-uid binding")
	}

	// 3. Match the extracted UID against the claimed UID.
	matched := false
	for _, uid := range extractedUIDs {
		if uid == claimedPodUID {
			matched = true
			break
		}
	}

	if !matched {
		// Log this strictly - it implies a replay attack or token theft attempt.
		return fmt.Errorf("security violation: pod UID mismatch. Claimed: %s, Token bound to: %v", claimedPodUID, extractedUIDs)
	}

	return nil
}
