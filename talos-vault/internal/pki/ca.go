package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// InternalCA manages the root certificate and signs workload certificates.
// SECURITY NOTE: In production, the Root Key should be stored in an HSM or Vault, never in memory like this.
type InternalCA struct {
	RootCert *x509.Certificate
	RootKey  *rsa.PrivateKey
}

// NewInternalCA initializes a self-signed root CA for the Control Plane.
func NewInternalCA() (*InternalCA, error) {
	// Generate Root Key
	rootKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate root key: %w", err)
	}

	// Create Root Certificate Template
	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Talos Vault Authority"},
			CommonName:   "Talos Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the Root Certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create root cert: %w", err)
	}

	rootCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root cert: %w", err)
	}

	return &InternalCA{
		RootCert: rootCert,
		RootKey:  rootKey,
	}, nil
}

// IssueWorkloadCert generates a short-lived certificate for a specific SPIFFE ID.
func (ca *InternalCA) IssueWorkloadCert(spiffeID string) ([]byte, []byte, error) {
	// Generate ephemeral key for the workload
	workloadKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate workload key: %w", err)
	}

	// Template for the workload certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Talos Workloads"},
			CommonName:   spiffeID,
		},
		DNSNames:              []string{spiffeID}, // SPIFFE ID typically goes in SAN URI, using DNS for simplicity here
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour), // Short-lived!
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Sign the certificate with the Root CA
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, ca.RootCert, &workloadKey.PublicKey, ca.RootKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign workload cert: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(workloadKey)})

	return certPEM, keyPEM, nil
}

// GetCABundle returns the PEM encoded root certificate.
func (ca *InternalCA) GetCABundle() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.RootCert.Raw})
}
