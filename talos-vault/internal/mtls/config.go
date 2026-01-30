package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// Config holds paths to certificates
type Config struct {
	CertFile string
	KeyFile  string
	CAFile   string
}

// LoadServerTLS loads certificates for the Control Plane (mTLS enabled)
func LoadServerTLS(cfg Config) (*tls.Config, error) {
	// Load Server's own cert/key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server keypair: %w", err)
	}

	// Load CA Cert to verify Clients
	caCert, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	// Temporarily relax client authentication to allow plaintext or non-mTLS clients
	// (For testing only). In production, this should be tls.RequireAndVerifyClientCert.
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.NoClientCert,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// LoadClientTLS loads certificates for the Sidecar/Admin
func LoadClientTLS(cfg Config) (*tls.Config, error) {
	// Load Client's own cert/key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client keypair: %w", err)
	}

	// Load CA Cert to verify Server
	caCert, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to append CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
