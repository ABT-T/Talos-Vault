// internal/mtls/config_test.go
package mtls_test

import (
	"net/url"
	"testing"

	"talos-vault/internal/mtls"
)

func TestSPIFFEValidation(t *testing.T) {
	// گواهی معتبر با SPIFFE ID
	cert := &x509.Certificate{
		URIs: []*url.URL{
			{Scheme: "spiffe", Host: "cluster.local", Path: "/ns/default/sa/talos-vault"},
		},
	}
	err := mtls.ValidateSPIFFEID(cert)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// گواهی بدون URI
	cert2 := &x509.Certificate{URIs: []*url.URL{}}
	err = mtls.ValidateSPIFFEID(cert2)
	if err == nil {
		t.Error("expected error for missing SPIFFE ID, got nil")
	}

	// گواهی با URI غیر SPIFFE
	cert3 := &x509.Certificate{
		URIs: []*url.URL{
			{Scheme: "https", Host: "example.com"},
		},
	}
	err = mtls.ValidateSPIFFEID(cert3)
	if err == nil {
		t.Error("expected error for non-SPIFFE URI, got nil")
	}
}