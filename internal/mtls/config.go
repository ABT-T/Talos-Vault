// internal/mtls/config.go
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

// EnableSPIFFEValidation از متغیر محیطی خوانده می‌شود
var EnableSPIFFEValidation = os.Getenv("ENABLE_SPIFFE_VALIDATION") == "true"

// ... (بقیه کدهای موجود، مثل LoadServerTLS، LoadClientTLS و ...)

// ValidateSPIFFEID بررسی می‌کند که گواهی حداقل یک URI با پیشوند SPIFFE و دامنه مجاز داشته باشد
func ValidateSPIFFEID(cert *x509.Certificate) error {
	const spiffePrefix = "spiffe://"
	allowedDomains := []string{"cluster.local"} // دامنه‌های مورد اعتماد

	for _, uri := range cert.URIs {
		uriStr := uri.String()
		if !strings.HasPrefix(uriStr, spiffePrefix) {
			continue
		}
		for _, domain := range allowedDomains {
			if strings.Contains(uriStr, domain) {
				return nil // SPIFFE ID معتبر است
			}
		}
	}
	return fmt.Errorf("no valid SPIFFE ID found in URI SANs (expected spiffe://<trust-domain>/... with domain in %v)", allowedDomains)
}

// VerifyPeerCertificateWithSPIFFE نسخه‌ای که می‌تواند SPIFFE را فعال/غیرفعال کند
func VerifyPeerCertificateWithSPIFFE(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, checkSPIFFE bool) error {
	if len(verifiedChains) == 0 {
		return fmt.Errorf("no verified certificate chains")
	}

	leaf := verifiedChains[0][0]

	// اعتبارسنجی Organization (اختیاری – می‌توانید حذف یا اصلاح کنید)
	validOrgs := map[string]bool{"TalosVault": true}
	if len(leaf.Subject.Organization) > 0 {
		if !validOrgs[leaf.Subject.Organization[0]] {
			return fmt.Errorf("invalid certificate organization: %s", leaf.Subject.Organization[0])
		}
	}

	// اعتبارسنجی SPIFFE در صورت فعال بودن
	if checkSPIFFE {
		if err := ValidateSPIFFEID(leaf); err != nil {
			return err
		}
	}

	return nil
}

// LoadServerTLSWithCustomVerification با پشتیبانی از SPIFFE
func LoadServerTLSWithCustomVerification(cfg Config) (*tls.Config, error) {
	tlsConfig, err := LoadServerTLS(cfg)
	if err != nil {
		return nil, err
	}

	// استفاده از متغیر سراسری EnableSPIFFEValidation
	tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		return VerifyPeerCertificateWithSPIFFE(rawCerts, verifiedChains, EnableSPIFFEValidation)
	}

	return tlsConfig, nil
}
