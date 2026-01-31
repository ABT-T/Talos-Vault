package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "math/big"
    "net"
    "os"
    "time"
)

func main() {
    // --- 1. Generate CA (Certificate Authority) ---
    fmt.Println("Generating Robust CA...")
    caPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
    
    caTemplate := x509.Certificate{
        SerialNumber:          big.NewInt(1),
        Subject:               pkix.Name{Organization: []string{"Talos-Vault CA"}},
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(365 * 24 * time.Hour),
        
        // CRITICAL FIXES HERE:
        IsCA:                  true,
        BasicConstraintsValid: true, // This was missing!
        
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
    }

    caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
    if err != nil {
        panic(err)
    }
    savePEM("certs/ca.crt", "CERTIFICATE", caBytes)
    savePEM("certs/ca.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caPriv))

    // --- 2. Generate Server Certificate ---
    fmt.Println("Generating Server Certificate...")
    servPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
    
    servTemplate := x509.Certificate{
        SerialNumber: big.NewInt(2),
        Subject:      pkix.Name{CommonName: "localhost"},
        
        // SANs are required for modern TLS (Chrome/Go 1.15+)
        IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
        DNSNames:     []string{"localhost"},
        
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(365 * 24 * time.Hour),
        
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, 
        
        BasicConstraintsValid: true,
    }

    servBytes, err := x509.CreateCertificate(rand.Reader, &servTemplate, &caTemplate, &servPriv.PublicKey, caPriv)
    if err != nil {
        panic(err)
    }
    savePEM("certs/server.crt", "CERTIFICATE", servBytes)
    savePEM("certs/server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(servPriv))

    // --- 3. Generate Client Certificate ---
    fmt.Println("Generating Client Certificate...")
    clientPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
    
    clientTemplate := x509.Certificate{
        SerialNumber: big.NewInt(3),
        Subject:      pkix.Name{CommonName: "agent-win-01"},
        
        NotBefore:    time.Now(),
        NotAfter:     time.Now().Add(365 * 24 * time.Hour),
        
        KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
        
        BasicConstraintsValid: true,
    }

    clientBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientPriv.PublicKey, caPriv)
    if err != nil {
        panic(err)
    }
    savePEM("certs/client.crt", "CERTIFICATE", clientBytes)
    savePEM("certs/client.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientPriv))

    fmt.Println("Success! Correct certificates generated.")
}

func savePEM(filename, typeStr string, bytes []byte) {
    f, _ := os.Create(filename)
    defer f.Close()
    pem.Encode(f, &pem.Block{Type: typeStr, Bytes: bytes})
}