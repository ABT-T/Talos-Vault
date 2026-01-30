package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "log"
    "math/big"
    "net"
    "os"
    "time"
)

func main() {
    // Clean slate: Ensure certs dir exists
    if _, err := os.Stat("certs"); os.IsNotExist(err) {
        os.Mkdir("certs", 0755)
    }

    // --- 1. CA (Certificate Authority) ---
    ca := &x509.Certificate{
        SerialNumber:          big.NewInt(2026),
        Subject:               pkix.Name{CommonName: "Talos Vault CA"},
        NotBefore:             time.Now(),
        NotAfter:              time.Now().AddDate(10, 0, 0),
        IsCA:                  true,
        BasicConstraintsValid: true, // <--- CRITICAL FIX: Allows this cert to sign others
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
    }

    caPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    caBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
    saveFile("certs/ca.crt", "CERTIFICATE", caBytes)
    saveFile("certs/ca.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(caPrivKey))
    log.Println("✅ CA Generated (Valid for Signing)")

    // --- 2. Server Cert ---
    serverCert := &x509.Certificate{
        SerialNumber: big.NewInt(2027),
        Subject:      pkix.Name{CommonName: "localhost"},
        DNSNames:     []string{"localhost"}, // Required for TLS verification
        IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
        // Server Cert is NOT a CA
        BasicConstraintsValid: true,
        IsCA:                  false, 
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
    }

    serverPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    serverBytes, _ := x509.CreateCertificate(rand.Reader, serverCert, ca, &serverPrivKey.PublicKey, caPrivKey)
    saveFile("certs/server.crt", "CERTIFICATE", serverBytes)
    saveFile("certs/server.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(serverPrivKey))
    log.Println("✅ Server Cert Generated")

    // --- 3. Client Cert ---
    clientCert := &x509.Certificate{
        SerialNumber: big.NewInt(2028),
        Subject:      pkix.Name{CommonName: "agent-01"},
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
        BasicConstraintsValid: true,
        IsCA:                  false,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
        KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
    }

    clientPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
    clientBytes, _ := x509.CreateCertificate(rand.Reader, clientCert, ca, &clientPrivKey.PublicKey, caPrivKey)
    saveFile("certs/agent.crt", "CERTIFICATE", clientBytes)
    saveFile("certs/agent.key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(clientPrivKey))
    log.Println("✅ Agent Cert Generated")
}

func saveFile(filename, typeName string, bytes []byte) {
    out, _ := os.Create(filename)
    defer out.Close()
    pem.Encode(out, &pem.Block{Type: typeName, Bytes: bytes})
}