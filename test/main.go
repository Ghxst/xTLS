package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"time"
	"unsafe"
)

func base64Encode(b []byte) string {
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(b)))
	base64.StdEncoding.Encode(enc, b)

	return string(enc)
}

func pemEncode(der []byte) []byte {
	return []byte(
		"-----BEGIN CERTIFICATE-----\n" +
			base64Encode(der) +
			"\n-----END CERTIFICATE-----\n")
}

func generateSelfSignedCert() (tls.Certificate, *x509.CertPool) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	derBytes, _ := x509.CreateCertificate(
		rand.Reader,
		&template,
		&template,
		&priv.PublicKey,
		priv,
	)

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemEncode(derBytes))

	return cert, pool
}

func main() {
	cert, rootPool := generateSelfSignedCert()

	ln, err := tls.Listen(
		"tcp",
		"127.0.0.1:0",
		&tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	)
	if err != nil {
		fmt.Println("server listen error:", err)
		os.Exit(1)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn := conn.(*tls.Conn)
		_ = tlsConn.Handshake()
		tlsConn.Close()
	}()

	clientCfg := &tls.Config{
		RootCAs:    rootPool,
		ServerName: "localhost", // must match cert
		ClientHelloHook: func(p unsafe.Pointer) {
			ch := (*clientHelloMsg)(p)

			msg := struct {
				Vers              uint16   `json:"vers"`
				ServerName        string   `json:"serverName"`
				CipherSuites      []uint16 `json:"cipherSuites"`
				ALPNProtocols     []string `json:"alpnProtocols"`
				SupportedVersions []uint16 `json:"supportedVersions"`
			}{
				Vers:              ch.vers,
				ServerName:        ch.serverName,
				CipherSuites:      ch.cipherSuites,
				ALPNProtocols:     ch.alpnProtocols,
				SupportedVersions: ch.supportedVersions,
			}

			b, err := json.MarshalIndent(msg, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "ClientHelloHook: marshal error: %v\n", err)
				return
			}

			fmt.Fprintf(os.Stderr, "ClientHelloHook:\n%s\n", b)
		},
	}

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		fmt.Println("client handshake error:", err)
		os.Exit(1)
	}
	conn.Close()

	fmt.Println("TLS handshake completed successfully.")
}
