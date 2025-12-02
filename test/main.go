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

var greaseValues = []uint16{
	0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
	0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
	0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
	0xcaca, 0xdada, 0xeaea, 0xfafa,
}

func pickGrease() uint16 {
	// for testing don't care about crypto strength
	var b [1]byte
	_, err := rand.Read(b[:])
	if err != nil {
		return 0x0a0a
	}

	return greaseValues[int(b[0])%len(greaseValues)]
}

// greaseMessage prepends a GREASE value to selected ClientHello fields.
// Only fields that are already present get greased, matching real-world behavior.
func greaseMessage(ch *clientHelloMsg, gv uint16) {
	// Always grease cipher suites.
	ch.cipherSuites = append([]uint16{gv}, ch.cipherSuites...)

	// GREASE supported TLS versions (if sent).
	if len(ch.supportedVersions) > 0 {
		ch.supportedVersions = append([]uint16{gv}, ch.supportedVersions...)
	}

	// GREASE supported curves (if sent).
	if len(ch.supportedCurves) > 0 {
		ch.supportedCurves = append([]CurveID{CurveID(gv)}, ch.supportedCurves...)
	}
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

			// Pick a GREASE value for this ClientHello.
			// A random value from the GREASE set is chosen each handshake.
			gv := pickGrease()

			// Apply GREASE to cipher suites, versions, and curves.
			greaseMessage(ch, gv)

			msg := struct {
				Vers              uint16    `json:"vers"`
				ServerName        string    `json:"serverName"`
				CipherSuites      []uint16  `json:"cipherSuites"`
				SupportedVersions []uint16  `json:"supportedVersions"`
				SupportedCurves   []CurveID `json:"supportedCurves"`
			}{
				Vers:              ch.vers,
				ServerName:        ch.serverName,
				CipherSuites:      ch.cipherSuites,
				SupportedVersions: ch.supportedVersions,
				SupportedCurves:   ch.supportedCurves,
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
