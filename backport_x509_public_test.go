package tls_test

import (
	"crypto/x509"
	"testing"

	tls "github.com/metacubex/tls"
)

func TestStdlibX509PublicTypes(t *testing.T) {
	var _ func([]byte) (*x509.Certificate, error) = tls.X509ParseCertificate
	var _ func([]byte) (any, error) = tls.X509ParsePKCS8PrivateKey
	pool := x509.NewCertPool()
	leaf := new(x509.Certificate)
	config := &tls.Config{
		RootCAs: pool, ClientCAs: pool,
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error { return nil },
		VerifyConnection: func(cs tls.ConnectionState) error {
			var certs []*x509.Certificate = cs.PeerCertificates
			var chains [][]*x509.Certificate = cs.VerifiedChains
			_, _ = certs, chains
			return nil
		},
	}
	cert := tls.Certificate{Leaf: leaf}
	err := &tls.CertificateVerificationError{UnverifiedCertificates: []*x509.Certificate{leaf}}
	if config.RootCAs != pool || config.ClientCAs != pool || cert.Leaf != leaf || err.UnverifiedCertificates[0] != leaf {
		t.Fatal("standard-library X.509 values were not preserved")
	}
}
