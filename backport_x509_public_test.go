package tls_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"reflect"
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

func TestX509VerifyCertificatePublicAPI(t *testing.T) {
	certPEM, err := os.ReadFile("testdata/example-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("could not decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	opts := x509.VerifyOptions{Roots: roots, CurrentTime: cert.NotBefore, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	want, err := cert.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	var verify func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error) = tls.X509VerifyCertificate
	got, err := verify(cert, opts)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("chains=%v, err=%v; want %v", got, err, want)
	}
}

func TestX509NormalizeCertificatePublicAPI(t *testing.T) {
	var normalize func(*x509.Certificate) (*x509.Certificate, error) = tls.X509NormalizeCertificate
	cert := new(x509.Certificate)
	if got, err := normalize(cert); err != nil || got != cert {
		t.Fatalf("normalization: got %p, %v; want %p", got, err, cert)
	}
}
