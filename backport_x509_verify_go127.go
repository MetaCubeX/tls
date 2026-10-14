//go:build go1.27

package tls

import "crypto/x509"

func verifyCertificate(cert *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	return cert.Verify(opts)
}
