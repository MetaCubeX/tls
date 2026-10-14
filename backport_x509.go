package tls

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"github.com/metacubex/mldsa"
)

// X509VerifyCertificate verifies cert like [x509.Certificate.Verify], adding ML-DSA
// CA support on Go 1.20-1.26. Supply intermediate certificates in opts.Intermediates.
// It does not modify cert or the certificate pools in opts. System-root verification
// retains the standard library's platform-specific behavior and limitations.
func X509VerifyCertificate(cert *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	return verifyCertificate(cert, opts)
}

// X509NormalizeCertificate converts cert's [mldsa.PublicKey] to crypto/mldsa on
// Go 1.27+. It returns a shallow copy only when conversion is needed, preserving
// all other fields without reparsing DER. Otherwise, including on Go 1.20-1.26,
// it returns cert unchanged. A nil cert returns nil, nil.
//
// Call this before adding externally supplied certificates to a CertPool. It
// does not modify cert, normalize existing pools, or validate the certificate.
// On older Go versions, use [X509VerifyCertificate] for ML-DSA CA verification.
func X509NormalizeCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, nil
	}
	key, err := normalizeX509PublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return cert, nil
	}
	normalized := *cert
	normalized.PublicKey = key
	return &normalized, nil
}

// X509ParseCertificate parses a certificate like [x509.ParseCertificate], adding
// ML-DSA public key decoding on Go versions before 1.27.
func X509ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil || cert.PublicKey != nil || nativeMLDSA {
		return cert, err
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil || len(rest) != 0 {
		return nil, errors.New("tls: invalid SubjectPublicKeyInfo")
	}
	params, ok := mldsaParametersFromOID(spki.Algorithm.Algorithm)
	if !ok {
		return cert, nil
	}
	if len(spki.Algorithm.Parameters.FullBytes) != 0 || spki.PublicKey.BitLength != len(spki.PublicKey.Bytes)*8 {
		return nil, errors.New("tls: invalid ML-DSA public key encoding")
	}
	cert.PublicKey, err = mldsa.NewPublicKey(params, spki.PublicKey.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// X509ParsePKCS8PrivateKey parses a private key like [x509.ParsePKCS8PrivateKey],
// adding seed-only ML-DSA private key decoding on Go versions before 1.27.
func X509ParsePKCS8PrivateKey(der []byte) (any, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err == nil || nativeMLDSA {
		return key, err
	}
	var priv struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	rest, parseErr := asn1.Unmarshal(der, &priv)
	if parseErr != nil {
		return key, err
	}
	params, ok := mldsaParametersFromOID(priv.Algorithm.Algorithm)
	if !ok {
		return key, err
	}
	// Only backport the seed-only encoding. Go 1.27 parsing, including errors,
	// is handled entirely by the standard library above.
	if len(rest) != 0 || priv.Version != 0 || len(priv.Algorithm.Parameters.FullBytes) != 0 ||
		len(priv.PrivateKey) != 2+mldsa.PrivateKeySize || priv.PrivateKey[0] != 0x80 || priv.PrivateKey[1] != mldsa.PrivateKeySize {
		return nil, errors.New("tls: invalid ML-DSA PKCS#8 key (expected a seed-only key without parameters)")
	}
	return mldsa.NewPrivateKey(params, priv.PrivateKey[2:])
}

func mldsaParametersFromOID(oid asn1.ObjectIdentifier) (mldsa.Parameters, bool) {
	switch {
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}):
		return mldsa.MLDSA44(), true
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}):
		return mldsa.MLDSA65(), true
	case oid.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}):
		return mldsa.MLDSA87(), true
	default:
		return mldsa.Parameters{}, false
	}
}
