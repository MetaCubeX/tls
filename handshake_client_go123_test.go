//go:build !go1.24

package tls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
)

// prepareReferenceConfig adapts a configuration already cloned by the recorded
// handshake runner. Upstream recordings now use ECDSA certificates by default,
// while Go 1.24 changed ECDSA nonce generation:
// https://github.com/golang/go/commit/9776d028f4b99b9a935dae9f63f32871b77c49af
//
// Go <1.24 produces different signature bytes from the same random stream.
// Replay tests compare exact wire bytes, including later records that depend
// on the signed transcript, so this affects many handshake tests. A test-only
// signer reproduces the recorded algorithm.
//
// Keys can come from Certificates, NameToCertificate, certificate callbacks,
// or GetConfigForClient, so all those paths need wrapping. Copy shared
// certificate containers and clone callback configs to keep native keys intact.
func prepareReferenceConfig(config *Config) *Config {
	config.Certificates = append([]Certificate(nil), config.Certificates...)
	for i := range config.Certificates {
		config.Certificates[i] = wrapReferenceCertificate(config.Certificates[i])
	}
	if config.NameToCertificate != nil {
		wrapped := make(map[string]*Certificate, len(config.NameToCertificate))
		for name, cert := range config.NameToCertificate {
			wrapped[name], _ = wrapReferenceCertificateResult(cert, nil)
		}
		config.NameToCertificate = wrapped
	}
	if get := config.GetCertificate; get != nil {
		config.GetCertificate = func(hello *ClientHelloInfo) (*Certificate, error) {
			return wrapReferenceCertificateResult(get(hello))
		}
	}
	if get := config.GetClientCertificate; get != nil {
		config.GetClientCertificate = func(request *CertificateRequestInfo) (*Certificate, error) {
			return wrapReferenceCertificateResult(get(request))
		}
	}
	if get := config.GetConfigForClient; get != nil {
		config.GetConfigForClient = func(hello *ClientHelloInfo) (*Config, error) {
			next, err := get(hello)
			if next == nil || err != nil {
				return next, err
			}
			return prepareReferenceConfig(next.Clone()), nil
		}
	}
	return config
}

func wrapReferenceCertificate(cert Certificate) Certificate {
	if key, ok := cert.PrivateKey.(*ecdsa.PrivateKey); ok {
		cert.PrivateKey = referenceECDSASigner{key}
	}
	return cert
}

func wrapReferenceCertificateResult(cert *Certificate, err error) (*Certificate, error) {
	if cert == nil || err != nil {
		return cert, err
	}
	wrapped := wrapReferenceCertificate(*cert)
	return &wrapped, nil
}

// referenceECDSASigner is only installed in recorded handshake configurations.
// Native signing is covered by TestLocalCertificate and TestVerifyCertificates.
type referenceECDSASigner struct {
	*ecdsa.PrivateKey
}

func (s referenceECDSASigner) Sign(random io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	return referenceHedgedECDSA(s.PrivateKey, random, digest)
}

// referenceHedgedECDSA reproduces the Go 1.24+ nonce generation used in the
// upstream recordings: SHA-512 HMAC_DRBG with entropy and block-aligned
// key/hash input. Each signature is checked with the native verifier.
// The big integer arithmetic is for recorded handshake tests only.
func referenceHedgedECDSA(key *ecdsa.PrivateKey, random io.Reader, digest []byte) ([]byte, error) {
	order := key.Curve.Params().N
	orderBits := order.BitLen()
	orderBytes := (orderBits + 7) / 8
	truncated := digest
	if len(truncated) > orderBytes {
		truncated = truncated[:orderBytes]
	}
	e := new(big.Int).SetBytes(truncated)
	if excess := len(truncated)*8 - orderBits; excess > 0 {
		e.Rsh(e, uint(excess))
	}
	e.Mod(e, order)

	entropy := make([]byte, orderBytes)
	if _, err := io.ReadFull(random, entropy); err != nil {
		return nil, err
	}
	seed := append([]byte(nil), entropy...)
	pad := func(length int) {
		if remainder := length % sha512.BlockSize; remainder != 0 {
			seed = append(seed, make([]byte, sha512.BlockSize-remainder)...)
		}
	}
	pad(sha512.Size + 1 + len(entropy))
	seed = append(seed, key.D.FillBytes(make([]byte, orderBytes))...)
	pad(orderBytes)
	seed = append(seed, e.FillBytes(make([]byte, orderBytes))...)
	drbg := newReferenceHMACDRBG(seed)

	nonce := make([]byte, orderBytes)
	for {
		drbg.generate(nonce)
		k := new(big.Int).SetBytes(nonce)
		if excess := orderBytes*8 - orderBits; excess > 0 {
			k.Rsh(k, uint(excess))
		}
		if k.Sign() == 0 || k.Cmp(order) >= 0 {
			continue
		}
		x, _ := key.Curve.ScalarBaseMult(k.Bytes())
		r := new(big.Int).Mod(x, order)
		if r.Sign() == 0 {
			continue
		}
		s := new(big.Int).Mul(r, key.D)
		s.Add(s, e)
		s.Mul(s, new(big.Int).ModInverse(k, order))
		s.Mod(s, order)
		if s.Sign() == 0 {
			continue
		}
		sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
		if err != nil {
			return nil, err
		}
		if !ecdsa.VerifyASN1(&key.PublicKey, digest, sig) {
			return nil, errors.New("reference test: invalid compatible ECDSA signature")
		}
		return sig, nil
	}
}

type referenceHMACDRBG struct {
	key, value []byte
}

func referenceHMAC(key []byte, parts ...[]byte) []byte {
	h := hmac.New(sha512.New, key)
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func newReferenceHMACDRBG(seed []byte) *referenceHMACDRBG {
	d := &referenceHMACDRBG{
		key:   make([]byte, sha512.Size),
		value: make([]byte, sha512.Size),
	}
	for i := range d.value {
		d.value[i] = 1
	}
	for _, separator := range []byte{0, 1} {
		d.key = referenceHMAC(d.key, d.value, []byte{separator}, seed)
		d.value = referenceHMAC(d.key, d.value)
	}
	return d
}

func (d *referenceHMACDRBG) generate(out []byte) {
	for copied := 0; copied < len(out); {
		d.value = referenceHMAC(d.key, d.value)
		copied += copy(out[copied:], d.value)
	}
	d.key = referenceHMAC(d.key, d.value, []byte{0})
	d.value = referenceHMAC(d.key, d.value)
}
