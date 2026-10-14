package tls

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"

	"github.com/metacubex/mldsa"
)

func TestMLDSAKeyDecoding(t *testing.T) {
	for _, tc := range []struct {
		name, certPEM, keyPEM string
		key                   *mldsaPrivateKey
	}{
		{"44", testMLDSA44CertPEM, testMLDSA44KeyPEM, testMLDSA44Key},
		{"65", testMLDSA65CertPEM, testMLDSA65KeyPEM, testMLDSA65Key},
		{"87", testMLDSA87CertPEM, testMLDSA87KeyPEM, testMLDSA87Key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matchesPublicKey := func(pub crypto.PublicKey) bool {
				encoded, ok := pub.(interface{ Bytes() []byte })
				want := tc.key.PublicKey()
				return ok && mldsaSignatureScheme(pub) == mldsaSignatureScheme(want) && bytes.Equal(encoded.Bytes(), want.Bytes())
			}
			block, _ := pem.Decode([]byte(tc.certPEM))
			cert, err := X509ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !matchesPublicKey(cert.PublicKey) {
				t.Fatalf("incorrect public key: %T", cert.PublicKey)
			}
			if !bytes.Equal(cert.Raw, block.Bytes) {
				t.Fatal("certificate DER changed")
			}
			if !nativeMLDSA && cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
				t.Fatal("backport invented a standard-library public key algorithm")
			}
			block, _ = pem.Decode([]byte(tc.keyPEM))
			key, err := X509ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			priv, ok := key.(interface {
				crypto.Signer
				Bytes() []byte
			})
			if !ok || !bytes.Equal(priv.Bytes(), tc.key.Bytes()) {
				t.Fatalf("incorrect seed-only private key: %T", key)
			}
			if !matchesPublicKey(priv.Public()) {
				t.Fatal("private key has the wrong public key")
			}
		})
	}
}

func TestMLDSAPrivateKeyEncoding(t *testing.T) {
	block, _ := pem.Decode([]byte(testMLDSA44KeyPEM))
	type pkcs8 struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	for _, name := range []string{"truncated", "trailing", "version", "parameters", "OID", "empty", "short", "long", "expanded", "both", "length"} {
		t.Run(name, func(t *testing.T) {
			var priv pkcs8
			if _, err := asn1.Unmarshal(block.Bytes, &priv); err != nil {
				t.Fatal(err)
			}
			priv.PrivateKey = bytes.Clone(priv.PrivateKey)
			switch name {
			case "version":
				priv.Version = 1
			case "parameters":
				priv.Algorithm.Parameters = asn1.NullRawValue
			case "OID":
				priv.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
			case "empty":
				priv.PrivateKey = nil
			case "short":
				priv.PrivateKey = priv.PrivateKey[:len(priv.PrivateKey)-1]
			case "long":
				priv.PrivateKey = append(priv.PrivateKey, 0)
			case "expanded":
				priv.PrivateKey[0] = 0x04
			case "both":
				priv.PrivateKey[0] = 0x30
			case "length":
				priv.PrivateKey[1]--
			}
			der, err := asn1.Marshal(priv)
			if err != nil {
				t.Fatal(err)
			}
			if name == "truncated" {
				der = der[:len(der)-1]
			} else if name == "trailing" {
				der = append(der, 0)
			}
			key, err := X509ParsePKCS8PrivateKey(der)
			if nativeMLDSA {
				_, standardErr := x509.ParsePKCS8PrivateKey(der)
				if (err == nil) != (standardErr == nil) {
					t.Fatalf("native parser behavior changed: got %v, want %v", err, standardErr)
				}
				return
			}
			if err == nil {
				t.Fatalf("invalid private key accepted: %T", key)
			}
		})
	}
}

func TestMLDSAPublicKeyEncoding(t *testing.T) {
	for _, name := range []string{"parameters", "short", "unaligned", "unknown_OID"} {
		t.Run(name, func(t *testing.T) {
			var cert struct {
				TBS       asn1.RawValue
				Algorithm pkix.AlgorithmIdentifier
				Signature asn1.BitString
			}
			if _, err := asn1.Unmarshal(testMLDSA44Cert.Certificate[0], &cert); err != nil {
				t.Fatal(err)
			}
			var fields []asn1.RawValue
			if _, err := asn1.Unmarshal(cert.TBS.FullBytes, &fields); err != nil {
				t.Fatal(err)
			}
			var spki struct {
				Algorithm pkix.AlgorithmIdentifier
				PublicKey asn1.BitString
			}
			if _, err := asn1.Unmarshal(fields[6].FullBytes, &spki); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "parameters":
				spki.Algorithm.Parameters = asn1.NullRawValue
			case "short":
				spki.PublicKey.Bytes = spki.PublicKey.Bytes[:len(spki.PublicKey.Bytes)-1]
				spki.PublicKey.BitLength -= 8
			case "unaligned":
				spki.PublicKey.Bytes = bytes.Clone(spki.PublicKey.Bytes)
				spki.PublicKey.Bytes[len(spki.PublicKey.Bytes)-1] &^= 1
				spki.PublicKey.BitLength--
			case "unknown_OID":
				spki.Algorithm.Algorithm = asn1.ObjectIdentifier{1, 2, 3, 4}
			}
			marshal := func(value any) []byte {
				t.Helper()
				der, err := asn1.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				return der
			}
			fields[6] = asn1.RawValue{FullBytes: marshal(spki)}
			cert.TBS = asn1.RawValue{FullBytes: marshal(fields)}
			der := marshal(cert)
			parsed, err := X509ParseCertificate(der)
			if nativeMLDSA {
				// The native parser is authoritative, including its handling of
				// unused BIT STRING bits. Do not reinterpret native public keys.
				standard, standardErr := x509.ParseCertificate(der)
				if (err == nil) != (standardErr == nil) || !reflect.DeepEqual(parsed, standard) {
					t.Fatalf("native parser behavior changed: got %v, want %v", err, standardErr)
				}
				return
			}
			if name == "unknown_OID" {
				if err != nil || parsed.PublicKey != nil {
					t.Fatalf("unknown algorithms should retain standard-library behavior: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid public key accepted")
			}
		})
	}
}

func TestMLDSACAChainVerification(t *testing.T) {
	ca := parseTestCert(testMLDSACACertPEM, testMLDSA44KeyPEM).Leaf
	leaf := parseTestCert(testMLDSACALeafCertPEM, testECDSAP256KeyPEM)
	leaf.Certificate = append(leaf.Certificate, ca.Raw)
	for _, name := range []string{"root", "intermediate"} {
		t.Run(name, func(t *testing.T) {
			client, server := testConfigClient.Clone(), testConfigServer.Clone()
			client.MinVersion, client.MaxVersion = VersionTLS13, VersionTLS13
			server.MinVersion, server.MaxVersion = VersionTLS13, VersionTLS13
			client.RootCAs = x509.NewCertPool()
			if name == "root" {
				// A trusted anchor need not be self-signed.
				client.RootCAs.AddCert(ca)
			} else {
				client.RootCAs.AddCert(testRootCert.Leaf)
			}
			client.Certificates, server.Certificates = []Certificate{leaf}, []Certificate{leaf}
			server.ClientAuth, server.ClientCAs = RequireAndVerifyClientCert, client.RootCAs
			ss, cs, err := testHandshake(t, client, server)
			if !nativeMLDSA {
				if err := leaf.Leaf.CheckSignatureFrom(ca); !errors.Is(err, x509.ErrUnsupportedAlgorithm) {
					t.Fatalf("expected an unsupported CA signature algorithm, got %v", err)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, state := range []ConnectionState{ss, cs} {
				if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) < 2 ||
					state.VerifiedChains[0][0] != state.PeerCertificates[0] {
					t.Fatal("standard-library verified chain was lost")
				}
			}
		})
	}
}

func TestStdlibSystemCertPool(t *testing.T) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("system certificate pool unavailable: %v", err)
	}
	pool.AddCert(testRootCert.Leaf) // Only changes this in-memory pool.
	client, server := testConfigClient.Clone(), testConfigServer.Clone()
	client.RootCAs = pool
	server.Certificates = []Certificate{testECDSAP256Cert}
	if _, _, err := testHandshake(t, client, server); err != nil {
		t.Fatal(err)
	}
	if client.RootCAs != pool {
		t.Fatal("standard-library system pool was replaced")
	}
}

func TestX509NormalizeCertificateUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		cert *x509.Certificate
	}{
		{"nil", nil},
		{"empty", new(x509.Certificate)},
		{"RSA", testRootCert.Leaf},
		// Ed25519 public keys are slices, so comparing PublicKey interfaces
		// to detect a change would panic.
		{"Ed25519", testEd25519Cert.Leaf},
		{"MLDSA44", testMLDSA44Cert.Leaf},
		{"MLDSA65", testMLDSA65Cert.Leaf},
		{"MLDSA87", testMLDSA87Cert.Leaf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if allocs := testing.AllocsPerRun(100, func() {
				got, err := X509NormalizeCertificate(tc.cert)
				if err != nil || got != tc.cert {
					t.Fatalf("no-op normalization: got %p, %v; want %p", got, err, tc.cert)
				}
			}); allocs != 0 {
				t.Fatalf("no-op normalization allocated %v times", allocs)
			}
		})
	}
}

func TestX509NormalizeForkMLDSACertificate(t *testing.T) {
	for _, tc := range []struct {
		params mldsa.Parameters
		cert   Certificate
	}{
		{mldsa.MLDSA44(), testMLDSA44Cert},
		{mldsa.MLDSA65(), testMLDSA65Cert},
		{mldsa.MLDSA87(), testMLDSA87Cert},
	} {
		t.Run(tc.params.String(), func(t *testing.T) {
			forkKey, err := mldsa.NewPrivateKey(tc.params, tc.cert.PrivateKey.(*mldsaPrivateKey).Bytes())
			if err != nil {
				t.Fatal(err)
			}
			input := *tc.cert.Leaf
			input.PublicKey = forkKey.PublicKey()
			// Preserve caller-supplied policy rather than reparse input.Raw.
			input.NotAfter = input.NotBefore
			input.PermittedDNSDomains = []string{"policy.example"}
			before := input
			got, err := X509NormalizeCertificate(&input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(input, before) {
				t.Fatal("input certificate changed")
			}
			if _, ok := got.PublicKey.(*mldsaPublicKey); !ok {
				t.Fatalf("unexpected normalized public key: %T", got.PublicKey)
			}
			if !got.PublicKey.(interface{ Equal(crypto.PublicKey) bool }).Equal(tc.cert.Leaf.PublicKey) {
				t.Fatal("normalized public key differs from the original")
			}
			_, primary := input.PublicKey.(*mldsaPublicKey)
			if (got == &input) != primary {
				t.Fatal("certificate must be copied only when key conversion is needed")
			}
			fields := *got
			fields.PublicKey = input.PublicKey
			if !reflect.DeepEqual(fields, input) {
				t.Fatal("normalization changed fields other than PublicKey")
			}
			if again, err := X509NormalizeCertificate(got); err != nil || again != got {
				t.Fatalf("repeated normalization: got %p, %v; want %p", again, err, got)
			}
			if !nativeMLDSA {
				return
			}
			encoded, err := x509.MarshalPKIXPublicKey(got.PublicKey)
			if err != nil || !bytes.Equal(encoded, input.RawSubjectPublicKeyInfo) {
				t.Fatalf("standard-library public-key encoding failed: %v", err)
			}
		})
	}
}

func TestX509NormalizeForkMLDSACertificatePools(t *testing.T) {
	for _, tc := range []struct {
		params mldsa.Parameters
		cert   Certificate
		scheme SignatureScheme
	}{
		{mldsa.MLDSA44(), testMLDSA44Cert, MLDSA44},
		{mldsa.MLDSA65(), testMLDSA65Cert, MLDSA65},
		{mldsa.MLDSA87(), testMLDSA87Cert, MLDSA87},
	} {
		t.Run(tc.params.String(), func(t *testing.T) {
			ca := reissueMLDSATestCertificate(t, tc.cert.Leaf, testRootCert.Leaf,
				testRootCert.PrivateKey.(crypto.Signer), PKCS1WithSHA256, 300, true)
			leaf := reissueMLDSATestCertificate(t, testECDSAP256Cert.Leaf, ca,
				tc.cert.PrivateKey.(crypto.Signer), tc.scheme, 301, false)
			forkKey, err := mldsa.NewPrivateKey(tc.params, tc.cert.PrivateKey.(*mldsaPrivateKey).Bytes())
			if err != nil {
				t.Fatal(err)
			}
			ca.PublicKey = forkKey.PublicKey()
			ca, err = X509NormalizeCertificate(ca)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"root", "intermediate"} {
				t.Run(name, func(t *testing.T) {
					opts := x509.VerifyOptions{
						Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool(),
						CurrentTime: testTime(), DNSName: "test.golang.example",
					}
					wantLen := 2
					if name == "root" {
						opts.Roots.AddCert(ca)
					} else {
						opts.Roots.AddCert(testRootCert.Leaf)
						opts.Intermediates.AddCert(ca)
						wantLen = 3
					}
					chains, err := X509VerifyCertificate(leaf, opts)
					if err != nil || len(chains) == 0 || len(chains[0]) != wantLen || chains[0][1] != ca {
						t.Fatalf("normalized CA verification failed: %v, %v", chains, err)
					}
					if nativeMLDSA {
						if err := leaf.CheckSignatureFrom(ca); err != nil {
							t.Fatalf("standard-library signature check failed: %v", err)
						}
						if _, err := leaf.Verify(opts); err != nil {
							t.Fatalf("standard-library chain verification failed: %v", err)
						}
					}
				})
			}
		})
	}
}

func TestX509NormalizeInvalidForkMLDSAPublicKey(t *testing.T) {
	for _, key := range []*mldsa.PublicKey{nil, new(mldsa.PublicKey)} {
		cert := &x509.Certificate{PublicKey: key}
		got, err := X509NormalizeCertificate(cert)
		if _, primary := cert.PublicKey.(*mldsaPublicKey); primary {
			// The normalizer does not validate keys already using the primary type.
			if err != nil || got != cert {
				t.Fatalf("no-op normalization: got %p, %v; want %p", got, err, cert)
			}
		} else if err == nil || got != nil {
			t.Fatalf("invalid fork key accepted: %v, %v", got, err)
		}
		if cert.PublicKey != key {
			t.Fatal("input public key changed")
		}
	}
}

// CA fixtures for TestMLDSACAChainVerification, kept outside upstream's
// generated certificates_test.go.
// Generated with Go 1.27 crypto/x509. The ML-DSA CA is issued by testRootCert;
// its ECDSA leaf uses testECDSAP256Key and permits server and client auth.
const testMLDSACACertPEM = `
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
`

const testMLDSACALeafCertPEM = `
-----BEGIN CERTIFICATE-----
MIIKnjCCARSgAwIBAgIBZjALBglghkgBZQMEAxEwGTEXMBUGA1UEAxMOTUwtRFNB
IHRlc3QgQ0EwHhcNMTYxMDIwMTYzMjA5WhcNMTYxMDIwMTgzMjA5WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAELPHOqBsUwImuWVBxojqLyyNXf8pnMl8tIu3z
FYQx9z4nscU9uLAZTL4/xPeFu5d32SwXihm8h5bKiOluf83BMqNlMGMwHQYDVR0l
BBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB8GA1UdIwQYMBaAFNZlyOSE4Ly545EQ
rJ+VEoqmQ9laMCEGA1UdEQEB/wQXMBWCE3Rlc3QuZ29sYW5nLmV4YW1wbGUwCwYJ
YIZIAWUDBAMRA4IJdQB+7hGf9Jv3Dp1NUK7gdP4t6BAMipSqIJ0qjWB4nEuNd92v
shJFcLZA3Laa88RHSHY6eT/kAvoHmA54d+/ifeWEtuWhBShrpkiDMOrfcB6hm12O
4krd630nOVzJnDfxFHGtWPd6Vw4tnzfxvEg59boSK69pvx2+0MT9F16SzOhQ14Fw
7lur0Ril8qmXtRACy+Ez//49zfl9J2KXD0w0HBOraWlCrEgBUyC1PySC/MQtmR19
//dHdHO5N4IdMwXFZ9KhjEi70u7ZsWBIK2Tsf7n0GXW0e5Js/rm2EWeYhRq8Zjvu
Ns7o3xVGMGTNhcpD9B5KeoVIn36YNUaWwxnk8vSK0ATNawJ48p0BC2z4+wH6WyU3
sYlQQ/twxd6Cp+U2+Akxk+yXmpoHuuUGwvoxEG7xR04u5tLgXANwkXkmeUwaG318
8iTzvSdccWZDeQgQJHKj5xFHj7VMteD8/WsQf3AxTxsTOO7zRAdyue5b6IVNiFT2
ZHPRUUraJrwNWIw9rV2I6JGkfkwwICPs3pTykfEgAb3DkUHgm3PQuXoHZKOgW6b8
oHadEzbscf1rBiDpfD5eRY95P1dkOjFaJegbARKhTlJExIDUQK+VDHw6CbKc/S+h
7eFzPeHs4TrzfHpgNOuBWLCLZtfU5zKArnjFLbIOedqHxtGAb9SX+Q21l4zj+6Fa
B8KkZ4jS8GJNHGLWZCSwYclKooZDkWCp+Tvpiq3Pk3c/hTNWrCEYFOY5nSAIx8Pn
yg+z8sbDx0Xe0E6h0d8oiJin8sIqxtpUvebdPMZfBMrM3rDspFoTRaMVFaaqS/u/
j+29OKxEOPAec/Qi7On4Za8iCw8beFhJQWpP838/bYoWmerNx9P0Wx9Z+kosyIjQ
oGtiVgAbacdoBWXvuIDmDu0/2WRaJExZZCIYkCm71epYpKv8oT24xj5xFClcCaPA
y5CIh1m/kChqgUrueyXDZiref2h+U0ceGSQvKBy1wwcf281xEQi99JW0ZgppOq/v
cipk66sGHrs09BUX4Zv42TVbQui5OakqaB/ZmRqYAe2TVhewAQFbV8iQUrqEcePm
5tvVHkoXQghCssR+XBI3lIQC30kqYD0xuPOs/BFWCDpPSuoyIWnYMmLX+yK6Fzk2
uPduzmMjMX9Xs4JPnI7OG5jLNof9C9sA71jcDlQZn7k3gN70Fd7xnvXLKtJU1pcK
uW5wjSshbD+WHDaZFSrCNk0XBVRr2aakHIevkJpHKYiNLjgR3p3EEbUcFq/EfeZh
hMZYTgkpWWhFaaaF7zhtXESIh1wdAjKRXSJSR9mJeHAd2IWuERdDU6FZ35HX1ORU
HZnkTTP2tGHi4RRl7q6guc5890b3Mzx1ipY9xKvcjtygkOPhAYzohVWvaDothC1U
MQgGCJgwqK5ioFUNC/lMEZr5RdNNgaDmDzyePmejKpUz+nczDpTNTu3uCywYoA90
rjQFB8H6QoYbl37DE/voTH+SJoXfRHAtuK30mHsqCsJGbstCqLQJichiZSSqTOvZ
taVI77JgIWeIH2/Zv9sUrlDvV3PkhfB6Vu9v6h4odo/2OBhMXAxYfKk3sU2fnnAp
oGNAJuXF0P4k1z/iM79VSLLjU5BzD5DSeYsXrDNDDgGRa+sI8SvMWbV95ZF65Fvz
J2n7a9RXPPlexGI1AHhL5bJHOkScUha/J+BLu0gtJ1R0VPRm//Elu03KsTIB07Ed
G2nFm4vtuxdKGnsjMJrwwjQV/TfzC8fLe/XvORXsK/Mu9Zo18NwRN8HrA7hgYlny
eBJhh1I6OdUFtmJ2pVPOMeh5DzNU9fY44RA0HJb8R6YgeqE/VdIHkMaLNmth+iIt
7jNpRLfSk2p3i3Yo+Z0BGqOpnhTS+yufcAGJk007iY5/0tf14t9ZVqTqlyI07AWc
SLckCaNDmuQDKbTe28v6g3btB3RJyQ+Ar0rCt5TqRk3/9gvlnG02J7893KPMmJ7Q
rPq2EVyjueY0n3F5gWeb79RZVBh0Mtk+8Hyd28SkQ6BuxSCzq/EDtfWlGzmaVhIA
g2QvPWGgwRY4yKL3Nh4cO7GMuC7ePjEKoszj2jVriKurMHU2iwEgC/GgPNehd7K0
n3tsZzICLkxS6ytmDwfHgl6F0WxCGCXl2o24Coo9apRqDN143BqZ8naUu0SA2RkX
VzHfScTA00csBL6z77FbIOMGFyoX8Snx4j08Ho1rQk3ZUG6fQ4fNk4hWO6nReTjY
QM1ZfsePXDmf6djWyVF/jU4PPPMk8mEEiVxMpfcfscOgb6CGSz5ov2DuL3RnJe0X
JaW4oJ2qzlz2uqTtoFIlx4/JlRu0tWROHTja//THr39d9AFIGn4zCdowQJ+5Qu0o
w8xEy7EhxyA13bN3osUJJ6xiexzBk3uVG6W3v4pKOAxq93VaDAUEyDUY9OZChW3+
b8VbKZbfFP40n3X0gW1m/vCPxewaPsLBY40Cd+zjPH4xgz/iklHxahZvR6DbLdjg
BYj/TRJIY50+JSYECHi8/nuS4NJ5etZcEaulPUFvui52PJjy0a1sr+acibctWcMQ
Vn7hzrEtOl1uGjycqu2MW7iJW1OO642GSm1yhVTry8REi8jDEpIS6Glpp8WTa88v
bstBY/5dI78nR1aLQqBvD+M+666EhZOD4nTNSy5kKKFluBPpYM2u5AIkQ4SG/YKD
BUCfWQkzB+tH+IMGyr718KlkX5Q0sD/y0ATpQu95LjKMgpmBdwlcNKy/G1Q0ihj6
FqK+DF8jJf1Jch6mGRGO4u86/7RsptHQCpJW/mEuiMZwVt3nT6sECq7utTbReAw+
u9wdHDBp59JVIBkPWq2Wu+MtMR/bvt6ebnAsXzHG1CucsCm5ETsJ9rvHdoCTirak
jV7M81FWgLvO8Rln6CYReJ+f5pxdAhz+UaC2cghL3gteAGMu0UAHchEroXUZHFmN
djPNyOrAprcb/sAVDhJ+sFZmGmgfaNdBQHKhpdNNWsJ5OPxd8UHXMZYhHBoQKW0D
dr2JGp4gIIigMKBqz4NzVBYnHlDmk/IjeHmH+wDulnom3ERSC7QqBMInn4Qy7fOF
9H3V/KFioXQsFJFy/a9WUfKRRxiR8CKeLxYY6+pSsPoPl8+WFK3EfbkSBOTv6BEx
PERkZXuGjNrm6+79HSMlKmuUnKOsy8zU1/MIJy0xPENJeH6OlKu1uODvDBxTXn2L
p62zvc3s8/cAAAAAAAAAAAAAAAAAAAAAAAAAAAAADhwsOg==
-----END CERTIFICATE-----
`
