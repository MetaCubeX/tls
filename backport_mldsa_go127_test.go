//go:build go1.27

package tls

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	backportmldsa "github.com/metacubex/mldsa"
)

func forkMLDSAPrivateKey(t *testing.T, key *mldsa.PrivateKey) *backportmldsa.PrivateKey {
	t.Helper()
	params := map[mldsa.Parameters]backportmldsa.Parameters{
		mldsa.MLDSA44(): backportmldsa.MLDSA44(),
		mldsa.MLDSA65(): backportmldsa.MLDSA65(),
		mldsa.MLDSA87(): backportmldsa.MLDSA87(),
	}
	forkKey, err := backportmldsa.NewPrivateKey(params[key.PublicKey().Parameters()], key.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return forkKey
}

func TestNativeMLDSAKeys(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		serverCert, clientCert Certificate
		serverKey, clientKey   string
	}{
		{"44", testMLDSA44Cert, testClientMLDSA44Cert, testMLDSA44KeyPEM, testClientMLDSA44KeyPEM},
		{"65", testMLDSA65Cert, testClientMLDSA65Cert, testMLDSA65KeyPEM, testClientMLDSA65KeyPEM},
		{"87", testMLDSA87Cert, testClientMLDSA87Cert, testMLDSA87KeyPEM, testClientMLDSA87KeyPEM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nativeCert := func(cert Certificate, keyPEM string) Certificate {
				t.Helper()
				loaded, err := X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), []byte(testingKey(keyPEM)))
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := loaded.PrivateKey.(*mldsa.PrivateKey); !ok {
					t.Fatalf("native private key was replaced when loading PEM: %T", loaded.PrivateKey)
				}
				block, _ := pem.Decode([]byte(keyPEM))
				key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if _, ok := key.(*mldsa.PrivateKey); !ok {
					t.Fatalf("non-native private key: %T", key)
				}
				cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
				if err != nil {
					t.Fatal(err)
				}
				cert.PrivateKey = key
				return cert
			}
			forkCert := func(cert Certificate) Certificate {
				cert.PrivateKey = forkMLDSAPrivateKey(t, cert.PrivateKey.(*mldsa.PrivateKey))
				return cert
			}
			for _, serverBackend := range []struct {
				name string
				cert Certificate
			}{{"native", nativeCert(tc.serverCert, tc.serverKey)}, {"fork", forkCert(tc.serverCert)}} {
				for _, clientBackend := range []struct {
					name string
					cert Certificate
				}{{"native", nativeCert(tc.clientCert, tc.clientKey)}, {"fork", forkCert(tc.clientCert)}} {
					for _, mode := range []string{"direct", "callbacks"} {
						t.Run(serverBackend.name+"/"+clientBackend.name+"/"+mode, func(t *testing.T) {
							client, server := testConfigClient.Clone(), testConfigServer.Clone()
							client.MinVersion, client.MaxVersion = VersionTLS13, VersionTLS13
							server.MinVersion, server.MaxVersion = VersionTLS13, VersionTLS13
							server.ClientAuth = RequireAndVerifyClientCert
							client.Certificates = []Certificate{clientBackend.cert}
							server.Certificates = []Certificate{serverBackend.cert}
							if mode == "callbacks" {
								client.Certificates, server.Certificates = nil, nil
								client.GetClientCertificate = func(*CertificateRequestInfo) (*Certificate, error) {
									return &clientBackend.cert, nil
								}
								server.GetCertificate = func(*ClientHelloInfo) (*Certificate, error) {
									return &serverBackend.cert, nil
								}
							}
							ss, cs, err := testHandshake(t, client, server)
							if err != nil {
								t.Fatal(err)
							}
							for _, cert := range []*x509.Certificate{clientBackend.cert.Leaf, serverBackend.cert.Leaf, ss.PeerCertificates[0], cs.PeerCertificates[0]} {
								if _, ok := cert.PublicKey.(*mldsa.PublicKey); !ok {
									t.Fatalf("native certificate public key was replaced: %T", cert.PublicKey)
								}
								spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
								if err != nil || !bytes.Equal(spki, cert.RawSubjectPublicKeyInfo) {
									t.Fatalf("standard-library public-key encoding failed: %v", err)
								}
							}
						})
					}
				}
			}
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tc.serverCert.Certificate[0]})
			for _, invalid := range []struct{ keyPEM, wantError string }{
				{tc.clientKey, "private key does not match public key"},
				{testECDSAP256KeyPEM, "private key type does not match public key type"},
			} {
				if _, err := X509KeyPair(certPEM, []byte(testingKey(invalid.keyPEM))); err == nil || !strings.Contains(err.Error(), invalid.wantError) {
					t.Fatalf("mismatched private key: got %v, want %q", err, invalid.wantError)
				}
			}
		})
	}
}

func TestMLDSABackendDispatch(t *testing.T) {
	message := []byte("TLS ML-DSA backend dispatch")
	for _, tc := range []struct {
		params mldsa.Parameters
		scheme SignatureScheme
		key    *mldsa.PrivateKey
	}{
		{mldsa.MLDSA44(), MLDSA44, testMLDSA44Key},
		{mldsa.MLDSA65(), MLDSA65, testMLDSA65Key},
		{mldsa.MLDSA87(), MLDSA87, testMLDSA87Key},
	} {
		t.Run(tc.params.String(), func(t *testing.T) {
			nativeKey, err := mldsa.NewPrivateKey(tc.params, tc.key.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			backends := []struct {
				name string
				key  crypto.Signer
			}{{"native", nativeKey}, {"fork", forkMLDSAPrivateKey(t, tc.key)}}
			for _, verifier := range backends {
				t.Run(verifier.name, func(t *testing.T) {
					pub := verifier.key.Public()
					var scheme SignatureScheme
					if allocs := testing.AllocsPerRun(100, func() {
						scheme = mldsaSignatureScheme(pub)
					}); allocs != 0 {
						t.Fatalf("public-key classification allocated %v times", allocs)
					}
					if scheme != tc.scheme {
						t.Fatalf("signature scheme = %v, want %v", scheme, tc.scheme)
					}
					schemes := signatureSchemesForPublicKey(VersionTLS13, pub)
					if len(schemes) != 1 || schemes[0] != tc.scheme {
						t.Fatalf("incorrect supported signature schemes: %v", schemes)
					}
					if _, _, err := legacyTypeAndHashFromPublicKey(pub); err == nil || !strings.Contains(err.Error(), "ML-DSA") {
						t.Fatalf("legacy ML-DSA key was not rejected: %v", err)
					}
					cert := &Certificate{PrivateKey: verifier.key}
					if _, err := selectSignatureScheme(VersionTLS12, cert, []SignatureScheme{tc.scheme}); err == nil {
						t.Fatal("ML-DSA key accepted for TLS 1.2")
					}
					for _, signer := range backends {
						t.Run(signer.name, func(t *testing.T) {
							sig, err := signer.key.Sign(rand.Reader, message, directSigning)
							if err != nil {
								t.Fatal(err)
							}
							baseline := testing.AllocsPerRun(10, func() {
								var err error
								if key, ok := pub.(*mldsa.PublicKey); ok {
									err = mldsa.Verify(key, message, sig, nil)
								} else if key, ok := pub.(*backportmldsa.PublicKey); ok {
									err = backportmldsa.Verify(key, message, sig, nil)
								} else {
									t.Fatalf("unexpected public key type: %T", pub)
								}
								if err != nil {
									t.Fatal(err)
								}
							})
							allocs := testing.AllocsPerRun(10, func() {
								if err := verifyHandshakeSignature(signatureMLDSA, pub, directSigning, message, sig); err != nil {
									t.Fatal(err)
								}
							})
							if allocs != baseline {
								t.Fatalf("signature dispatch added allocations: got %v, direct backend %v", allocs, baseline)
							}
							badSig := bytes.Clone(sig)
							badSig[0] ^= 1
							for _, invalid := range [][]byte{nil, sig[:len(sig)-1], badSig} {
								if err := verifyHandshakeSignature(signatureMLDSA, pub, directSigning, message, invalid); err == nil {
									t.Fatal("invalid signature accepted")
								}
							}
						})
					}
				})
			}
		})
	}
	for _, pub := range []crypto.PublicKey{nil, testRSA2048Key.Public(), (*mldsa.PublicKey)(nil), (*backportmldsa.PublicKey)(nil)} {
		if mldsaSignatureScheme(pub) != 0 {
			t.Fatalf("invalid ML-DSA key recognized: %T", pub)
		}
		if err := verifyHandshakeSignature(signatureMLDSA, pub, directSigning, message, nil); err == nil {
			t.Fatalf("invalid ML-DSA key accepted: %T", pub)
		}
	}
}

func TestForkMLDSALegacyVersions(t *testing.T) {
	for _, cert := range []Certificate{testMLDSA44Cert, testMLDSA65Cert, testMLDSA87Cert} {
		key := cert.PrivateKey.(*mldsa.PrivateKey)
		cert.PrivateKey = forkMLDSAPrivateKey(t, key)
		for _, version := range []uint16{VersionTLS10, VersionTLS12} {
			t.Run(key.PublicKey().Parameters().String()+"/"+VersionName(version), func(t *testing.T) {
				client, server := testConfigClient.Clone(), testConfigServer.Clone()
				client.MinVersion, client.MaxVersion = version, version
				server.MinVersion, server.MaxVersion = version, version
				server.Certificates = []Certificate{cert}
				if _, _, err := testHandshake(t, client, server); err == nil || !strings.Contains(err.Error(), "ML-DSA") {
					t.Fatalf("legacy fork-key handshake was not rejected as ML-DSA: %v", err)
				}
			})
		}
		// With no signature_algorithms extension, exercise SupportsCertificate's
		// legacy fallback rather than selectSignatureScheme.
		hello := &ClientHelloInfo{
			SupportedVersions: []uint16{VersionTLS12},
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256},
			SupportedPoints:   []uint8{pointFormatUncompressed},
		}
		if err := hello.SupportsCertificate(&cert); err == nil || !strings.Contains(err.Error(), "ML-DSA") {
			t.Fatalf("legacy fork-key certificate was not rejected as ML-DSA: %v", err)
		}
	}
}

func BenchmarkNativeMLDSADispatch(b *testing.B) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		key, err := mldsa.GenerateKey(params)
		if err != nil {
			b.Fatal(err)
		}
		pub := key.PublicKey()
		message := make([]byte, 130)
		sig, err := key.Sign(rand.Reader, message, directSigning)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(params.String()+"/direct", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := mldsa.Verify(pub, message, sig, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(params.String()+"/TLS", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if err := verifyHandshakeSignature(signatureMLDSA, pub, directSigning, message, sig); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
