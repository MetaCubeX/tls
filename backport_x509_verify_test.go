package tls

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mldsa"
)

// Re-sign existing fixture keys without requiring the host x509 package to
// marshal ML-DSA keys. No upstream generated fixtures need to change.
func reissueMLDSATestCertificate(t testing.TB, template, parent *x509.Certificate, signer crypto.Signer, scheme SignatureScheme, serial int64, ca bool) *x509.Certificate {
	t.Helper()
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(template.Raw, &outer); err != nil {
		t.Fatal(err)
	}
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(outer.TBS.FullBytes, &fields); err != nil {
		t.Fatal(err)
	}
	switch scheme {
	case MLDSA44, MLDSA65, MLDSA87:
		last := map[SignatureScheme]int{MLDSA44: 17, MLDSA65: 18, MLDSA87: 19}[scheme]
		outer.Algorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, last}}
	case PKCS1WithSHA256:
		outer.Algorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Parameters: asn1.NullRawValue}
	case Ed25519:
		outer.Algorithm = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}}
	default:
		t.Fatalf("unsupported test signature scheme %v", scheme)
	}
	algorithm, err := asn1.Marshal(outer.Algorithm)
	if err != nil {
		t.Fatal(err)
	}
	serialDER, err := asn1.Marshal(big.NewInt(serial))
	if err != nil {
		t.Fatal(err)
	}
	fields[1] = asn1.RawValue{FullBytes: serialDER}
	fields[2] = asn1.RawValue{FullBytes: algorithm}
	fields[3] = asn1.RawValue{FullBytes: parent.RawSubject}
	if ca {
		var extensions []pkix.Extension
		for _, ext := range parent.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) || ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}) {
				extensions = append(extensions, ext)
			}
		}
		der, err := asn1.Marshal(extensions)
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields[:7], asn1.RawValue{Class: 2, Tag: 3, IsCompound: true, Bytes: der})
	}
	tbs, err := asn1.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	signed, opts := tbs, crypto.SignerOpts(directSigning)
	if scheme == PKCS1WithSHA256 {
		digest := sha256.Sum256(tbs)
		signed, opts = digest[:], crypto.SHA256
	}
	sig, err := signer.Sign(rand.Reader, signed, opts)
	if err != nil {
		t.Fatal(err)
	}
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	outer.Signature = asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}
	der, err := asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := X509ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mldsaVerificationFixtures() (ca, leaf *x509.Certificate) {
	return parseTestCert(testMLDSACACertPEM, testMLDSA44KeyPEM).Leaf,
		parseTestCert(testMLDSACALeafCertPEM, testECDSAP256KeyPEM).Leaf
}

func TestMLDSAVerificationPools(t *testing.T) {
	ca, leaf := mldsaVerificationFixtures()
	for _, name := range []string{"root", "intermediate", "PEM-root", "system-plus-root"} {
		t.Run(name, func(t *testing.T) {
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			switch name {
			case "root":
				roots.AddCert(ca)
			case "PEM-root":
				if !roots.AppendCertsFromPEM([]byte(testMLDSACACertPEM)) {
					t.Fatal("could not load root")
				}
			case "system-plus-root":
				var err error
				roots, err = x509.SystemCertPool()
				if err != nil {
					t.Skip(err)
				}
				fallthrough
			case "intermediate":
				roots.AddCert(testRootCert.Leaf)
				intermediates.AddCert(ca)
			}
			rootCopy, intermediateCopy := roots.Clone(), intermediates.Clone()
			chains, err := X509VerifyCertificate(leaf, x509.VerifyOptions{
				Roots: roots, Intermediates: intermediates, CurrentTime: testTime(), DNSName: "test.golang.example",
			})
			if err != nil || len(chains) == 0 || chains[0][0] != leaf {
				t.Fatalf("chains=%v, err=%v", chains, err)
			}
			if !roots.Equal(rootCopy) || !intermediates.Equal(intermediateCopy) {
				t.Fatal("caller pools changed")
			}
			for _, chain := range chains {
				for _, cert := range chain {
					if _, ok := cert.PublicKey.(ed25519.PublicKey); ok {
						t.Fatal("replacement public key escaped")
					}
				}
			}
		})
	}
}

func TestMLDSAVerificationClassicalLeaf(t *testing.T) {
	ca, template := mldsaVerificationFixtures()
	intermediate := reissueMLDSATestCertificate(t, testRootCert.Leaf, ca, testMLDSA44Cert.PrivateKey.(crypto.Signer), MLDSA44, 110, true)
	leaf := reissueMLDSATestCertificate(t, template, intermediate, testRootCert.PrivateKey.(crypto.Signer), PKCS1WithSHA256, 111, false)
	if leaf.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatal("leaf must not require ML-DSA signature adaptation")
	}
	for _, name := range []string{"AddCert", "PEM"} {
		t.Run(name, func(t *testing.T) {
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			if name == "PEM" {
				// Both pools and the leaf can be populated entirely by crypto/x509.
				for pool, cert := range map[*x509.CertPool]*x509.Certificate{roots: ca, intermediates: intermediate} {
					if !pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})) {
						t.Fatal("could not load certificate pool")
					}
				}
			} else {
				roots.AddCert(ca)
				intermediates.AddCert(intermediate)
			}
			candidate, err := x509.ParseCertificate(leaf.Raw)
			if err != nil {
				t.Fatal(err)
			}
			rootCopy, intermediateCopy := roots.Clone(), intermediates.Clone()
			chains, err := X509VerifyCertificate(candidate, x509.VerifyOptions{
				Roots: roots, Intermediates: intermediates, CurrentTime: testTime(), DNSName: "test.golang.example",
			})
			if err != nil || len(chains) != 1 || len(chains[0]) != 3 || chains[0][0] != candidate {
				t.Fatalf("chains=%v, err=%v", chains, err)
			}
			if !roots.Equal(rootCopy) || !intermediates.Equal(intermediateCopy) {
				t.Fatal("caller pools changed")
			}
		})
	}
}

func TestMLDSAVerificationInvalidClassicalBranchBudget(t *testing.T) {
	ca, _ := mldsaVerificationFixtures()
	issuer := reissueMLDSATestCertificate(t, testRootCert.Leaf, ca, testMLDSA44Cert.PrivateKey.(crypto.Signer), MLDSA44, 112, true)
	leaf := testMLDSA44Cert.Leaf // A classical signature, with an ML-DSA-signed issuer.
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca)
	// Only the first certificate can be an issuer candidate for the leaf, and
	// its ECDSA key cannot verify the leaf's RSA signature. Its long issuer
	// branch must not consume preprocessing's budget before the valid issuer.
	for i := 0; i < 100; i++ {
		template, parent := *testRootCert.Leaf, *testRootCert.Leaf
		template.RawSubject, template.RawIssuer, parent.RawSubject = nil, nil, nil
		template.Subject = pkix.Name{CommonName: fmt.Sprintf("irrelevant-%d", i)}
		parent.Subject = pkix.Name{CommonName: fmt.Sprintf("irrelevant-%d", i+1)}
		template.SerialNumber = big.NewInt(int64(2000 + i))
		pub := testRootCert.Leaf.PublicKey
		if i == 0 {
			template.Subject = testRootCert.Leaf.Subject
			pub = testECDSAP256Cert.Leaf.PublicKey
		}
		der, err := x509.CreateCertificate(rand.Reader, &template, &parent, pub, testRootCert.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := X509ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 && !bytes.Equal(candidate.RawSubject, issuer.RawSubject) {
			t.Fatal("invalid candidate must have the valid issuer's subject")
		}
		intermediates.AddCert(candidate)
	}
	intermediates.AddCert(issuer)
	chains, err := X509VerifyCertificate(leaf, x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: testTime(),
	})
	if err != nil || len(chains) != 1 || len(chains[0]) != 3 ||
		chains[0][0] != leaf || chains[0][1] != issuer || chains[0][2] != ca {
		t.Fatalf("invalid branch hid valid chain: chains=%v, err=%v", chains, err)
	}
}

func TestMLDSAVerificationConstraints(t *testing.T) {
	ca, leaf := mldsaVerificationFixtures()
	for _, name := range []string{"signature", "expired", "hostname", "path-length", "name-constraints", "EKU", "unknown-issuer", "not-CA", "key-usage", "critical-extension"} {
		t.Run(name, func(t *testing.T) {
			root, intermediate, candidate := *testRootCert.Leaf, *ca, *leaf
			opts := x509.VerifyOptions{CurrentTime: testTime(), DNSName: "test.golang.example"}
			switch name {
			case "signature":
				candidate.Signature = append([]byte(nil), candidate.Signature...)
				candidate.Signature[0] ^= 1
			case "expired":
				candidate.NotAfter = testTime().Add(-time.Hour)
			case "hostname":
				opts.DNSName = "invalid.example"
			case "path-length":
				root.MaxPathLen, root.MaxPathLenZero = 0, true
			case "name-constraints":
				root.PermittedDNSDomains = []string{"invalid.example"}
				root.PermittedDNSDomainsCritical = true
				root.Extensions = append(append([]pkix.Extension(nil), root.Extensions...), pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 30}, Critical: true})
			case "EKU":
				root.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			case "unknown-issuer":
				root.RawSubject = []byte("different issuer")
			case "not-CA":
				intermediate.IsCA = false
			case "key-usage":
				intermediate.KeyUsage = x509.KeyUsageDigitalSignature
			case "critical-extension":
				candidate.UnhandledCriticalExtensions = []asn1.ObjectIdentifier{{1, 2, 3, 4}}
			}
			opts.Roots, opts.Intermediates = x509.NewCertPool(), x509.NewCertPool()
			opts.Roots.AddCert(&root)
			opts.Intermediates.AddCert(&intermediate)
			if chains, err := X509VerifyCertificate(&candidate, opts); err == nil || len(chains) != 0 {
				t.Fatalf("invalid chain accepted: %v, %v", chains, err)
			}
		})
	}
}

func TestMLDSAVerificationMultipleCAs(t *testing.T) {
	ca1 := parseTestCert(testMLDSACACertPEM, testMLDSA44KeyPEM)
	ca2 := reissueMLDSATestCertificate(t, testMLDSA65Cert.Leaf, ca1.Leaf, ca1.PrivateKey.(crypto.Signer), MLDSA44, 103, true)
	leaf := reissueMLDSATestCertificate(t, testMLDSA87Cert.Leaf, ca2, testMLDSA65Cert.PrivateKey.(crypto.Signer), MLDSA65, 104, false)
	for _, mldsaRoot := range []bool{false, true} {
		t.Run(fmt.Sprint(mldsaRoot), func(t *testing.T) {
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			if mldsaRoot {
				roots.AddCert(ca1.Leaf)
			} else {
				roots.AddCert(testRootCert.Leaf)
				intermediates.AddCert(ca1.Leaf)
			}
			intermediates.AddCert(ca2)
			chains, err := X509VerifyCertificate(leaf, x509.VerifyOptions{
				Roots: roots, Intermediates: intermediates, CurrentTime: testTime(), DNSName: "test.golang.example",
			})
			if err != nil || len(chains) == 0 || chains[0][0] != leaf || chains[0][1] != ca2 {
				t.Fatalf("chains=%v, err=%v", chains, err)
			}
		})
	}
}

func TestMLDSAVerificationAlternatePathsBudget(t *testing.T) {
	ca, leaf := mldsaVerificationFixtures()
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(ca)
	// The direct leaf-to-root path is valid. Same-key issuer candidates that
	// cannot extend that path must not make preprocessing reject it globally.
	for i := 0; i < 100; i++ {
		intermediates.AddCert(reissueMLDSATestCertificate(t, ca, ca,
			testMLDSA44Cert.PrivateKey.(crypto.Signer), MLDSA44, int64(200+i), true))
	}
	chains, err := X509VerifyCertificate(leaf, x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: testTime(),
	})
	if err != nil || len(chains) == 0 || len(chains[0]) != 2 || chains[0][0] != leaf || !chains[0][1].Equal(ca) {
		t.Fatalf("valid direct path rejected: chains=%v, err=%v", chains, err)
	}
}

func TestMLDSAVerificationAuthorityKeyID(t *testing.T) {
	ca, leaf := mldsaVerificationFixtures()
	if len(leaf.AuthorityKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
		t.Fatal("fixtures must have matching authority and subject key IDs")
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(ca.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	keyOffset := bytes.Index(ca.Raw, spki.PublicKey.Bytes)
	if keyOffset < 0 {
		t.Fatal("could not locate CA public key")
	}
	roots := x509.NewCertPool()
	for i := 0; i < 100; i++ {
		seed := make([]byte, mldsa.PrivateKeySize)
		seed[0] = byte(i)
		key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
		if err != nil {
			t.Fatal(err)
		}
		// A trust anchor's certificate signature is not checked. Change only
		// its key, keeping a valid DER certificate with the same subject.
		der := append([]byte(nil), ca.Raw...)
		copy(der[keyOffset:], key.PublicKey().Bytes())
		wrong, err := X509ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		wrong.SubjectKeyId = []byte{0}
		roots.AddCert(wrong)
	}
	// Like crypto/x509, the adapter must try this matching SKID before the
	// earlier same-subject roots whose keys cannot verify the leaf signature.
	roots.AddCert(ca)
	chains, err := X509VerifyCertificate(leaf, x509.VerifyOptions{Roots: roots, CurrentTime: testTime()})
	if err != nil || len(chains) == 0 || len(chains[0]) != 2 || !chains[0][1].Equal(ca) {
		t.Fatalf("matching authority key ignored: chains=%v, err=%v", chains, err)
	}
}

func TestMLDSAVerificationConcurrent(t *testing.T) {
	ca, leaf := mldsaVerificationFixtures()
	caCopy, leafCopy := *ca, *leaf
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(testRootCert.Leaf)
	intermediates.AddCert(ca)
	opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: testTime()}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if _, err := X509VerifyCertificate(leaf, opts); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(ca, &caCopy) || !reflect.DeepEqual(leaf, &leafCopy) {
		t.Fatal("shared certificates changed")
	}
}

func TestMLDSACertificateResumption(t *testing.T) {
	ca, _ := mldsaVerificationFixtures()
	cert := parseTestCert(testMLDSACALeafCertPEM, testECDSAP256KeyPEM)
	cert.Certificate = append(cert.Certificate, ca.Raw)
	for _, version := range []uint16{VersionTLS12, VersionTLS13} {
		for _, root := range []*x509.Certificate{ca, testRootCert.Leaf} {
			t.Run(fmt.Sprintf("%s/%s", VersionName(version), root.Subject.CommonName), func(t *testing.T) {
				client, server := testConfigClient.Clone(), testConfigServer.Clone()
				client.MinVersion, client.MaxVersion = version, version
				server.MinVersion, server.MaxVersion = version, version
				client.Certificates, server.Certificates = []Certificate{cert}, []Certificate{cert}
				client.RootCAs = x509.NewCertPool()
				client.RootCAs.AddCert(root)
				server.ClientAuth, server.ClientCAs = RequireAndVerifyClientCert, client.RootCAs
				client.ClientSessionCache = NewLRUClientSessionCache(1)
				server.SetSessionTicketKeys([][32]byte{{1}})
				check := func(state ConnectionState) error {
					intermediates := x509.NewCertPool()
					for _, peer := range state.PeerCertificates[1:] {
						intermediates.AddCert(peer)
					}
					if _, err := X509VerifyCertificate(state.PeerCertificates[0], x509.VerifyOptions{
						Roots: client.RootCAs, Intermediates: intermediates, CurrentTime: testTime(),
					}); err != nil {
						return err
					}
					if len(state.VerifiedChains) == 0 || state.VerifiedChains[0][0] != state.PeerCertificates[0] {
						return fmt.Errorf("verified chain not preserved")
					}
					for _, chain := range state.VerifiedChains {
						for _, cert := range chain {
							if _, ok := cert.PublicKey.(ed25519.PublicKey); ok {
								return fmt.Errorf("replacement public key escaped")
							}
						}
					}
					return nil
				}
				client.VerifyConnection, server.VerifyConnection = check, check
				for i := 0; i < 2; i++ {
					ss, cs, err := testHandshake(t, client, server)
					if err != nil {
						t.Fatal(err)
					}
					if ss.DidResume != (i == 1) || cs.DidResume != (i == 1) {
						t.Fatalf("handshake %d: server resumed=%v, client resumed=%v", i, ss.DidResume, cs.DidResume)
					}
				}
			})
		}
	}
}
