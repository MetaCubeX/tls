//go:build !go1.27

package tls

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/metacubex/mldsa"
)

// Keep the tests' field access independent of the production offset cache.
func writableX509Field(field reflect.Value) reflect.Value {
	return reflect.NewAt(field.Type(), field.Addr().UnsafePointer()).Elem()
}

func TestMLDSACertificateParents(t *testing.T) {
	view := func(id []byte) *mldsaCertificateView {
		return &mldsaCertificateView{original: &x509.Certificate{SubjectKeyId: id}}
	}
	rWrong, rMissing, rEmpty, rMatch := view([]byte{2}), view(nil), view([]byte{}), view([]byte{1})
	iWrong, iMatch, iMissing := view([]byte{2}), view([]byte{1}), view(nil)
	pools := [2][]*mldsaCertificateView{{rWrong, rMissing, rEmpty, rMatch}, {iWrong, iMatch, iMissing}}
	for _, test := range []struct {
		name string
		akid []byte
		want []*mldsaCertificateView
	}{
		{"present", []byte{1}, []*mldsaCertificateView{rMatch, rMissing, rEmpty, rWrong, iMatch, iMissing, iWrong}},
		{"absent", nil, []*mldsaCertificateView{rMissing, rEmpty, rWrong, rMatch, iMissing, iWrong, iMatch}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := mldsaCertificateParents(&x509.Certificate{AuthorityKeyId: test.akid}, pools)
			for i, parent := range got {
				if i >= len(test.want) || parent != test.want[i] {
					t.Fatalf("unexpected parent at index %d", i)
				}
			}
			if len(got) != len(test.want) {
				t.Fatalf("parents=%d, want %d", len(got), len(test.want))
			}
		})
	}
}

func TestMLDSAVerificationOriginalErrors(t *testing.T) {
	ca, _ := mldsaVerificationFixtures()
	leaf := reissueMLDSATestCertificate(t, testMLDSA65Cert.Leaf, ca, testMLDSA44Cert.PrivateKey.(crypto.Signer), MLDSA44, 107, false)
	for _, name := range []string{"expired", "hostname", "unknown-authority", "expired-intermediate"} {
		t.Run(name, func(t *testing.T) {
			candidate, intermediate := *leaf, *ca
			roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
			opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: testTime()}
			switch name {
			case "expired":
				candidate.NotAfter = testTime().Add(-time.Hour)
				roots.AddCert(&intermediate)
			case "hostname":
				opts.DNSName = "invalid.example"
				roots.AddCert(&intermediate)
			case "expired-intermediate":
				intermediate.NotAfter = testTime().Add(-time.Hour)
				roots.AddCert(testRootCert.Leaf)
				intermediates.AddCert(&intermediate)
			}
			_, err := X509VerifyCertificate(&candidate, opts)
			if err == nil {
				t.Fatal("expected verification failure")
			}
			var check func(error)
			check = func(err error) {
				checkCert := func(cert *x509.Certificate) {
					if cert != &candidate && cert != &intermediate && cert != testRootCert.Leaf {
						t.Fatal("verification error exposed a replacement certificate")
					}
				}
				switch e := err.(type) {
				case x509.CertificateInvalidError:
					checkCert(e.Cert)
				case x509.HostnameError:
					checkCert(e.Certificate)
				case x509.UnknownAuthorityError:
					checkCert(e.Cert)
					value := reflect.ValueOf(&e).Elem()
					cert := writableX509Field(value.FieldByName("hintCert"))
					if !cert.IsNil() {
						checkCert(cert.Interface().(*x509.Certificate))
					}
					hint := writableX509Field(value.FieldByName("hintErr"))
					if !hint.IsNil() {
						check(hint.Interface().(error))
					}
				}
			}
			check(err)
		})
	}
}

func TestMLDSAVerificationRejectsReplacementSignatures(t *testing.T) {
	ca, goodLeaf := mldsaVerificationFixtures()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"invalid-MLDSA", "wrong-algorithm"} {
		t.Run(name, func(t *testing.T) {
			leaf := *goodLeaf
			if name == "invalid-MLDSA" {
				leaf.Signature = append([]byte(nil), leaf.Signature...)
				leaf.Signature[0] ^= 1
			} else {
				leaf = *reissueMLDSATestCertificate(t, goodLeaf, ca, private, Ed25519, 108, false)
			}
			rootView, leafView := *ca, leaf
			rootView.PublicKey, rootView.PublicKeyAlgorithm = private.Public(), x509.Ed25519
			leafView.SignatureAlgorithm = x509.PureEd25519
			leafView.Signature = ed25519.Sign(private, leaf.RawTBSCertificate)
			// Model an adapter defect: the replacement is valid, while the real
			// edge is not. The independent guards must still reject the chain.
			v := &mldsaCertificateVerifier{
				views: map[*x509.Certificate]*mldsaCertificateView{
					ca:    {original: ca, cert: &rootView, key: ca.PublicKey.(*mldsa.PublicKey), keyID: "test-key"},
					&leaf: {original: &leaf, cert: &leafView},
				},
				verified: make(map[mldsaSignatureEdge]error),
			}
			v.views[&rootView], v.views[&leafView] = v.views[ca], v.views[&leaf]
			roots := x509.NewCertPool()
			called := false
			constraint := reflect.ValueOf(roots).MethodByName("AddCertWithConstraint")
			if constraint.IsValid() {
				constraint.Call([]reflect.Value{reflect.ValueOf(ca), reflect.ValueOf(func([]*x509.Certificate) error {
					called = true
					return nil
				})})
			} else {
				roots.AddCert(ca)
			}
			clone, entries, err := cloneMLDSACertPool(roots)
			if err != nil {
				t.Fatal(err)
			}
			v.patchPool(entries)
			chains, err := v.verify(&leaf, x509.VerifyOptions{Roots: clone, CurrentTime: testTime()})
			if err == nil || len(chains) != 0 || called {
				t.Fatalf("replacement authorized invalid chain: chains=%v, err=%v, callback=%v", chains, err, called)
			}
		})
	}
}

func TestMLDSAVerificationNilKeySameSubject(t *testing.T) {
	ca, _ := mldsaVerificationFixtures()
	root, err := x509.ParseCertificate(ca.Raw) // Unknown key in a standard pool.
	if err != nil {
		t.Fatal(err)
	}
	var outer struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	if _, err := asn1.Unmarshal(testMLDSA65Cert.Leaf.Raw, &outer); err != nil {
		t.Fatal(err)
	}
	var fields []asn1.RawValue
	if _, err := asn1.Unmarshal(outer.TBS.FullBytes, &fields); err != nil {
		t.Fatal(err)
	}
	fields[5] = asn1.RawValue{FullBytes: ca.RawSubject}
	tbs, err := asn1.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	outer.TBS = asn1.RawValue{FullBytes: tbs}
	template := *testMLDSA65Cert.Leaf
	template.Raw, err = asn1.Marshal(outer)
	if err != nil {
		t.Fatal(err)
	}
	leaf := reissueMLDSATestCertificate(t, &template, ca, testMLDSA44Cert.PrivateKey.(crypto.Signer), MLDSA44, 109, false)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := X509VerifyCertificate(leaf, x509.VerifyOptions{Roots: roots, CurrentTime: testTime()}); err != nil {
		t.Fatal(err)
	}
	if root.PublicKey != nil {
		t.Fatal("caller root public key changed")
	}
}

func TestMLDSACertPoolInvalidGetter(t *testing.T) {
	ca, _ := mldsaVerificationFixtures()
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	field := reflect.ValueOf(roots).Elem().FieldByName("lazyCerts").Index(0).FieldByName("getCert")
	writableX509Field(field).Set(reflect.Zero(field.Type()))
	if _, _, err := cloneMLDSACertPool(roots); !errors.Is(err, errX509Layout) {
		t.Fatalf("unexpected pool layout error: %v", err)
	}
}

type incompatibleX509ConstraintPool struct {
	lazyCerts []struct {
		rawSubject []byte
		constraint int // Deliberately incompatible with crypto/x509.
		getCert    func() (*x509.Certificate, error)
	}
}

func (*incompatibleX509ConstraintPool) AddCertWithConstraint(*x509.Certificate, func([]*x509.Certificate) error) {
}

func TestX509VerifyLayout(t *testing.T) {
	poolType, errorType := reflect.TypeOf(x509.CertPool{}), reflect.TypeOf(x509.UnknownAuthorityError{})
	if got := loadX509VerifyLayout(poolType, errorType); got != x509VerifyOffsets {
		t.Fatalf("layout=%+v, cached=%+v", got, x509VerifyOffsets)
	}
	for _, test := range []struct {
		name                string
		poolType, errorType reflect.Type
	}{
		{name: "not-a-struct", poolType: reflect.TypeOf(0)},
		{name: "missing-lazyCerts", poolType: reflect.TypeOf(struct{}{})},
		{name: "not-a-slice", poolType: reflect.TypeOf(struct{ lazyCerts int }{})},
		{name: "wrong-getter", poolType: reflect.TypeOf(struct {
			lazyCerts []struct {
				rawSubject []byte
				getCert    func() any
			}
		}{})},
		{name: "wrong-constraint", poolType: reflect.TypeOf(incompatibleX509ConstraintPool{})},
		{name: "missing-hints", errorType: reflect.TypeOf(struct{ Cert *x509.Certificate }{})},
		{name: "wrong-hint-error", errorType: reflect.TypeOf(struct {
			Cert, hintCert *x509.Certificate
			hintErr        string
		}{})},
	} {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				err, ok := recover().(error)
				if !ok || !errors.Is(err, errX509Layout) {
					t.Fatalf("expected incompatible-layout panic, got %v", err)
				}
			}()
			if test.poolType == nil {
				test.poolType = poolType
			}
			if test.errorType == nil {
				test.errorType = errorType
			}
			loadX509VerifyLayout(test.poolType, test.errorType)
		})
	}
}

func TestMLDSACertPoolScan(t *testing.T) {
	for _, empty := range []*x509.CertPool{nil, x509.NewCertPool(), x509.NewCertPool().Clone()} {
		if err := forEachMLDSACertPoolEntry(mldsaCertPoolCerts(empty), func(mldsaCertPoolEntry) bool {
			t.Fatal("empty pool yielded a certificate")
			return false
		}); err != nil {
			t.Fatal(err)
		}
	}
	pool := x509.NewCertPool()
	pool.AddCert(testRootCert.Leaf)
	pool.AddCert(testClientRootCert.Leaf)
	want := []*x509.Certificate{testRootCert.Leaf, testClientRootCert.Leaf}
	lazy := mldsaCertPoolCerts(pool)
	count := 0
	visit := func(entry mldsaCertPoolEntry) bool {
		if entry.cert != want[count] {
			t.Fatal("unexpected certificate from offset-based getter")
		}
		count++
		return true
	}
	allocs := testing.AllocsPerRun(100, func() {
		count = 0
		if err := forEachMLDSACertPoolEntry(lazy, visit); err != nil {
			t.Fatal(err)
		}
	})
	if count != len(want) || allocs != 0 {
		t.Fatalf("visited=%d, allocations=%v; want %d and zero", count, allocs, len(want))
	}
	count = 0
	if err := forEachMLDSACertPoolEntry(lazy, func(entry mldsaCertPoolEntry) bool {
		count++
		return false
	}); err != nil || count != 1 {
		t.Fatalf("scan did not stop early: visited=%d, err=%v", count, err)
	}
}

func TestMLDSAVerificationSignatureLimit(t *testing.T) {
	ca, leaf := mldsaVerificationFixtures()
	for _, name := range []string{"valid", "invalid"} {
		t.Run(name, func(t *testing.T) {
			v := &mldsaCertificateVerifier{
				views: map[*x509.Certificate]*mldsaCertificateView{
					ca: {key: ca.PublicKey.(*mldsa.PublicKey), keyID: "test-key"},
				},
				verified: make(map[mldsaSignatureEdge]error),
			}
			for i := 0; i <= maxMLDSASignatureChecks; i++ {
				child := *leaf
				if name == "invalid" {
					child.Signature = nil
				}
				err := v.checkSignature(&child, ca)
				if i == maxMLDSASignatureChecks {
					if !errors.Is(err, errMLDSASignatureLimit) {
						t.Fatalf("expected signature-check limit, got %v", err)
					}
				} else if (err == nil) != (name == "valid") {
					t.Fatalf("unexpected signature result: %v", err)
				} else if cached := v.checkSignature(&child, ca); cached != err {
					t.Fatalf("cached check changed the result or used the signature budget: %v", cached)
				}
			}
		})
	}
}

func BenchmarkMLDSACertPoolClone(b *testing.B) {
	ca, _ := mldsaVerificationFixtures()
	pool := x509.NewCertPool()
	pool.AddCert(testRootCert.Leaf)
	pool.AddCert(ca)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, entries, err := cloneMLDSACertPool(pool)
		if err != nil || len(entries) != 2 {
			b.Fatalf("entries=%v, err=%v", entries, err)
		}
	}
}

func BenchmarkVerifyCertificateClassical(b *testing.B) {
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(testRootCert.Leaf)
	intermediates.AddCert(testRootCert.Leaf)
	opts := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: testTime()}
	for _, test := range []struct {
		name   string
		verify func(*x509.Certificate, x509.VerifyOptions) ([][]*x509.Certificate, error)
	}{
		{"stdlib", func(cert *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
			return cert.Verify(opts)
		}},
		{"compat", X509VerifyCertificate},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := test.verify(testRSA2048Cert.Leaf, opts); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
