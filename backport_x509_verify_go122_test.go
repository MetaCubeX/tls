//go:build go1.22

package tls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"
)

func TestMLDSARootConstraints(t *testing.T) {
	ca, leaf := mldsaVerificationFixtures()
	for _, reject := range []bool{false, true} {
		for _, root := range []*x509.Certificate{ca, testRootCert.Leaf} {
			name := root.Subject.CommonName + "/allow"
			if reject {
				name = root.Subject.CommonName + "/reject"
			}
			t.Run(name, func(t *testing.T) {
				roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
				if root != ca {
					intermediates.AddCert(ca)
				}
				called := false
				roots.AddCertWithConstraint(root, func(chain []*x509.Certificate) error {
					called = true
					want := []*x509.Certificate{leaf}
					if root != ca {
						want = append(want, ca)
					}
					if !reflect.DeepEqual(chain, want) {
						t.Error("constraint received changed certificates")
					}
					for i := range want {
						if chain[i] != want[i] {
							t.Error("constraint did not receive original certificate pointers")
						}
					}
					if reject {
						return errors.New("reject original chain")
					}
					return nil
				})
				_, err := X509VerifyCertificate(leaf, x509.VerifyOptions{
					Roots: roots, Intermediates: intermediates, CurrentTime: testTime(),
				})
				if !called || (err != nil) != reject {
					t.Fatalf("called=%v, reject=%v, err=%v", called, reject, err)
				}
			})
		}
	}
}

func TestMLDSACrossSignedConstraints(t *testing.T) {
	ca, leaf := mldsaVerificationFixtures()
	bad := reissueMLDSATestCertificate(t, ca, testRootCert.Leaf, testRootCert.PrivateKey.(crypto.Signer), PKCS1WithSHA256, 105, true)
	good := reissueMLDSATestCertificate(t, ca, testRootCert.Leaf, testRootCert.PrivateKey.(crypto.Signer), PKCS1WithSHA256, 106, true)
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	intermediates.AddCert(bad)
	intermediates.AddCert(good)
	var rejected, accepted bool
	roots.AddCertWithConstraint(testRootCert.Leaf, func(chain []*x509.Certificate) error {
		if len(chain) != 2 || chain[0] != leaf {
			t.Fatal("unexpected chain")
		}
		switch chain[1] {
		case bad:
			rejected = true
			return errors.New("reject first cross-sign")
		case good:
			accepted = true
		default:
			t.Error("constraint received a replacement certificate")
		}
		return nil
	})
	chains, err := X509VerifyCertificate(leaf, x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: testTime(),
	})
	if err != nil || !rejected || !accepted || len(chains) != 1 || chains[0][1] != good {
		t.Fatalf("rejected=%v, accepted=%v, chains=%v, err=%v", rejected, accepted, chains, err)
	}
}
