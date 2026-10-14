//go:build go1.22

package tls

import (
	"bytes"
	"crypto/x509"
	"errors"
	"testing"
)

func TestStdlibCertPoolConstraints(t *testing.T) {
	for _, reject := range []bool{false, true} {
		name := "allow"
		if reject {
			name = "reject"
		}
		t.Run(name, func(t *testing.T) {
			client, server := testConfigClient.Clone(), testConfigServer.Clone()
			server.Certificates = []Certificate{testMLDSA44Cert}
			client.RootCAs = x509.NewCertPool()
			called := false
			client.RootCAs.AddCertWithConstraint(testRootCert.Leaf, func(chain []*x509.Certificate) error {
				called = true
				if len(chain) == 0 || !bytes.Equal(chain[0].Raw, testMLDSA44Cert.Leaf.Raw) {
					t.Error("constraint received the wrong chain")
				}
				if reject {
					return errors.New("root policy rejects this chain")
				}
				return nil
			})
			_, _, err := testHandshake(t, client, server)
			if !called || (err != nil) != reject {
				t.Fatalf("certificate pool constraint: called=%v, reject=%v, err=%v", called, reject, err)
			}
		})
	}
}
