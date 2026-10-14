//go:build !go1.27

package tls

import (
	"crypto"

	"github.com/metacubex/mldsa"
)

const nativeMLDSA = false

// Match the key types returned by the certificate and private-key parsers.
type (
	mldsaPublicKey  = mldsa.PublicKey
	mldsaPrivateKey = mldsa.PrivateKey
)

func mldsaMLDSA44() mldsa.Parameters { return mldsa.MLDSA44() }
func mldsaMLDSA65() mldsa.Parameters { return mldsa.MLDSA65() }
func mldsaMLDSA87() mldsa.Parameters { return mldsa.MLDSA87() }

func mldsaVerify(pub *mldsaPublicKey, message, signature []byte, opts *mldsa.Options) error {
	return mldsa.Verify(pub, message, signature, opts)
}

func extraMLDSASignatureScheme(pub crypto.PublicKey) SignatureScheme { return 0 }

func verifyExtraMLDSA(pub crypto.PublicKey, signed, sig []byte) (bool, error) {
	return false, nil
}
