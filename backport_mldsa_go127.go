//go:build go1.27

package tls

import (
	"crypto"
	"crypto/mldsa"
	"errors"

	backportmldsa "github.com/metacubex/mldsa"
)

const nativeMLDSA = true

// Keep native X.509 key values and upstream's concrete-key branches intact.
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

func extraMLDSASignatureScheme(pub crypto.PublicKey) SignatureScheme {
	key, ok := pub.(*backportmldsa.PublicKey)
	if !ok || key == nil {
		return 0
	}
	switch key.Parameters() {
	case backportmldsa.MLDSA44():
		return MLDSA44
	case backportmldsa.MLDSA65():
		return MLDSA65
	case backportmldsa.MLDSA87():
		return MLDSA87
	default:
		panic("tls: internal error: unknown ML-DSA parameter set: " + key.Parameters().String())
	}
}

// Report key-type support separately from signature validity, without
// serializing or replacing the public key.
func verifyExtraMLDSA(pub crypto.PublicKey, signed, sig []byte) (bool, error) {
	key, ok := pub.(*backportmldsa.PublicKey)
	if !ok {
		return false, nil
	}
	return true, backportmldsa.Verify(key, signed, sig, nil)
}

// A nil key with no error means that the original public key needs no change.
func normalizeX509PublicKey(pub crypto.PublicKey) (*mldsaPublicKey, error) {
	// Also avoid conversion if the fork ever aliases the native type.
	if _, ok := pub.(*mldsaPublicKey); ok {
		return nil, nil
	}
	key, ok := pub.(*backportmldsa.PublicKey)
	if !ok {
		return nil, nil
	}
	if key == nil {
		return nil, errors.New("tls: nil ML-DSA public key")
	}
	encoded := key.Bytes()
	var params mldsa.Parameters
	// Each ML-DSA parameter set has a distinct public-key encoding length. This
	// also rejects a zero-value fork key without calling its Parameters method.
	switch len(encoded) {
	case mldsa.MLDSA44PublicKeySize:
		params = mldsaMLDSA44()
	case mldsa.MLDSA65PublicKeySize:
		params = mldsaMLDSA65()
	case mldsa.MLDSA87PublicKeySize:
		params = mldsaMLDSA87()
	default:
		return nil, errors.New("tls: invalid ML-DSA public key size")
	}
	return mldsa.NewPublicKey(params, encoded)
}
