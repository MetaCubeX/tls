package tls

import (
	"crypto"
	"fmt"
)

// Keep upstream's concrete-key branches; recognize non-primary keys only at
// their fallback boundaries. No key is serialized or replaced.
func mldsaSignatureScheme(pub crypto.PublicKey) SignatureScheme {
	key, ok := pub.(*mldsaPublicKey)
	if !ok {
		return extraMLDSASignatureScheme(pub)
	}
	if key == nil {
		return 0
	}
	switch key.Parameters() {
	case mldsaMLDSA44():
		return MLDSA44
	case mldsaMLDSA65():
		return MLDSA65
	case mldsaMLDSA87():
		return MLDSA87
	default:
		panic("tls: internal error: unknown ML-DSA parameter set: " + key.Parameters().String())
	}
}

func verifyExtraMLDSAHandshakeSignature(pub crypto.PublicKey, signed, sig []byte) error {
	ok, err := verifyExtraMLDSA(pub, signed, sig)
	if !ok {
		return fmt.Errorf("expected an ML-DSA public key, got %T", pub)
	}
	if err != nil {
		return fmt.Errorf("ML-DSA verification failure: %w", err)
	}
	return nil
}
