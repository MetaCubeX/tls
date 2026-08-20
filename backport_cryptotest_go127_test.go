//go:build go1.27

package tls

import (
	"testing"
	"testing/cryptotest"
)

func setGlobalRandom(t *testing.T, seed uint64) {
	t.Helper()
	cryptotest.SetGlobalRandom(t, seed)
}
