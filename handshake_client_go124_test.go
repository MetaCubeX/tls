//go:build go1.24

package tls

// Go 1.24+ already produces the signatures used by the handshake recordings.
func prepareReferenceConfig(config *Config) *Config {
	return config
}
