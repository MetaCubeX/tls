package tls

func fips140Version() string {
	return "v1.0.0"
}

func fips140WithoutEnforcement(f func()) {
	f()
}
