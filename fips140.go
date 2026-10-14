package tls

func fips140Version() string {
	return ""
}

func fips140WithoutEnforcement(f func()) {
	f()
}
