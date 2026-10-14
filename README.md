# TLS

backport tls for go1.20+

export `crypto/tls` from:
https://github.com/golang/go/tree/go1.27.2/src/crypto/tls

## ML-DSA compatibility

ML-DSA CA verification is supported on Go 1.20-1.26 through a
version-gated certificate pool adapter. Go 1.27+ uses the standard verifier
directly. Public certificate and pool types remain those of `crypto/x509`.
TLS uses this adapter automatically. External callers can use
`tls.X509VerifyCertificate(leaf, opts)` in place of `leaf.Verify(opts)`, with
intermediate certificates supplied in `opts.Intermediates` as usual.
Certificates and pools can be populated using the standard library's parsers.
`tls.X509ParseCertificate` and `tls.X509ParsePKCS8PrivateKey` additionally decode
ML-DSA public keys and seed-only private keys on older Go versions.
On Go 1.20-1.26, private X.509 layouts are validated once at package initialization;
an incompatible standard library causes an immediate panic.
Direct calls to the older standard library's `Certificate.Verify` or
`CheckSignatureFrom` methods are not changed. In `VerifyConnection` or
`VerifyPeerCertificate`, use `tls.X509VerifyCertificate` when verifying chains
that may contain ML-DSA CA signatures.

On Go 1.20-1.26, decoded ML-DSA keys use `github.com/metacubex/mldsa` types;
on Go 1.27+, the parsers return native `crypto/mldsa` types. Prefer
`crypto.Signer` over version-dependent concrete private-key assertions.

For externally supplied certificates with fork ML-DSA public keys, call
`tls.X509NormalizeCertificate` before `CertPool.AddCert` or `AddCertWithConstraint`.
On Go 1.27+ it returns a shallow copy with a native public key, preserving all
other fields; otherwise it returns the original certificate. Repeated calls
reuse the normalized certificate. It does not change TLS private keys or
normalize certificates already stored in a pool.

The older standard library's ML-DSA algorithm fields remain `Unknown`.
Certificates loaded into pools by standard-library parsers can retain a nil
`PublicKey`, even in returned verified chains: the adapter preserves the
original certificates. Use `tls.X509ParseCertificate` before `CertPool.AddCert`
if callers need the decoded public key.

This is a TLS backport, not a complete X.509 backport. On older Go versions,
standard-library `ParsePKIXPublicKey`, `MarshalPKIXPublicKey`,
`MarshalPKCS8PrivateKey`, and ML-DSA certificate, CSR, and CRL operations are
not extended. Parsing private keys supports only seed-only ML-DSA encoding,
matching Go 1.27. Other certificate validation rules follow the host Go
version, and malformed-input errors need not match Go 1.27 exactly.

ML-DSA CA verification clones the pools and uses private certificate views
with independently checked signatures. Candidate preprocessing and ML-DSA
signature checks are bounded to prevent excessive work; pathological candidate
graphs need not produce exactly the same chain selection as Go 1.27. Go 1.27+
does not compile this adapter and uses native verification directly.

System-root verification retains standard-library behavior. On Windows and
macOS, ML-DSA support in the native system verifier still depends on the OS,
just as with Go 1.27.
