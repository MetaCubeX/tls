//go:build !go1.27

package tls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"reflect"
	"unsafe"

	"github.com/metacubex/mldsa"
)

func verifyCertificate(cert *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	needsAdapter := func(cert *x509.Certificate) bool {
		if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
			_, ok, _ := mldsaCertificateSignature(cert)
			return ok
		}
		return false
	}
	// The leaf can have a classical signature even when an intermediate was
	// signed by an ML-DSA CA. Inspect the supplied pool without cloning or writing.
	needsMLDSA := needsAdapter(cert)
	if !needsMLDSA {
		if err := forEachMLDSACertPoolEntry(mldsaCertPoolCerts(opts.Intermediates), func(entry mldsaCertPoolEntry) bool {
			needsMLDSA = needsAdapter(entry.cert)
			return !needsMLDSA
		}); err != nil {
			return nil, err
		}
	}
	if needsMLDSA {
		return verifyMLDSACertificates(cert, opts)
	}
	return cert.Verify(opts)
}

// A view changes only the algorithm fields used by the Go verifier. DER and
// all certificate constraints remain unchanged. Views must never escape into
// callbacks, ConnectionState, or verification errors.
type mldsaCertificateView struct {
	original, cert *x509.Certificate
	key            *mldsa.PublicKey
	keyID          string
	private        ed25519.PrivateKey
}

type mldsaSignatureEdge struct {
	child *x509.Certificate
	keyID string
}

type mldsaCertificateVerifier struct {
	views    map[*x509.Certificate]*mldsaCertificateView // Indexed by both original and view pointers.
	verified map[mldsaSignatureEdge]error
}

var errMLDSASignatureLimit = errors.New("tls: ML-DSA certificate signature check limit exceeded")

// Match the Go verifier's signature-check budget, including preprocessing.
const maxMLDSASignatureChecks = 100

func mldsaCertificateSignature(cert *x509.Certificate) (mldsa.Parameters, bool, error) {
	var raw struct {
		TBS       asn1.RawValue
		Algorithm pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}
	rest, err := asn1.Unmarshal(cert.Raw, &raw)
	if err != nil {
		return mldsa.Parameters{}, false, err
	}
	params, ok := mldsaParametersFromOID(raw.Algorithm.Algorithm)
	if ok && (len(rest) != 0 || len(raw.Algorithm.Parameters.FullBytes) != 0 ||
		raw.Signature.BitLength != len(raw.Signature.Bytes)*8) {
		return params, true, errors.New("tls: invalid ML-DSA certificate signature encoding")
	}
	return params, ok, nil
}

func mldsaCertificateParents(child *x509.Certificate, pools [2][]*mldsaCertificateView) []*mldsaCertificateView {
	var parents []*mldsaCertificateView
	// Match CertPool.findPotentialParents: roots before intermediates, then
	// matching, missing, and mismatched key IDs within each pool.
	for _, candidates := range pools {
		for group := 0; group < 3; group++ {
			for _, parent := range candidates {
				priority := 2
				if bytes.Equal(parent.original.SubjectKeyId, child.AuthorityKeyId) {
					priority = 0
				} else if len(parent.original.SubjectKeyId) == 0 || len(child.AuthorityKeyId) == 0 {
					priority = 1
				}
				if priority == group {
					parents = append(parents, parent)
				}
			}
		}
	}
	return parents
}

func verifyMLDSACertificates(leaf *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	if opts.Roots == nil {
		var err error
		opts.Roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, x509.SystemRootsError{Err: err}
		}
	}
	roots, rootEntries, err := cloneMLDSACertPool(opts.Roots)
	if err != nil {
		return nil, err
	}
	intermediates, intermediateEntries, err := cloneMLDSACertPool(opts.Intermediates)
	if err != nil {
		return nil, err
	}
	v := &mldsaCertificateVerifier{
		views:    make(map[*x509.Certificate]*mldsaCertificateView),
		verified: make(map[mldsaSignatureEdge]error),
	}
	keys := make(map[string]ed25519.PrivateKey)
	add := func(cert *x509.Certificate) error {
		if v.views[cert] != nil {
			return nil
		}
		copy := *cert
		view := &mldsaCertificateView{original: cert, cert: &copy}
		v.views[cert], v.views[&copy] = view, view
		pub := cert.PublicKey
		if pub == nil {
			if parsed, err := X509ParseCertificate(cert.Raw); err == nil {
				pub = parsed.PublicKey
			}
		}
		if key, ok := pub.(*mldsa.PublicKey); ok && key != nil {
			view.key, view.keyID = key, string(key.Bytes())
			private := keys[view.keyID]
			if private == nil {
				_, private, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return err
				}
				keys[view.keyID] = private
			}
			view.private = private
			copy.PublicKey, copy.PublicKeyAlgorithm = private.Public(), x509.Ed25519
		} else if copy.PublicKey == nil && copy.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm {
			// Go 1.20-1.25's loop detector expects even unsupported candidate
			// keys to implement Equal. The algorithm remains unsupported.
			copy.PublicKey = ed25519.PublicKey(make([]byte, ed25519.PublicKeySize))
		}
		return nil
	}
	if err := add(leaf); err != nil {
		return nil, err
	}
	bySubject := make(map[string][2][]*mldsaCertificateView)
	for i, entries := range [][]mldsaCertPoolEntry{rootEntries, intermediateEntries} {
		for _, entry := range entries {
			if err := add(entry.cert); err != nil {
				return nil, err
			}
			subject := string(entry.cert.RawSubject)
			parents := bySubject[subject]
			parents[i] = append(parents[i], v.views[entry.cert])
			bySubject[subject] = parents
		}
	}
	// Only intermediates reachable through valid signatures need replacement
	// signatures. In particular, trust anchors need no self-signature checks.
	pending := map[*x509.Certificate]bool{leaf: true}
	for _, entry := range intermediateEntries {
		pending[entry.cert] = true
	}
	remaining := maxMLDSASignatureChecks // Includes classical candidate checks.
	var prepare func(*x509.Certificate)
	prepare = func(cert *x509.Certificate) {
		// Bound candidate checks as well as traversal. Unprepared ML-DSA
		// signatures remain unsupported; they can never authorize a chain.
		if !pending[cert] || remaining == 0 {
			return
		}
		delete(pending, cert)
		view := v.views[cert].cert
		_, isMLDSA, _ := mldsaCertificateSignature(cert)
		if isMLDSA {
			view.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
		} else if view.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
			return
		}
		parents := mldsaCertificateParents(cert, bySubject[string(cert.RawIssuer)])
		for _, parent := range parents {
			if remaining == 0 {
				return // Already prepared paths remain usable.
			}
			remaining--
			if err := v.checkSignature(cert, parent.original); err != nil {
				continue
			}
			if isMLDSA && view.SignatureAlgorithm == x509.UnknownSignatureAlgorithm {
				view.SignatureAlgorithm = x509.PureEd25519
				view.Signature = ed25519.Sign(parent.private, cert.RawTBSCertificate)
			}
			prepare(parent.original)
		}
	}
	prepare(leaf)
	v.patchPool(rootEntries)
	v.patchPool(intermediateEntries)
	opts.Roots, opts.Intermediates = roots, intermediates
	return v.verify(leaf, opts)
}

func (v *mldsaCertificateVerifier) verify(leaf *x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	chains, err := v.views[leaf].cert.Verify(opts)
	if err != nil {
		return nil, v.originalError(err)
	}
	var verified [][]*x509.Certificate
	for _, chain := range chains {
		err = nil
		// The Go verifier keeps the input leaf. Platform verifiers reparse the
		// original DER; preserve their verification policy instead of rechecking it.
		original := v.originalChain(chain)
		if chain[0] == v.views[leaf].cert {
			for i := 0; i+1 < len(original); i++ {
				if err = v.checkSignature(original[i], original[i+1]); err != nil {
					break
				}
			}
		}
		if err == nil {
			verified = append(verified, original)
		}
	}
	if len(verified) == 0 {
		return nil, err
	}
	return verified, nil
}

func (v *mldsaCertificateVerifier) checkSignature(child, parent *x509.Certificate) error {
	params, ok, err := mldsaCertificateSignature(child)
	if !ok {
		return child.CheckSignatureFrom(parent)
	}
	if err != nil {
		return err
	}
	p := v.views[parent]
	if p == nil || p.key == nil || p.key.Parameters() != params {
		return x509.ErrUnsupportedAlgorithm
	}
	if parent.Version == 3 && !parent.BasicConstraintsValid || parent.BasicConstraintsValid && !parent.IsCA ||
		parent.KeyUsage != 0 && parent.KeyUsage&x509.KeyUsageCertSign == 0 {
		return x509.ConstraintViolationError{}
	}
	edge := mldsaSignatureEdge{child, p.keyID}
	if err, checked := v.verified[edge]; checked {
		return err
	}
	if len(v.verified) >= maxMLDSASignatureChecks {
		return errMLDSASignatureLimit
	}
	err = mldsa.Verify(p.key, child.RawTBSCertificate, child.Signature, nil)
	v.verified[edge] = err
	return err
}

func (v *mldsaCertificateVerifier) originalChain(chain []*x509.Certificate) []*x509.Certificate {
	original := make([]*x509.Certificate, len(chain))
	for i, cert := range chain {
		original[i] = v.original(cert)
	}
	return original
}

func (v *mldsaCertificateVerifier) original(cert *x509.Certificate) *x509.Certificate {
	if view := v.views[cert]; view != nil {
		return view.original
	}
	return cert
}

func (v *mldsaCertificateVerifier) originalError(err error) error {
	switch e := err.(type) {
	case x509.CertificateInvalidError:
		e.Cert = v.original(e.Cert)
		return e
	case x509.HostnameError:
		e.Certificate = v.original(e.Certificate)
		return e
	case x509.UnknownAuthorityError:
		e.Cert = v.original(e.Cert)
		// Private hints can contain views too. Their offsets are checked at init.
		hintCert := (**x509.Certificate)(unsafe.Add(unsafe.Pointer(&e), x509VerifyOffsets.hintCert))
		hintErr := (*error)(unsafe.Add(unsafe.Pointer(&e), x509VerifyOffsets.hintErr))
		*hintCert = v.original(*hintCert)
		*hintErr = v.originalError(*hintErr)
		return e
	}
	return err
}

type mldsaCertPoolEntry struct {
	cert       *x509.Certificate
	getter     *func() (*x509.Certificate, error)
	constraint *func([]*x509.Certificate) error
}

var errX509Layout = errors.New("tls: unsupported crypto/x509 layout for ML-DSA verification")

type x509VerifyLayout struct {
	poolLazyCerts, lazyCertSize, lazyGetCert, lazyConstraint uintptr
	hintCert, hintErr                                        uintptr
	hasConstraints                                           bool
}

// Resolve and validate private fields once, before any verification can run.
// Offsets come from this toolchain, not a hard-coded copy of a private struct.
var x509VerifyOffsets = loadX509VerifyLayout(reflect.TypeOf(x509.CertPool{}), reflect.TypeOf(x509.UnknownAuthorityError{}))

func loadX509VerifyLayout(poolType, errorType reflect.Type) x509VerifyLayout {
	field := func(t reflect.Type, name string, want reflect.Type) reflect.StructField {
		if t.Kind() != reflect.Struct {
			panic(errX509Layout)
		}
		f, ok := t.FieldByName(name)
		if !ok || len(f.Index) != 1 || want != nil && f.Type != want {
			panic(errX509Layout)
		}
		return f
	}
	lazy := field(poolType, "lazyCerts", nil)
	if lazy.Type.Kind() != reflect.Slice || lazy.Type.Elem().Kind() != reflect.Struct {
		panic(errX509Layout)
	}
	entryType := lazy.Type.Elem()
	_, hasConstraints := reflect.PointerTo(poolType).MethodByName("AddCertWithConstraint")
	fields := 2
	if hasConstraints {
		fields++
	}
	if entryType.NumField() != fields {
		panic(errX509Layout)
	}
	field(entryType, "rawSubject", reflect.TypeOf([]byte(nil)))
	layout := x509VerifyLayout{
		poolLazyCerts:  lazy.Offset,
		lazyCertSize:   entryType.Size(),
		lazyGetCert:    field(entryType, "getCert", reflect.TypeOf((func() (*x509.Certificate, error))(nil))).Offset,
		hasConstraints: hasConstraints,
	}
	if hasConstraints {
		layout.lazyConstraint = field(entryType, "constraint", reflect.TypeOf((func([]*x509.Certificate) error)(nil))).Offset
	}
	certType := reflect.TypeOf((*x509.Certificate)(nil))
	field(errorType, "Cert", certType)
	if errorType.NumField() != 3 {
		panic(errX509Layout)
	}
	layout.hintCert = field(errorType, "hintCert", certType).Offset
	layout.hintErr = field(errorType, "hintErr", reflect.TypeOf((*error)(nil)).Elem()).Offset
	return layout
}

// View only the slice descriptor as []byte. Its length is the certificate count,
// not a byte count; never index or reslice it. Entries use the cached stride.
func mldsaCertPoolCerts(pool *x509.CertPool) []byte {
	if pool == nil {
		return nil
	}
	return *(*[]byte)(unsafe.Add(unsafe.Pointer(pool), x509VerifyOffsets.poolLazyCerts))
}

func cloneMLDSACertPool(pool *x509.CertPool) (*x509.CertPool, []mldsaCertPoolEntry, error) {
	if pool == nil {
		return nil, nil, nil
	}
	clone := pool.Clone()
	lazy := mldsaCertPoolCerts(clone)
	entries := make([]mldsaCertPoolEntry, 0, len(lazy))
	err := forEachMLDSACertPoolEntry(lazy, func(entry mldsaCertPoolEntry) bool {
		entries = append(entries, entry)
		return true
	})
	return clone, entries, err
}

// Visit until the callback returns false. Writes through entry pointers are
// allowed only for slices obtained from CertPool.Clone, never caller-owned pools.
func forEachMLDSACertPoolEntry(certs []byte, visit func(mldsaCertPoolEntry) bool) error {
	data := unsafe.Pointer(unsafe.SliceData(certs))
	for i := 0; i < len(certs); i++ {
		ptr := unsafe.Add(data, uintptr(i)*x509VerifyOffsets.lazyCertSize)
		getter := (*func() (*x509.Certificate, error))(unsafe.Add(ptr, x509VerifyOffsets.lazyGetCert))
		if *getter == nil {
			return errX509Layout
		}
		cert, err := (*getter)()
		if err != nil {
			continue // Preserve failed getters; Verify handles their errors.
		}
		if cert == nil {
			return errX509Layout
		}
		entry := mldsaCertPoolEntry{cert: cert, getter: getter}
		if x509VerifyOffsets.hasConstraints {
			entry.constraint = (*func([]*x509.Certificate) error)(unsafe.Add(ptr, x509VerifyOffsets.lazyConstraint))
		}
		if !visit(entry) {
			return nil
		}
	}
	return nil
}

func (v *mldsaCertificateVerifier) patchPool(entries []mldsaCertPoolEntry) {
	for _, entry := range entries {
		cert, view := entry.cert, v.views[entry.cert].cert
		*entry.getter = func() (*x509.Certificate, error) { return view, nil }
		if entry.constraint != nil {
			constraint := *entry.constraint
			*entry.constraint = func(chain []*x509.Certificate) error {
				// Every edge is checked before the parent's original constraint.
				// Never let a replacement signature authorize a real chain.
				if err := v.checkSignature(v.original(chain[len(chain)-1]), cert); err != nil {
					return err
				}
				if constraint != nil {
					return constraint(v.originalChain(chain))
				}
				return nil
			}
		}
	}
}
