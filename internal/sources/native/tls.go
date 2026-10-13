package native

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// TLSCert grabs a host's TLS certificate and mines it: the certificate becomes an
// entity keyed by its SHA-256 (the substrate for sibling-infrastructure pivots),
// and every SAN becomes a host the engine then resolves. It is active: it dials the
// target on 443.
type TLSCert struct {
	Timeout time.Duration
}

// NewTLSCert returns a TLS source with a short dial timeout.
func NewTLSCert() *TLSCert { return &TLSCert{Timeout: 10 * time.Second} }

// Capability marks it active, consuming a host and producing hosts and a cert.
func (p *TLSCert) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/tls",
		Consumes: []graph.EntityType{graph.TypeHost},
		Produces: []graph.EntityType{graph.TypeHost, graph.TypeCertificate},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; it uses the standard library.
func (p *TLSCert) Available(sources.Env) bool { return true }

// Collect dials the host on 443 and mines its leaf certificate. A host that does
// not serve TLS is not an error.
func (p *TLSCert) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	host := in.Key
	// InsecureSkipVerify so a self-signed or expired certificate is still mined; the
	// certificate's own validity is recorded as facts, not enforced.
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: p.Timeout},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec // recon mines invalid certs on purpose
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil
	}
	defer conn.Close()
	tconn, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	certs := tconn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	p.emit(host, certs[0], sink)
	return nil
}

// emit records a leaf certificate and its SANs.
func (p *TLSCert) emit(host string, cert *x509.Certificate, sink sources.Sink) {
	self := sink.Entity(graph.TypeHost, host, host)
	sum := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(sum[:])

	display := cert.Subject.CommonName
	if display == "" {
		display = fp[:16]
	}
	ce := sink.Entity(graph.TypeCertificate, fp, display)
	sink.Edge(self, ce, graph.RelPresentsCert, 1.0)
	sink.Fact(self, "tls_sha256", fp, 1.0) // the key other hosts correlate on

	if cert.Subject.CommonName != "" {
		sink.Fact(ce, "subject_cn", cert.Subject.CommonName, 1.0)
	}
	if iss := issuerName(cert); iss != "" {
		sink.Fact(ce, "issuer", iss, 1.0)
	}
	sink.Fact(ce, "not_before", cert.NotBefore.UTC().Format(time.RFC3339), 1.0)
	sink.Fact(ce, "not_after", cert.NotAfter.UTC().Format(time.RFC3339), 1.0)
	if cert.SerialNumber != nil {
		sink.Fact(ce, "serial", cert.SerialNumber.Text(16), 0.9)
	}
	sink.Fact(ce, "key_algo", cert.PublicKeyAlgorithm.String(), 0.9)
	sink.Fact(ce, "sig_algo", cert.SignatureAlgorithm.String(), 0.9)
	if bits := keyBits(cert); bits > 0 {
		sink.Fact(ce, "key_bits", strconv.Itoa(bits), 0.9)
	}
	// Posture facts a report and the exposure rules can read directly.
	if strings.EqualFold(cert.Subject.String(), cert.Issuer.String()) {
		sink.Fact(ce, "self_signed", "true", 0.9)
	}
	if weakSignature(cert.SignatureAlgorithm) {
		sink.Fact(ce, "weak_signature", cert.SignatureAlgorithm.String(), 0.9)
	}
	if now := time.Now(); now.After(cert.NotAfter) {
		sink.Fact(ce, "expired", "true", 1.0)
	} else if now.Before(cert.NotBefore) {
		sink.Fact(ce, "not_yet_valid", "true", 1.0)
	}

	for _, raw := range cert.DNSNames {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		sink.Fact(ce, "san", name, 1.0)
		// A wildcard SAN names a zone, not a host; the bare parent is emitted so the
		// engine still chases it, but the wildcard form is kept as the fact above.
		bare := strings.TrimPrefix(name, "*.")
		if !isHostname(bare) {
			continue
		}
		h := sink.Entity(graph.TypeHost, bare, bare)
		sink.Edge(ce, h, graph.RelSanOf, 1.0)
	}
}

// keyBits returns the certificate's public-key size in bits, or 0 for an algorithm
// without a meaningful size.
func keyBits(cert *x509.Certificate) int {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// weakSignature reports whether a certificate signature algorithm is one that is
// cryptographically broken (MD2/MD5/SHA-1 family), which is a reportable weakness.
func weakSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// issuerName prefers the issuer common name, falling back to its organization.
func issuerName(cert *x509.Certificate) string {
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	if len(cert.Issuer.Organization) > 0 {
		return cert.Issuer.Organization[0]
	}
	return ""
}
