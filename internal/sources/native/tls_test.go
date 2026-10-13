package native

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

// makeCert builds a self-signed certificate with the given CN and SANs, for testing
// the mining logic without a live TLS server.
func makeCert(t *testing.T, cn string, sans []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "Test Issuer CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestTLSEmitMinesSANsAndCert(t *testing.T) {
	cert := makeCert(t, "www.example.com", []string{"www.example.com", "*.example.com", "api.example.com"})
	p := NewTLSCert()
	s := &recSink{}
	p.emit("www.example.com", cert, s)

	// The wildcard SAN folds to example.com; all three SAN hosts must appear.
	for _, want := range []string{"www.example.com", "example.com", "api.example.com"} {
		if !s.hasEntity(graph.TypeHost, want) {
			t.Errorf("expected SAN host %s, got %+v", want, s.entities)
		}
	}
	certs := 0
	for _, e := range s.entities {
		if e.t == graph.TypeCertificate {
			certs++
		}
	}
	if certs != 1 {
		t.Errorf("expected exactly one certificate entity, got %d", certs)
	}

	var presents, san int
	for _, r := range s.edges {
		switch r {
		case graph.RelPresentsCert:
			presents++
		case graph.RelSanOf:
			san++
		}
	}
	if presents != 1 {
		t.Errorf("presents_cert edges = %d, want 1", presents)
	}
	if san != 3 {
		t.Errorf("san_of edges = %d, want 3", san)
	}

	var fp, cn bool
	for _, f := range s.facts {
		if f.key == "tls_sha256" && len(f.value) == 64 {
			fp = true
		}
		if f.key == "subject_cn" && f.value == "www.example.com" {
			cn = true
		}
	}
	if !fp {
		t.Errorf("expected a tls_sha256 fact (64 hex chars), got %+v", s.facts)
	}
	if !cn {
		t.Errorf("expected subject_cn fact, got %+v", s.facts)
	}
}
