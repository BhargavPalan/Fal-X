package pdtools

import (
	"context"
	"strings"
	"testing"

	"github.com/BhargavPalan/Fal-X/internal/graph"
)

// fakeRunner returns canned output and records how it was called.
type fakeRunner struct {
	out      []byte
	gotName  string
	gotArgs  []string
	gotStdin []byte
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	f.gotName, f.gotArgs, f.gotStdin = name, args, stdin
	return f.out, nil
}

// recSink records emissions for assertion.
type recSink struct {
	entities []struct {
		t   graph.EntityType
		key string
	}
	facts []struct{ key, value string }
	edges []graph.EdgeType
}

func (s *recSink) Entity(t graph.EntityType, key, _ string) graph.Ref {
	s.entities = append(s.entities, struct {
		t   graph.EntityType
		key string
	}{t, key})
	return graph.Ref(len(s.entities))
}
func (s *recSink) Fact(_ graph.Ref, key, value string, _ float64) {
	s.facts = append(s.facts, struct{ key, value string }{key, value})
}
func (s *recSink) Edge(_, _ graph.Ref, rel graph.EdgeType, _ float64) { s.edges = append(s.edges, rel) }

func (s *recSink) hasEntity(t graph.EntityType, key string) bool {
	for _, e := range s.entities {
		if e.t == t && e.key == key {
			return true
		}
	}
	return false
}
func (s *recSink) hasFact(key, value string) bool {
	for _, f := range s.facts {
		if f.key == key && f.value == value {
			return true
		}
	}
	return false
}

func argvHas(args []string, want ...string) bool {
	joined := " " + strings.Join(args, " ") + " "
	for _, w := range want {
		if !strings.Contains(joined, " "+w+" ") {
			return false
		}
	}
	return true
}

func TestSubfinderParsesAndScopes(t *testing.T) {
	r := &fakeRunner{out: []byte("api.example.com\nwww.example.com\nunrelated.test\n")}
	s := &Subfinder{Runner: r}
	rec := &recSink{}
	if err := s.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, rec); err != nil {
		t.Fatal(err)
	}
	if !argvHas(r.gotArgs, "-d", "example.com") {
		t.Errorf("argv = %v", r.gotArgs)
	}
	if !rec.hasEntity(graph.TypeHost, "api.example.com") || !rec.hasEntity(graph.TypeHost, "www.example.com") {
		t.Errorf("expected in-scope subdomains, entities=%+v", rec.entities)
	}
	if rec.hasEntity(graph.TypeHost, "unrelated.test") {
		t.Errorf("an out-of-domain name must be dropped, entities=%+v", rec.entities)
	}
}

func TestHTTPXParsesProbe(t *testing.T) {
	r := &fakeRunner{out: []byte(`{"url":"https://example.com","status_code":200,"title":"Home","webserver":"nginx","tech":["PHP","nginx"]}` + "\n")}
	h := &HTTPX{Runner: r}
	rec := &recSink{}
	if err := h.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "example.com"}, rec); err != nil {
		t.Fatal(err)
	}
	if string(r.gotStdin) != "example.com\n" {
		t.Errorf("stdin = %q", r.gotStdin)
	}
	if !rec.hasEntity(graph.TypeURL, "https://example.com") || !rec.hasFact("server", "nginx") ||
		!rec.hasFact("tech", "PHP") || !rec.hasFact("status", "200") {
		t.Errorf("httpx parse incomplete: entities=%+v facts=%+v", rec.entities, rec.facts)
	}
}

func TestNaabuParsesPorts(t *testing.T) {
	r := &fakeRunner{out: []byte(`{"ip":"192.0.2.1","port":22}` + "\n" + `{"ip":"192.0.2.1","port":443}` + "\n")}
	n := &Naabu{Runner: r}
	rec := &recSink{}
	if err := n.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "192.0.2.1"}, rec); err != nil {
		t.Fatal(err)
	}
	if !rec.hasEntity(graph.TypeService, "192.0.2.1:22") || !rec.hasEntity(graph.TypeService, "192.0.2.1:443") {
		t.Errorf("expected services, entities=%+v", rec.entities)
	}
}

func TestNucleiParsesFindings(t *testing.T) {
	r := &fakeRunner{out: []byte(`{"template-id":"CVE-2021-41773","matched-at":"https://x","info":{"name":"Apache Path Traversal","severity":"high"}}` + "\n")}
	n := &Nuclei{Runner: r}
	rec := &recSink{}
	if err := n.Collect(context.Background(), graph.Entity{Type: graph.TypeURL, Key: "https://x"}, rec); err != nil {
		t.Fatal(err)
	}
	if !rec.hasFact("finding", "high CVE-2021-41773 Apache Path Traversal") {
		t.Errorf("expected nuclei finding, facts=%+v", rec.facts)
	}
}

func TestFingerprintxParsesProtocol(t *testing.T) {
	r := &fakeRunner{out: []byte(`{"protocol":"ssh","version":"OpenSSH_8.9"}` + "\n")}
	f := &Fingerprintx{Runner: r}
	rec := &recSink{}
	if err := f.Collect(context.Background(), graph.Entity{Type: graph.TypeService, Key: "192.0.2.1:22"}, rec); err != nil {
		t.Fatal(err)
	}
	if string(r.gotStdin) != "192.0.2.1:22\n" {
		t.Errorf("stdin = %q", r.gotStdin)
	}
	if !rec.hasFact("service", "ssh") || !rec.hasFact("tech", "ssh OpenSSH_8.9") {
		t.Errorf("fingerprintx parse incomplete: facts=%+v", rec.facts)
	}
}

func TestMasscanParsesListOutput(t *testing.T) {
	r := &fakeRunner{out: []byte("#masscan\nopen tcp 80 192.0.2.1 1620000000\nopen tcp 443 192.0.2.1 1620000000\n# end\n")}
	m := &Masscan{Runner: r}
	rec := &recSink{}
	if err := m.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "192.0.2.1"}, rec); err != nil {
		t.Fatal(err)
	}
	if !rec.hasEntity(graph.TypeService, "192.0.2.1:80") || !rec.hasEntity(graph.TypeService, "192.0.2.1:443") {
		t.Errorf("expected services, entities=%+v", rec.entities)
	}
}

func TestTrufflehogParsesSecrets(t *testing.T) {
	out := `{"DetectorName":"AWS","Verified":true,"SourceMetadata":{"Data":{"Git":{"file":"config.yml"}}}}` + "\n" +
		`{"DetectorName":"Slack","Verified":false,"SourceMetadata":{"Data":{"Git":{"file":"app.js"}}}}` + "\n"
	r := &fakeRunner{out: []byte(out)}
	th := &Trufflehog{Runner: r}
	rec := &recSink{}
	if err := th.Collect(context.Background(), graph.Entity{Type: graph.TypeRepository, Key: "github.com/acme/web"}, rec); err != nil {
		t.Fatal(err)
	}
	if !argvHas(r.gotArgs, "git", "https://github.com/acme/web") {
		t.Errorf("argv = %v", r.gotArgs)
	}
	if !rec.hasFact("finding", "high verified-secret AWS") || !rec.hasFact("finding", "medium unverified-secret Slack") {
		t.Errorf("trufflehog findings incomplete: facts=%+v", rec.facts)
	}
}

func TestGauParsesURLs(t *testing.T) {
	r := &fakeRunner{out: []byte("https://www.example.com/a\nhttps://api.example.com/b\nhttps://evil.test/c\n")}
	g := &Gau{Runner: r}
	rec := &recSink{}
	if err := g.Collect(context.Background(), graph.Entity{Type: graph.TypeDomain, Key: "example.com"}, rec); err != nil {
		t.Fatal(err)
	}
	if !rec.hasEntity(graph.TypeURL, "https://www.example.com/a") || !rec.hasEntity(graph.TypeHost, "api.example.com") {
		t.Errorf("gau parse incomplete: entities=%+v", rec.entities)
	}
	if rec.hasEntity(graph.TypeHost, "evil.test") {
		t.Errorf("out-of-domain host must not be emitted: %+v", rec.entities)
	}
}

func TestDNSxParsesResolution(t *testing.T) {
	r := &fakeRunner{out: []byte(`{"host":"www.example.com","a":["192.0.2.1"],"cname":["cdn.example.net"]}` + "\n")}
	d := &DNSx{Runner: r}
	rec := &recSink{}
	if err := d.Collect(context.Background(), graph.Entity{Type: graph.TypeHost, Key: "www.example.com"}, rec); err != nil {
		t.Fatal(err)
	}
	if !rec.hasEntity(graph.TypeIP, "192.0.2.1") || !rec.hasFact("cname", "cdn.example.net") {
		t.Errorf("dnsx parse incomplete: entities=%+v facts=%+v", rec.entities, rec.facts)
	}
}

func TestKatanaParsesURLsAndEndpoints(t *testing.T) {
	r := &fakeRunner{out: []byte("https://example.com/\nhttps://example.com/admin/login\n")}
	k := &Katana{Runner: r}
	rec := &recSink{}
	if err := k.Collect(context.Background(), graph.Entity{Type: graph.TypeURL, Key: "https://example.com"}, rec); err != nil {
		t.Fatal(err)
	}
	if !rec.hasEntity(graph.TypeURL, "https://example.com/admin/login") || !rec.hasEntity(graph.TypeEndpoint, "/admin/login") {
		t.Errorf("katana parse incomplete: entities=%+v", rec.entities)
	}
}

func TestNmapParsesServiceVersion(t *testing.T) {
	const xmlOut = `<?xml version="1.0"?><nmaprun><host><ports>
		<port protocol="tcp" portid="22"><state state="open"/>
		<service name="ssh" product="OpenSSH" version="6.6.1p1" ostype="Linux"/></port>
		<port protocol="tcp" portid="81"><state state="closed"/><service name="hosts2-ns"/></port>
		</ports></host></nmaprun>`
	r := &fakeRunner{out: []byte(xmlOut)}
	n := &Nmap{Runner: r}
	rec := &recSink{}
	if err := n.Collect(context.Background(), graph.Entity{Type: graph.TypeIP, Key: "192.0.2.1"}, rec); err != nil {
		t.Fatal(err)
	}
	if !argvHas(r.gotArgs, "-sV") {
		t.Errorf("argv = %v", r.gotArgs)
	}
	if !rec.hasEntity(graph.TypeService, "192.0.2.1:22") || !rec.hasFact("tech", "OpenSSH 6.6.1p1") {
		t.Errorf("expected ssh service+version, entities=%+v facts=%+v", rec.entities, rec.facts)
	}
	// A closed port is not emitted.
	if rec.hasEntity(graph.TypeService, "192.0.2.1:81") {
		t.Errorf("a closed port must not become a service, entities=%+v", rec.entities)
	}
}
