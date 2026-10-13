package native

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/sources"
)

// RecordResolver is the subset of *net.Resolver the records source needs, so it can
// be tested with a fake instead of live name servers.
type RecordResolver interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// srvServices are the service/proto pairs probed for SRV records: the mail,
// collaboration and directory services an estate commonly advertises.
var srvServices = [][2]string{
	{"sip", "tcp"}, {"sips", "tcp"}, {"sip", "udp"},
	{"xmpp-client", "tcp"}, {"xmpp-server", "tcp"},
	{"ldap", "tcp"}, {"kerberos", "tcp"}, {"kerberos", "udp"},
	{"autodiscover", "tcp"}, {"caldav", "tcp"}, {"carddav", "tcp"},
	{"submission", "tcp"}, {"imaps", "tcp"},
}

// DNSRecords reads a domain's zone-level records: name servers, mail exchangers,
// TXT (SPF, DMARC, verification tokens) and CAA. It turns the records into graph
// facts and new entities — mail/name-server hosts the engine resolves, netblocks and
// IPs an SPF record authorizes, and the reporting addresses in a DMARC policy — so
// one domain seed unfolds into mail posture, delegation and authorized sender
// infrastructure. It is active: it queries live name servers (though not the target).
type DNSRecords struct {
	Resolver RecordResolver
}

// NewDNSRecords returns a records source using the system resolver.
func NewDNSRecords() *DNSRecords { return &DNSRecords{Resolver: net.DefaultResolver} }

// Capability marks the source active, consuming a domain and producing the hosts,
// netblocks, IPs and emails its records name.
func (r *DNSRecords) Capability() sources.Capability {
	return sources.Capability{
		Name:     "native/dns-records",
		Consumes: []graph.EntityType{graph.TypeDomain},
		Produces: []graph.EntityType{graph.TypeHost, graph.TypeNetblock, graph.TypeIP, graph.TypeEmail},
		Passive:  false,
		Cost:     1,
	}
}

// Available is always true; the system resolver is always present.
func (r *DNSRecords) Available(sources.Env) bool { return true }

// Collect reads the domain's records. Every lookup is best-effort: a domain with no
// MX or no DMARC record is ordinary, not a failure, so a missing record is skipped
// rather than returned as an error.
func (r *DNSRecords) Collect(ctx context.Context, in graph.Entity, sink sources.Sink) error {
	domain := in.Key
	self := sink.Entity(graph.TypeDomain, domain, domain)

	if ns, err := r.Resolver.LookupNS(ctx, domain); err == nil {
		for _, n := range ns {
			name := trimName(n.Host)
			if !isHostname(name) {
				continue
			}
			h := sink.Entity(graph.TypeHost, name, name)
			sink.Edge(h, self, graph.RelNsFor, 1.0)
			sink.Fact(self, "ns", name, 1.0)
		}
	}

	if mx, err := r.Resolver.LookupMX(ctx, domain); err == nil {
		for _, m := range mx {
			name := trimName(m.Host)
			if !isHostname(name) {
				continue
			}
			h := sink.Entity(graph.TypeHost, name, name)
			sink.Edge(h, self, graph.RelMxFor, 1.0)
			sink.Fact(self, "mx", name, 1.0)
			if v := saasVendor(name); v != "" {
				sink.Fact(self, "saas", v, 0.7)
			}
		}
	}

	hasSPF := false
	if txts, err := r.Resolver.LookupTXT(ctx, domain); err == nil {
		for _, rec := range txts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=spf1") {
				hasSPF = true
				sink.Fact(self, "spf", rec, 1.0)
				parseSPF(self, rec, sink)
				continue
			}
			// Verification tokens and other TXT records reveal SaaS adoption and domain
			// ownership proofs, so they are kept verbatim rather than dropped.
			sink.Fact(self, "txt", rec, 0.8)
		}
	}

	dmarcPolicy := r.collectDMARC(ctx, domain, self, sink)
	r.collectSRV(ctx, domain, self, sink)
	r.collectMailExtras(ctx, domain, self, sink)
	emitSpoofability(self, hasSPF, dmarcPolicy, sink)
	return nil
}

// collectMailExtras reads the remaining brand and mail-security records: BIMI (a brand
// logo and its verifying certificate), MTA-STS and TLS-RPT (SMTP transport security),
// and common DKIM selectors.
func (r *DNSRecords) collectMailExtras(ctx context.Context, domain string, self graph.Ref, sink sources.Sink) {
	if recs, err := r.Resolver.LookupTXT(ctx, "default._bimi."+domain); err == nil {
		for _, rec := range recs {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=bimi1") {
				sink.Fact(self, "bimi", rec, 0.8)
			}
		}
	}
	if recs, err := r.Resolver.LookupTXT(ctx, "_mta-sts."+domain); err == nil {
		for _, rec := range recs {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=stsv1") {
				sink.Fact(self, "mta_sts", "present", 0.8)
			}
		}
	}
	if recs, err := r.Resolver.LookupTXT(ctx, "_smtp._tls."+domain); err == nil {
		for _, rec := range recs {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=tlsrptv1") {
				sink.Fact(self, "tls_rpt", rec, 0.8)
			}
		}
	}
	for _, sel := range dkimSelectors {
		recs, err := r.Resolver.LookupTXT(ctx, sel+"._domainkey."+domain)
		if err != nil {
			continue
		}
		for _, rec := range recs {
			if strings.Contains(strings.ToLower(rec), "v=dkim1") || strings.Contains(strings.ToLower(rec), "p=") {
				sink.Fact(self, "dkim_selector", sel, 0.8)
				break
			}
		}
	}
}

// dkimSelectors are the selector names most mail providers publish a DKIM key under.
var dkimSelectors = []string{"default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "mandrill", "mxvault"}

// emitSpoofability records whether the domain can be spoofed in email, derived from the
// SPF and DMARC posture already collected: no DMARC (or p=none) with weak or absent SPF
// means a forged sender is likely to be delivered.
func emitSpoofability(self graph.Ref, hasSPF bool, dmarcPolicy string, sink sources.Sink) {
	p := strings.ToLower(strings.TrimSpace(dmarcPolicy))
	switch {
	case dmarcPolicy == "" && !hasSPF:
		sink.Fact(self, "finding", "medium email-spoofable-no-spf-dmarc", 0.8)
		sink.Fact(self, "exposure", "email_spoofable", 0.8)
	case dmarcPolicy == "" || p == "none":
		sink.Fact(self, "finding", "low email-spoofable-weak-dmarc", 0.7)
		sink.Fact(self, "exposure", "email_spoofable", 0.7)
	default:
		sink.Fact(self, "dmarc_enforced", p, 0.9)
	}
}

// collectSRV probes the common SRV services and records each advertised target as a
// host the engine then resolves.
func (r *DNSRecords) collectSRV(ctx context.Context, domain string, self graph.Ref, sink sources.Sink) {
	for _, s := range srvServices {
		_, addrs, err := r.Resolver.LookupSRV(ctx, s[0], s[1], domain)
		if err != nil {
			continue
		}
		for _, srv := range addrs {
			target := trimName(srv.Target)
			if target == "" || !isHostname(target) {
				continue
			}
			label := "_" + s[0] + "._" + s[1]
			sink.Fact(self, "srv", label+" "+target+":"+strconv.Itoa(int(srv.Port)), 0.9)
			sink.Entity(graph.TypeHost, target, target)
		}
	}
}

// collectDMARC reads the _dmarc record, records the policy and the addresses it sends
// aggregate and forensic reports to, and returns the policy (p=) for the spoofability
// verdict.
func (r *DNSRecords) collectDMARC(ctx context.Context, domain string, self graph.Ref, sink sources.Sink) string {
	recs, err := r.Resolver.LookupTXT(ctx, "_dmarc."+domain)
	if err != nil {
		return ""
	}
	policy := ""
	for _, rec := range recs {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(rec)), "v=dmarc1") {
			continue
		}
		for part := range strings.SplitSeq(rec, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok {
				continue
			}
			k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
			switch k {
			case "p":
				policy = v
				sink.Fact(self, "dmarc_policy", v, 1.0)
			case "sp":
				sink.Fact(self, "dmarc_subpolicy", v, 0.9)
			case "rua", "ruf":
				for u := range strings.SplitSeq(v, ",") {
					addr := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(u), "mailto:"))
					if emailRe.MatchString(addr) {
						sink.Entity(graph.TypeEmail, addr, addr)
						sink.Fact(self, "dmarc_email", addr, 0.8)
					}
				}
			}
		}
	}
	return policy
}

// parseSPF mines an SPF record for the sender infrastructure it authorizes: an ip4/
// ip6 CIDR becomes a netblock entity, a bare address an IP entity, and an include or
// redirect names another sender (often a known SaaS provider) kept as a fact.
func parseSPF(self graph.Ref, record string, sink sources.Sink) {
	for f := range strings.FieldsSeq(record) {
		// A mechanism may carry a qualifier (+ pass, - fail, ~ softfail, ? neutral);
		// the qualifier does not change what infrastructure the mechanism names.
		f = strings.TrimLeft(f, "+-~?")
		switch {
		case strings.HasPrefix(f, "ip4:"), strings.HasPrefix(f, "ip6:"):
			v := f[len("ip4:"):] // ip4: and ip6: are the same length
			if strings.Contains(v, "/") {
				sink.Entity(graph.TypeNetblock, v, v)
				sink.Fact(self, "spf_netblock", v, 0.9)
			} else {
				sink.Entity(graph.TypeIP, v, v)
				sink.Fact(self, "spf_ip", v, 0.9)
			}
		case strings.HasPrefix(f, "include:"):
			spfSender(self, f[len("include:"):], sink)
		case strings.HasPrefix(f, "redirect="):
			spfSender(self, f[len("redirect="):], sink)
		}
	}
}

// spfSender records an SPF include/redirect target and, when recognisable, the SaaS
// provider it belongs to.
func spfSender(self graph.Ref, host string, sink sources.Sink) {
	if host = strings.TrimSpace(host); host == "" {
		return
	}
	sink.Fact(self, "spf_include", host, 0.9)
	if v := saasVendor(host); v != "" {
		sink.Fact(self, "saas", v, 0.7)
	}
}

// saasVendor maps a mail/SPF host to the SaaS provider it belongs to, so a domain's
// third-party dependencies are visible without a separate source. An unknown host
// returns an empty string.
func saasVendor(host string) string {
	host = strings.ToLower(host)
	switch {
	case strings.Contains(host, "google.com"), strings.Contains(host, "googlemail"):
		return "Google Workspace"
	case strings.Contains(host, "protection.outlook.com"), strings.Contains(host, "outlook.com"):
		return "Microsoft 365"
	case strings.Contains(host, "sendgrid"):
		return "SendGrid"
	case strings.Contains(host, "mailgun"):
		return "Mailgun"
	case strings.Contains(host, "amazonses"), strings.Contains(host, "amazonaws"):
		return "Amazon SES"
	case strings.Contains(host, "mailchimp"), strings.Contains(host, "mandrill"):
		return "Mailchimp"
	case strings.Contains(host, "salesforce"):
		return "Salesforce"
	case strings.Contains(host, "zoho"):
		return "Zoho"
	case strings.Contains(host, "pardot"):
		return "Pardot"
	case strings.Contains(host, "hubspot"), strings.Contains(host, "hubspotemail"):
		return "HubSpot"
	case strings.Contains(host, "zendesk"):
		return "Zendesk"
	case strings.Contains(host, "freshdesk"), strings.Contains(host, "freshemail"):
		return "Freshdesk"
	case strings.Contains(host, "mimecast"):
		return "Mimecast"
	case strings.Contains(host, "proofpoint"), strings.Contains(host, "pphosted"):
		return "Proofpoint"
	default:
		return ""
	}
}

// trimName lowercases a DNS name and drops the trailing root dot.
func trimName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
