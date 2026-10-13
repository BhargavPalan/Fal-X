package match

import (
	"regexp"
	"strings"
)

// Software is one thing an asset was observed running.
type Software struct {
	// Name is as observed ("Apache HTTP Server", "nginx"); Version may be empty.
	Name    string
	Version string
	// Evidence is the attribute value it was read from.
	Evidence string
	// Distro names an operating system the server banner mentions, such as Ubuntu.
	// Distributions patch software without changing its version number, so a match
	// on a banner from one is weaker than it looks.
	Distro string
}

var (
	versionLike = regexp.MustCompile(`^[0-9][0-9A-Za-z._+~-]*$`)
	distroWord  = regexp.MustCompile(`(?i)ubuntu|debian|centos|red hat|rhel|fedora|suse|alpine|amazon|rocky|alma|oracle linux`)
)

// Observations reads the software named by one attribute. key is "tech", for a
// detected technology written "Name:version" or just "Name", or "server", for a
// Server header such as "Apache/2.4.7 (Ubuntu)".
func Observations(key, value string) []Software {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	switch key {
	case "tech":
		name, version, _ := strings.Cut(value, ":")
		return []Software{{Name: strings.TrimSpace(name), Version: cleanVersion(version), Evidence: value}}
	case "server":
		return fromServerHeader(value)
	case "service":
		return fromNmap(value)
	}
	return nil
}

// fromNmap reads "<service> <product> <version> <notes>" as the asset import stores
// nmap's version column, such as "ssh OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu
// Linux; protocol 2.0)". The product is the words before the first one that looks
// like a version. A port nmap could not identify has nothing after the service name
// and yields nothing.
func fromNmap(value string) []Software {
	_, detail, _ := strings.Cut(value, " ")
	distro := ""
	words := strings.Fields(stripComments(detail, &distro))
	var name []string
	for i, w := range words {
		if versionLike.MatchString(w) && strings.Contains(w, ".") {
			return []Software{{Name: strings.Join(name, " "), Version: w, Evidence: value, Distro: distro}}
		}
		name = words[:i+1]
	}
	if len(name) == 0 {
		return nil
	}
	return []Software{{Name: strings.Join(name, " "), Evidence: value, Distro: distro}}
}

// fromServerHeader reads "product/version product/version (comment)" tokens.
func fromServerHeader(header string) []Software {
	distro := ""
	var out []Software
	for field := range strings.FieldsSeq(stripComments(header, &distro)) {
		name, version, _ := strings.Cut(field, "/")
		if name == "" {
			continue
		}
		out = append(out, Software{Name: name, Version: cleanVersion(version), Evidence: header, Distro: distro})
	}
	return out
}

// stripComments removes parenthesised comments from a header, noting a
// distribution name found inside one.
func stripComments(s string, distro *string) string {
	var b strings.Builder
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			if depth == 0 {
				start = i + 1
			}
			depth++
		case ')':
			if depth > 0 {
				depth--
				if depth == 0 && *distro == "" {
					*distro = distroWord.FindString(s[start:i])
				}
			}
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return b.String()
}

// cleanVersion returns v when it looks like a version and "" otherwise, so a word
// such as "Browser" or "3" is not mistaken for one.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if !versionLike.MatchString(v) || (!strings.Contains(v, ".") && len(v) < 2) {
		return ""
	}
	return v
}

// Product is a CPE vendor and product.
type Product struct {
	Vendor, Product string
}

// known maps the names scanners report onto the CPE vendor and product NVD uses.
// Only names that are unambiguous are listed; anything else is looked up against
// the CVE data by name and reported as unverified.
var known = map[string]Product{
	"apache http server":  {"apache", "http_server"},
	"apache":              {"apache", "http_server"},
	"apache httpd":        {"apache", "http_server"},
	"microsoft iis httpd": {"microsoft", "internet_information_services"},
	"exim smtpd":          {"exim", "exim"},
	"postfix smtpd":       {"postfix", "postfix"},
	"dovecot imapd":       {"dovecot", "dovecot"},
	"dovecot pop3d":       {"dovecot", "dovecot"},
	"apache tomcat":       {"apache", "tomcat"},
	"tomcat":              {"apache", "tomcat"},
	"nginx":               {"nginx", "nginx"},
	"openssh":             {"openbsd", "openssh"},
	"microsoft iis":       {"microsoft", "internet_information_services"},
	"iis":                 {"microsoft", "internet_information_services"},
	"php":                 {"php", "php"},
	"wordpress":           {"wordpress", "wordpress"},
	"drupal":              {"drupal", "drupal"},
	"joomla":              {"joomla", "joomla!"},
	"jquery":              {"jquery", "jquery"},
	"jquery ui":           {"jqueryui", "jquery_ui"},
	"openssl":             {"openssl", "openssl"},
	"lighttpd":            {"lighttpd", "lighttpd"},
	"haproxy":             {"haproxy", "haproxy"},
	"mysql":               {"oracle", "mysql"},
	"mariadb":             {"mariadb", "mariadb"},
	"postgresql":          {"postgresql", "postgresql"},
	"redis":               {"redis", "redis"},
	"elasticsearch":       {"elastic", "elasticsearch"},
	"grafana":             {"grafana", "grafana"},
	"gitlab":              {"gitlab", "gitlab"},
	"jenkins":             {"jenkins", "jenkins"},
	"node.js":             {"nodejs", "node.js"},
	"nodejs":              {"nodejs", "node.js"},
	"proftpd":             {"proftpd", "proftpd"},
	"exim":                {"exim", "exim"},
	"postfix":             {"postfix", "postfix"},
	"dovecot":             {"dovecot", "dovecot"},
	"samba":               {"samba", "samba"},
}

// normalise lower-cases a name and turns separators into single spaces.
func normalise(name string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == ' ' || r == '-' || r == '_'
	}), " ")
}

// Resolve returns the CPE product for a name, if the name is one the matcher knows.
func Resolve(name string) (Product, bool) {
	p, ok := known[normalise(name)]
	return p, ok
}

// guess is how an unknown name is turned into a CPE product name.
func guess(name string) string {
	return strings.ReplaceAll(normalise(name), " ", "_")
}
