package intel

import (
	"errors"
	"strings"
)

// CPEMatch is one CPE entry of an NVD configuration, with its place in the tree.
type CPEMatch struct {
	ConfigSeq, NodeSeq, MatchSeq int
	ConfigOperator, NodeOperator string
	Negate                       bool
	Vulnerable                   bool

	// Criteria is the CPE name; Part, Vendor, Product and Version are read from it.
	// A wildcard is "*" and "not applicable" is "-", as the name has them.
	Criteria                       string
	Part, Vendor, Product, Version string

	StartIncluding, StartExcluding string
	EndIncluding, EndExcluding     string
	MatchID                        string
}

// ParseCPE reads the part, vendor, product and version of a CPE 2.3 name. A colon
// separates components unless it is escaped with a backslash, and the escape is
// removed from what is returned.
func ParseCPE(name string) (part, vendor, product, version string, err error) {
	if !strings.HasPrefix(name, "cpe:2.3:") {
		return "", "", "", "", errors.New("intel: not a CPE 2.3 name")
	}
	fields := splitCPE(name[len("cpe:2.3:"):])
	if len(fields) != 11 {
		return "", "", "", "", errors.New("intel: a CPE 2.3 name has eleven components")
	}
	return fields[0], fields[1], fields[2], fields[3], nil
}

func splitCPE(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case s[i] == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, cur.String())
}
