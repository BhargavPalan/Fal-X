package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// switchFlags reads options.go and returns the flags the argument switch handles
// as bare switches, that is the cases whose whole body is one assignment of true
// to a field.
//
// It parses the source rather than hard-coding a list, so a flag added to the
// switch is picked up here without this test being edited alongside it.
func switchFlags(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "options.go", nil, 0)
	if err != nil {
		t.Fatalf("parse options.go: %v", err)
	}

	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		// Parse dispatches on the bare flag name: `switch arg {`.
		tag, ok := sw.Tag.(*ast.Ident)
		if !ok || tag.Name != "arg" {
			return true
		}
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok {
				continue
			}
			if len(cc.Body) != 1 {
				continue // not a bare switch
			}
			assign, ok := cc.Body[0].(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 {
				continue
			}
			sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
			if !ok || sel.Sel.Name == "" {
				continue
			}
			lit, ok := assign.Rhs[0].(*ast.Ident)
			if !ok || lit.Name != "true" {
				continue
			}
			for _, e := range cc.List {
				if lit, ok := e.(*ast.BasicLit); ok {
					found = append(found, strings.Trim(lit.Value, `"`))
				}
			}
		}
		return true
	})
	sort.Strings(found)
	return found
}

// boolFlags and the switch in Parse are two lists of the same thing: which flags
// take no value. They are kept apart today, and nothing forced them to agree.
//
// If a switch is added to Parse and not to boolFlags, then --switch=false is
// silently reduced to --switch, which is the one outcome the flag exists to
// prevent: --dry-run=false would run a scan the operator asked to skip. This
// pins the two lists together.
func TestBoolFlagsMatchTheSwitchesInParse(t *testing.T) {
	inSwitch := switchFlags(t)
	if len(inSwitch) == 0 {
		t.Fatal("no switches found in Parse; the source shape this test reads has changed")
	}

	inMap := make([]string, 0, len(boolFlags))
	for f := range boolFlags {
		inMap = append(inMap, f)
	}
	sort.Strings(inMap)

	var missingFromMap, missingFromSwitch []string
	for _, f := range inSwitch {
		if !boolFlags[f] {
			missingFromMap = append(missingFromMap, f)
		}
	}
	for f := range boolFlags {
		if !contains(inSwitch, f) {
			missingFromSwitch = append(missingFromSwitch, f)
		}
	}

	if len(missingFromMap) > 0 {
		t.Errorf("switches handled by Parse but absent from boolFlags: %v\n"+
			"add them there, or --%s=false will be accepted as --%s",
			missingFromMap, strings.TrimLeft(missingFromMap[0], "-"),
			strings.TrimLeft(missingFromMap[0], "-"))
	}
	if len(missingFromSwitch) > 0 {
		t.Errorf("boolFlags lists %v, which Parse does not handle as a switch", missingFromSwitch)
	}
	if len(inSwitch) != len(inMap) {
		t.Errorf("boolFlags has %d entries, the switch has %d", len(inMap), len(inSwitch))
	}
}

// The behaviour the list exists to protect, checked directly rather than through
// the list: every switch must refuse an attached value.
func TestSwitchesRefuseAnAttachedValue(t *testing.T) {
	for _, f := range switchFlags(t) {
		for _, spelling := range []string{f + "=false", f + "=true", f + "=1"} {
			if _, err := Parse(spelling); err == nil {
				t.Errorf("Parse(%q) was accepted; a switch must refuse an attached value, "+
					"or --%s=false runs the scan the operator asked to skip",
					spelling, strings.TrimLeft(f, "-"))
			}
		}
	}
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
