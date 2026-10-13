package people

import "strings"

// roleLocals are mailbox local-parts that name a function, not a person: shared
// inboxes, automated senders, and the RFC 2142 role addresses. A person is never
// derived from one, so "security@" does not become a contact named "Security".
var roleLocals = map[string]bool{
	"info": true, "contact": true, "hello": true, "hi": true, "team": true,
	"office": true, "help": true, "support": true, "sales": true, "enquiries": true,
	"enquiry": true, "inquiries": true, "inquiry": true, "orders": true, "feedback": true,
	"admin": true, "administrator": true, "root": true, "sysadmin": true, "webadmin": true,
	"postmaster": true, "hostmaster": true, "webmaster": true, "abuse": true,
	"security": true, "privacy": true, "legal": true, "compliance": true,
	"billing": true, "accounts": true, "accounting": true, "finance": true,
	"hr": true, "jobs": true, "careers": true, "recruiting": true, "recruitment": true,
	"press": true, "media": true, "marketing": true, "newsletter": true, "news": true,
	"notifications": true, "notification": true, "notify": true, "alerts": true, "alert": true,
	"noreply": true, "no-reply": true, "no_reply": true, "donotreply": true,
	"do-not-reply": true, "do_not_reply": true, "mailer-daemon": true, "bounce": true,
	"bounces": true, "mail": true, "email": true, "service": true, "services": true,
	"dev": true, "devops": true, "it": true, "noc": true, "api": true, "test": true,
	"example": true, "user": true, "username": true, "name": true,
}

// splitEmail separates an address into its lowercased local-part (with any "+tag"
// suffix removed) and domain. It reports ok only for a well-formed address.
func splitEmail(addr string) (local, domain string, ok bool) {
	a := strings.ToLower(strings.TrimSpace(addr))
	at := strings.LastIndexByte(a, '@')
	if at <= 0 || at == len(a)-1 {
		return "", "", false
	}
	local, domain = a[:at], a[at+1:]
	if i := strings.IndexByte(local, '+'); i >= 0 { // drop plus-addressing: jane+news -> jane
		local = local[:i]
	}
	if local == "" || !strings.Contains(domain, ".") {
		return "", "", false
	}
	return local, domain, true
}

// classifyLocal labels a local-part as "role" (a function address), "personal" (a
// human-shaped mailbox, whether or not a full name can be read from it), or "other"
// (an opaque id: anything carrying a digit or other non-name character). Classifying
// is deliberately more permissive than naming: "jane" and "jdoe" are both personal
// mailboxes, but only an unambiguous "first.last" yields an actual contact name.
func classifyLocal(local string) string {
	if local == "" {
		return "other"
	}
	if isRoleLocal(local) {
		return "role"
	}
	if nameShaped(local) {
		return "personal"
	}
	return "other"
}

// roleCompoundTokens are tokens that mark a shared or automated inbox when they appear
// inside a separated local-part ("no.reply", "mailer.daemon", "help.desk", "sales.team"),
// complementing roleLocals, which matches a whole local-part.
var roleCompoundTokens = map[string]bool{
	"reply": true, "team": true, "desk": true, "daemon": true, "mailer": true,
	"no": true, "do": true, "not": true, "noreply": true,
}

// isRoleToken reports whether a single token signals a role address.
func isRoleToken(t string) bool { return roleLocals[t] || roleCompoundTokens[t] }

// isRoleLocal reports whether a local-part names a function rather than a person: the
// whole local-part is a role word, or every separated token is a role token (so
// "it.support" and "no.reply" are roles, but "jane.doe" is not).
func isRoleLocal(local string) bool {
	if roleLocals[local] {
		return true
	}
	toks := strings.FieldsFunc(local, func(r rune) bool { return r == '.' || r == '_' || r == '-' })
	if len(toks) < 2 {
		return false
	}
	for _, t := range toks {
		if !isRoleToken(t) {
			return false
		}
	}
	return true
}

// nameShaped reports whether a local-part is built only of letters and the name
// separators ".", "_" and "-", with at least one letter. A digit or any other
// character marks it an opaque identifier rather than a person's mailbox.
func nameShaped(local string) bool {
	hasLetter := false
	for i := 0; i < len(local); i++ {
		c := local[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			hasLetter = true
		case c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return hasLetter
}

// personFromLocal derives a display name and the naming format from a mailbox
// local-part, when the local-part looks like a human name. It is deliberately
// conservative: it recognises "first<sep>last" and a bare "first", and declines
// anything it cannot split confidently (an initials blob like "jdoe", a role word, a
// token with digits), because a wrong guess invents a person that is not there.
//
// The format is returned with "{first}", "{last}" placeholders and the separator the
// address actually used, so the same tally that names the person also reveals the
// domain's address convention.
func personFromLocal(local string) (display, format string, ok bool) {
	if local == "" || roleLocals[local] {
		return "", "", false
	}
	sep := ""
	for _, s := range []string{".", "_", "-"} {
		if strings.Contains(local, s) {
			sep = s
			break
		}
	}
	if sep == "" {
		// A single token is not a confident full name: "jane" could be a first name, but
		// "jdoe" is an initial and a surname, and the two cannot be told apart. So no
		// contact is named from a single token (it is still classified a personal mailbox).
		return "", "", false
	}
	tokens := strings.Split(local, sep)
	if len(tokens) != 2 {
		return "", "", false // three-plus parts are ambiguous; do not guess
	}
	first, last := tokens[0], tokens[1]
	if !isAlpha(first) || !isAlpha(last) || len(first) < 2 || len(last) < 2 {
		return "", "", false
	}
	if isRoleToken(first) || isRoleToken(last) {
		return "", "", false // a compound role/shared inbox (it.support, no.reply), not a person
	}
	return titleCase(first) + " " + titleCase(last), "{first}" + sep + "{last}", true
}

// isAlpha reports whether s is non-empty and only ASCII letters.
func isAlpha(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 'a' || c > 'z' {
			if c < 'A' || c > 'Z' {
				return false
			}
		}
	}
	return true
}

// titleCase upper-cases the first letter of an ASCII token and lower-cases the rest.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	b := []byte(strings.ToLower(s))
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 'a' - 'A'
	}
	return string(b)
}
