package redact

import "regexp"

const sens = `(?:pass(?:word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential)`

var (
	privateKeyRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)`)

	// name=value where the name looks sensitive (--password=x, db_pass=x).
	sensAssign = regexp.MustCompile(`(?i)((?:--?)?[a-z0-9_.-]*` + sens + `[a-z0-9_.-]*)=("[^"]*"|'[^']*'|[^\s"']+)`)
	// Upper-case environment style assignment (FOO=bar). Case sensitive on purpose so that
	// ordinary flags such as --log-level=debug stay intact.
	upperAssign = regexp.MustCompile(`\b([A-Z][A-Z0-9_]*)=("[^"]*"|'[^']*'|[^\s"']+)`)
	// --password VALUE / -p style long flags followed by a separate value.
	flagRe = regexp.MustCompile(`(?i)(--?[a-z0-9_-]*` + sens + `[a-z0-9_-]*)(\s+)("[^"]*"|'[^']*'|[^\s"'-][^\s"']*)`)
	// scheme://user:pass@host
	urlCredRe = regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]*):[^\s@/]+@`)
	// Authorization: Bearer xxx / Basic xxx
	bearerRe = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`)
	// ENV/ARG instructions in image history: "ENV KEY value"
	envInstrRe = regexp.MustCompile(`\b(ENV|ARG)\s+([A-Za-z_][A-Za-z0-9_]*)(\s+|=)("[^"]*"|'[^']*'|[^\s"']+)`)

	flagOnlyRe = regexp.MustCompile(`(?i)^--?[a-z0-9_-]*` + sens + `[a-z0-9_-]*$`)
)

// flagWantsValue reports whether an argv element is a secret-bearing flag whose
// value is the next element (e.g. "--password").
func flagWantsValue(s string) bool { return flagOnlyRe.MatchString(s) }

// heuristic redacts probable secrets in a command line fragment. It is a
// best-effort filter, not a guarantee.
func heuristic(s string) string {
	if s == "" {
		return s
	}
	s = envInstrRe.ReplaceAllString(s, "${1} ${2}${3}"+Redacted)
	s = urlCredRe.ReplaceAllString(s, "${1}:"+Redacted+"@")
	s = bearerRe.ReplaceAllString(s, "$1 "+Redacted)
	s = flagRe.ReplaceAllString(s, "${1}${2}"+Redacted)
	s = sensAssign.ReplaceAllString(s, "${1}="+Redacted)
	s = upperAssign.ReplaceAllString(s, "${1}="+Redacted)
	return s
}
