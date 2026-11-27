// Package redact removes environment values and secrets from Docker API JSON.
//
// It walks the JSON token stream (encoding/json/jsontext) so that every value
// it does not touch keeps its exact text: numbers are never converted to
// float64 and key order is preserved.
package redact

import (
	"bytes"
	"encoding/json/jsontext"
	"errors"
	"io"
	"regexp"
	"strings"
)

// Redacted is the replacement for removed values.
const Redacted = "REDACTED"

// Options tunes optional behaviour.
type Options struct {
	RedactLabels    bool             // redact every label value
	RedactLabelKeys []*regexp.Regexp // redact label values whose key matches
	Patterns        []*regexp.Regexp // extra regexes; matches in any string become REDACTED
}

// Redactor is safe for concurrent use.
type Redactor struct{ opt Options }

// New creates a Redactor.
func New(o Options) *Redactor { return &Redactor{opt: o} }

var (
	sensitiveKey = regexp.MustCompile(`(?i)passw(or)?d|passwd|secret|token|api[_-]?key|private[_-]?key|credential|^auths?$|^auth[_-]?config$|signingca|unlockkey|trustroot|^x-registry`)
	// Keys that merely reference secrets by name/ID; the value is not sensitive.
	referenceKey = regexp.MustCompile(`(?i)^(secrets|secret_?names?|secret_?ids?)$`)

	envKeys  = map[string]bool{"env": true, "envs": true, "environment": true}
	heurKeys = map[string]bool{"cmd": true, "entrypoint": true, "args": true, "command": true,
		"createdby": true, "test": true, "shell": true, "arguments": true, "action": true}
	labelKeys = map[string]bool{"labels": true, "attributes": true}
)

type ctx struct {
	all    bool // every string below is replaced
	env    bool // strings are KEY=VALUE
	heur   bool // apply command-line heuristics
	labels bool // object is a label map
	inSpec bool // below a "Spec" key
}

// Bytes redacts one or more concatenated JSON values and returns them
// newline-terminated. It fails on any syntax error.
func (r *Redactor) Bytes(in []byte) ([]byte, error) {
	var out bytes.Buffer
	err := r.Stream(bytes.NewReader(in), writerFunc(func(b []byte) error { out.Write(b); return nil }))
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type writerFunc func([]byte) error

func (f writerFunc) Write(b []byte) (int, error) {
	if err := f(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Stream reads concatenated/NDJSON values from src and writes each redacted
// value, newline-terminated, with a single Write call as soon as it is complete.
func (r *Redactor) Stream(src io.Reader, dst io.Writer) error {
	dec := jsontext.NewDecoder(src, jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
	for {
		if dec.PeekKind() == 0 {
			if _, err := dec.ReadToken(); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
		}
		var buf bytes.Buffer
		enc := jsontext.NewEncoder(&buf, jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true), jsontext.PreserveRawStrings(true))
		w := &walker{r: r, dec: dec, enc: enc}
		if err := w.value(ctx{}); err != nil {
			return err
		}
		if _, err := dst.Write(buf.Bytes()); err != nil {
			return err
		}
	}
}

type walker struct {
	r   *Redactor
	dec *jsontext.Decoder
	enc *jsontext.Encoder
}

func (w *walker) value(c ctx) error {
	switch w.dec.PeekKind() {
	case '{':
		return w.object(c)
	case '[':
		return w.array(c)
	case 0:
		_, err := w.dec.ReadToken()
		return err
	}
	tok, err := w.dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() == '"' {
		s := tok.String()
		if ns, changed := w.r.str(c, s); changed {
			return w.enc.WriteToken(jsontext.String(ns))
		}
	}
	return w.enc.WriteToken(tok)
}

func (w *walker) object(c ctx) error {
	t, err := w.dec.ReadToken()
	if err != nil {
		return err
	}
	if err := w.enc.WriteToken(t); err != nil {
		return err
	}
	for w.dec.PeekKind() != '}' {
		k, err := w.dec.ReadToken()
		if err != nil {
			return err
		}
		if err := w.enc.WriteToken(k); err != nil {
			return err
		}
		if err := w.value(w.r.child(c, k.String())); err != nil {
			return err
		}
	}
	t, err = w.dec.ReadToken()
	if err != nil {
		return err
	}
	return w.enc.WriteToken(t)
}

func (w *walker) array(c ctx) error {
	t, err := w.dec.ReadToken()
	if err != nil {
		return err
	}
	if err := w.enc.WriteToken(t); err != nil {
		return err
	}
	redactNext := false // previous element was a secret-bearing flag
	for w.dec.PeekKind() != ']' {
		if c.heur && w.dec.PeekKind() == '"' {
			tok, err := w.dec.ReadToken()
			if err != nil {
				return err
			}
			s := tok.String()
			ns, changed := s, false
			if redactNext {
				ns, changed = Redacted, true
				redactNext = false
			} else {
				ns, changed = w.r.str(c, s)
				if !changed && flagWantsValue(s) {
					redactNext = true
				}
			}
			if changed {
				err = w.enc.WriteToken(jsontext.String(ns))
			} else {
				err = w.enc.WriteToken(tok)
			}
			if err != nil {
				return err
			}
			continue
		}
		if err := w.value(c); err != nil {
			return err
		}
	}
	t, err = w.dec.ReadToken()
	if err != nil {
		return err
	}
	return w.enc.WriteToken(t)
}

// child derives the context for the value stored under key.
func (r *Redactor) child(c ctx, key string) ctx {
	lk := strings.ToLower(key)
	if c.labels {
		// Label keys are arbitrary user data: never apply key heuristics.
		n := ctx{all: c.all}
		if r.opt.RedactLabels {
			n.all = true
		}
		for _, re := range r.opt.RedactLabelKeys {
			if re.MatchString(key) {
				n.all = true
			}
		}
		return n
	}
	n := ctx{all: c.all, inSpec: c.inSpec || lk == "spec"}
	switch {
	case envKeys[lk]:
		n.env = true
	case heurKeys[lk]:
		n.heur = true
	case labelKeys[lk]:
		n.labels = true
	}
	if sensitiveKey.MatchString(key) && !referenceKey.MatchString(key) {
		n.all = true
	}
	if lk == "data" && c.inSpec { // swarm config/secret payload
		n.all = true
	}
	return n
}

// str applies the context rules to a string value.
func (r *Redactor) str(c ctx, s string) (string, bool) {
	if c.all {
		if s == "" {
			return s, false
		}
		return Redacted, s != Redacted
	}
	orig := s
	if c.env {
		if i := strings.IndexByte(s, '='); i >= 0 {
			s = s[:i+1] + Redacted
		}
	}
	if c.heur {
		s = heuristic(s)
	}
	if strings.Contains(s, "PRIVATE KEY-----") {
		s = privateKeyRe.ReplaceAllString(s, Redacted)
	}
	for _, re := range r.opt.Patterns {
		s = re.ReplaceAllString(s, Redacted)
	}
	return s, s != orig
}
