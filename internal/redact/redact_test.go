package redact

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, o Options, in string) string {
	t.Helper()
	out, err := New(o).Bytes([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func TestEnvAndPreservation(t *testing.T) {
	in := `{"Id":"abc","Size":18446744073709551615,"F":1.50,"E":1e3,"Config":{"Env":["OPENAPI_KEY=supersecret123","DB_PASSWORD=hunter2","PATH=/usr/bin","NOEQ"],"Labels":{"traefik.enable":"true","a.password":"keepme"}},"Mounts":null,"x":"a<b"}`
	want := `{"Id":"abc","Size":18446744073709551615,"F":1.50,"E":1e3,"Config":{"Env":["OPENAPI_KEY=REDACTED","DB_PASSWORD=REDACTED","PATH=REDACTED","NOEQ"],"Labels":{"traefik.enable":"true","a.password":"keepme"}},"Mounts":null,"x":"a<b"}`
	if got := run(t, Options{}, in); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

func TestKeyBasedAndSwarm(t *testing.T) {
	in := `{"JoinTokens":{"Worker":"SWMTKN-1-x","Manager":"SWMTKN-1-y"},"Spec":{"Name":"cfg","Data":"c2VjcmV0","CAConfig":{"SigningCAKey":"K","SigningCACert":"C","NodeCertExpiry":1},"TaskTemplate":{"ContainerSpec":{"Env":["A=b"],"Secrets":[{"SecretName":"s1","SecretID":"id1","File":{"Name":"s1"}}]}}},"AuthConfig":{"username":"u","password":"p"},"IdentityToken":"tok","Password":"","Settings":{"Env":["X=1"]}}`
	got := run(t, Options{}, in)
	for _, bad := range []string{"SWMTKN", "c2VjcmV0", `"K"`, `"C"`, `"p"`, `"tok"`, "A=b", "X=1"} {
		if strings.Contains(got, bad) {
			t.Errorf("leaked %s in %s", bad, got)
		}
	}
	for _, good := range []string{`"SecretName":"s1"`, `"SecretID":"id1"`, `"NodeCertExpiry":1`, `"Password":""`, `"Name":"cfg"`} {
		if !strings.Contains(got, good) {
			t.Errorf("lost %s in %s", good, got)
		}
	}
}

func TestDataOutsideSpecKept(t *testing.T) {
	got := run(t, Options{}, `{"GraphDriver":{"Data":{"LowerDir":"/x"}}}`)
	if !strings.Contains(got, "/x") {
		t.Fatal(got)
	}
}

func TestHeuristics(t *testing.T) {
	cases := map[string]string{
		`{"Cmd":["app","--password","pw1","--token=abc","--log-level=debug"]}`: `{"Cmd":["app","--password","REDACTED","--token=REDACTED","--log-level=debug"]}`,
		`{"Command":"sleep 3600"}`:                                                    `{"Command":"sleep 3600"}`,
		`{"Command":"sh -c \"DB_PASS=x run --api-key 123 --port 80\""}`:               `{"Command":"sh -c \"DB_PASS=REDACTED run --api-key REDACTED --port 80\""}`,
		`{"History":[{"CreatedBy":"/bin/sh -c #(nop)  ENV TOKEN=abc"}]}`:              `{"History":[{"CreatedBy":"/bin/sh -c #(nop)  ENV TOKEN=REDACTED"}]}`,
		`{"Entrypoint":["curl","https://user:pw@host/x"]}`:                            `{"Entrypoint":["curl","https://user:REDACTED@host/x"]}`,
		`{"Args":["-H","Authorization: Bearer abcdefghijkl"]}`:                        `{"Args":["-H","Authorization: Bearer REDACTED"]}`,
		`{"x":"-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"}`: `{"x":"REDACTED"}`,
	}
	for in, want := range cases {
		if got := run(t, Options{}, in); got != want {
			t.Errorf("in %s\n got %s\nwant %s", in, got, want)
		}
	}
}

func TestLabels(t *testing.T) {
	in := `{"Labels":{"traefik.http.middlewares.a.basicauth.users":"u:$apr1$x","k":"v"}}`
	if got := run(t, Options{RedactLabels: true}, in); got != `{"Labels":{"traefik.http.middlewares.a.basicauth.users":"REDACTED","k":"REDACTED"}}` {
		t.Error(got)
	}
	o := Options{RedactLabelKeys: []*regexp.Regexp{regexp.MustCompile(`basicauth`)}}
	if got := run(t, o, in); got != `{"Labels":{"traefik.http.middlewares.a.basicauth.users":"REDACTED","k":"v"}}` {
		t.Error(got)
	}
	o = Options{Patterns: []*regexp.Regexp{regexp.MustCompile(`\$apr1\$\S+`)}}
	if got := run(t, o, in); !strings.Contains(got, `"u:REDACTED"`) {
		t.Error(got)
	}
}

func TestNDJSON(t *testing.T) {
	in := `{"Type":"container","Action":"exec_start: sh -c TOKEN=abc","Actor":{"Attributes":{"name":"x","image":"y"}}}` + "\n" + `{"a":1}` + "{\"b\":[]}"
	got := run(t, Options{}, in)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 || strings.Contains(got, "abc") {
		t.Fatalf("%q", got)
	}
}

func TestInvalidFailsClosed(t *testing.T) {
	for _, in := range []string{`{"a":`, `{"a":1}}`, `[1,2`, `nope`} {
		if _, err := New(Options{}).Bytes([]byte(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

// Stream must emit each value as soon as it is complete, without waiting for EOF.
func TestStreamingFlushesPerObject(t *testing.T) {
	pr, pw := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- New(Options{}).Stream(pr, outW); outW.Close() }()
	go pw.Write([]byte(`{"Env":["A=b"]}` + "\n"))
	buf := make([]byte, 256)
	ch := make(chan string, 1)
	go func() { n, _ := outR.Read(buf); ch <- string(buf[:n]) }()
	select {
	case s := <-ch:
		if s != "{\"Env\":[\"A=REDACTED\"]}\n" {
			t.Fatalf("%q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first event not flushed before stream end")
	}
	pw.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = bytes.MinRead
}
