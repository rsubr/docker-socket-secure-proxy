package config

import "testing"

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaultsAndOverrides(t *testing.T) {
	c, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":2375" || c.Socket != "/var/run/docker.sock" || !c.Allow[Containers] || c.Allow[Secrets] || c.Allow[Logs] {
		t.Fatalf("%+v", c)
	}
	c, err = Load(env(map[string]string{"CONTAINERS": "0", "LOGS": "true", "REDACT_PATTERNS": `a+;;b\d`, "REDACT_LABELS": "1"}))
	if err != nil || c.Allow[Containers] || !c.Allow[Logs] || len(c.RedactPatterns) != 2 || !c.RedactLabels {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestInvalid(t *testing.T) {
	for _, m := range []map[string]string{{"INFO": "maybe"}, {"REDACT_PATTERNS": "("}, {"MAX_BODY_BYTES": "x"}, {"REQUEST_TIMEOUT": "-1s"}} {
		if _, err := Load(env(m)); err == nil {
			t.Errorf("expected error for %v", m)
		}
	}
}

func TestResolveListen(t *testing.T) {
	for _, c := range []struct{ l, p, want string }{
		{":2375", "", ":2375"}, {":2375", "8080", ":8080"}, {"127.0.0.1:2375", "8080", "127.0.0.1:8080"},
		{"[::1]:2375", "9", "[::1]:9"}, {"localhost", "80", "localhost:80"},
	} {
		got, err := ResolveListen(c.l, c.p)
		if err != nil || got != c.want {
			t.Errorf("%v: got %q %v", c, got, err)
		}
	}
	for _, p := range []string{"x", "0", "70000"} {
		if _, err := ResolveListen(":2375", p); err == nil {
			t.Errorf("port %q should fail", p)
		}
	}
	if _, err := ResolveListen("a:b:c", "80"); err == nil {
		t.Error("bad listen should fail")
	}
	c, _ := Load(env(map[string]string{"PORT": "8081"}))
	if c.Port != "8081" {
		t.Errorf("Port=%q", c.Port)
	}
}
