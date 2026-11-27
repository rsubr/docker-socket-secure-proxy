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
