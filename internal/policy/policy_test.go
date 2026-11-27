package policy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"docker-socket-secure-proxy/internal/config"
)

func decide(t *testing.T, env map[string]string, method, target string) Decision {
	t.Helper()
	c, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return New(c).Decide(httptest.NewRequest(method, target, nil))
}

func TestMatrix(t *testing.T) {
	logs := map[string]string{"LOGS": "1"}
	all := map[string]string{"SWARM": "1", "SECRETS": "1", "CONFIGS": "1", "PLUGINS": "1", "SYSTEM": "1", "DISTRIBUTION": "1", "EXEC": "1", "LOGS": "1"}
	cases := []struct {
		env    map[string]string
		method string
		path   string
		allow  bool
	}{
		{nil, "GET", "/_ping", true},
		{nil, "HEAD", "/_ping", true},
		{nil, "GET", "/v1.47/containers/json?all=1", true},
		{nil, "GET", "/containers/abc/json", true},
		{nil, "GET", "/v1.47/containers/abc/stats", true},
		{nil, "GET", "/events?filters=%7B%7D", true},
		{nil, "GET", "/version", true},
		{nil, "GET", "/v1.47/info", true},
		{nil, "GET", "/networks", true},
		{nil, "GET", "/networks/bridge", true},
		{nil, "GET", "/volumes", true},
		{nil, "GET", "/services", true},
		{nil, "GET", "/tasks", true},
		{nil, "GET", "/nodes", true},
		{nil, "GET", "/images/json", true},
		{nil, "GET", "/images/docker.io/library/alpine/json", true},
		{nil, "GET", "/images/alpine/history", true},
		// writes
		{nil, "POST", "/containers/create", false},
		{nil, "POST", "/containers/abc/start", false},
		{nil, "DELETE", "/containers/abc", false},
		{nil, "PUT", "/containers/abc/archive", false},
		{nil, "POST", "/_ping", false},
		{nil, "POST", "/exec/abc/start", false},
		{nil, "POST", "/images/create", false},
		// dangerous GETs
		{all, "GET", "/containers/abc/archive", false},
		{all, "HEAD", "/containers/abc/archive", false},
		{all, "GET", "/containers/abc/export", false},
		{all, "GET", "/containers/abc/attach/ws", false},
		{all, "GET", "/containers/abc/top", false},
		{all, "GET", "/images/get", false},
		{all, "GET", "/images/alpine/get", false},
		{all, "GET", "/images/search", false},
		{all, "GET", "/swarm/unlockkey", false},
		{all, "GET", "/plugins/privileges", false},
		{all, "GET", "/session", false},
		// traversal / odd paths
		{nil, "GET", "/containers/json/../abc/archive", false},
		{nil, "GET", "/v1.47/containers/abc/../../../images/get", false},
		{nil, "GET", "//containers//abc//archive", false},
		{nil, "GET", "/", false},
		{nil, "GET", "/unknown", false},
		// category toggles
		{nil, "GET", "/containers/abc/logs", false},
		{logs, "GET", "/containers/abc/logs", true},
		{logs, "GET", "/services/x/logs", true},
		{nil, "GET", "/swarm", false},
		{nil, "GET", "/secrets", false},
		{nil, "GET", "/configs/x", false},
		{nil, "GET", "/system/df", false},
		{all, "GET", "/swarm", true},
		{all, "GET", "/secrets/x", true},
		{all, "GET", "/configs", true},
		{all, "GET", "/system/df", true},
		{all, "GET", "/plugins/foo/bar/json", true},
		{all, "GET", "/distribution/alpine/json", true},
		{map[string]string{"CONTAINERS": "0"}, "GET", "/containers/json", false},
		{map[string]string{"PING": "0"}, "GET", "/_ping", false},
	}
	for _, c := range cases {
		d := decide(t, c.env, c.method, c.path)
		if d.Allow != c.allow {
			t.Errorf("%s %s: allow=%v want %v (%s)", c.method, c.path, d.Allow, c.allow, d.Reason)
		}
		if !d.Allow && d.Status < 400 {
			t.Errorf("%s %s: bad status %d", c.method, c.path, d.Status)
		}
	}
}

func TestNormalisedPathAndFlags(t *testing.T) {
	d := decide(t, nil, "GET", "/v1.47//containers/./json")
	if !d.Allow || d.Path != "/v1.47/containers/json" {
		t.Fatalf("%+v", d)
	}
	if d := decide(t, nil, "GET", "/events"); !d.Stream {
		t.Error("events should stream")
	}
	if d := decide(t, map[string]string{"LOGS": "1"}, "GET", "/containers/a/logs"); !d.Raw {
		t.Error("logs should be raw")
	}
	if d := decide(t, nil, "POST", "/containers/json"); d.Status != http.StatusMethodNotAllowed {
		t.Errorf("status %d", d.Status)
	}
}

func TestUpgradeAndBodyBlocked(t *testing.T) {
	c, _ := config.Load(func(string) string { return "" })
	r := httptest.NewRequest("GET", "/containers/a/json", nil)
	r.Header.Set("Connection", "keep-alive, Upgrade")
	r.Header.Set("Upgrade", "tcp")
	if New(c).Decide(r).Allow {
		t.Error("upgrade allowed")
	}
	r = httptest.NewRequest("GET", "/containers/json", http_body("x"))
	r.ContentLength = 1
	if New(c).Decide(r).Allow {
		t.Error("body allowed")
	}
}
