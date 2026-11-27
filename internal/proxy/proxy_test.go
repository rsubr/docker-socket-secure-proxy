package proxy

import (
	"bufio"
	"compress/gzip"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"docker-socket-secure-proxy/internal/config"
)

type fake struct {
	events chan string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/_ping"):
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Api-Version", "1.47")
		io.WriteString(w, "OK")
	case strings.HasSuffix(r.URL.Path, "/containers/abc/json"):
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"Id":"abc","Config":{"Env":["OPENAPI_KEY=supersecret123"],"Labels":{"traefik.enable":"true"}},"Big":18446744073709551615}`+"\n")
	case strings.HasSuffix(r.URL.Path, "/networks"):
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		io.WriteString(zw, `{"Env":["A=secret"]}`)
		zw.Close()
	case strings.HasSuffix(r.URL.Path, "/events"):
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		for e := range f.events {
			io.WriteString(w, e)
			w.(http.Flusher).Flush()
		}
	case strings.HasSuffix(r.URL.Path, "/images/json"):
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"broken":`)
	case strings.HasSuffix(r.URL.Path, "/info"):
		w.Header().Set("Content-Type", "application/x-tar")
		io.WriteString(w, "tardata supersecret123")
	case strings.HasSuffix(r.URL.Path, "/version"):
		w.WriteHeader(404)
		io.WriteString(w, "page not found\n")
	default:
		w.WriteHeader(500)
	}
}

func setup(t *testing.T, f *fake) *httptest.Server {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	up := &http.Server{Handler: f}
	go up.Serve(ln)
	t.Cleanup(func() { up.Close(); os.Remove(sock) })
	cfg, _ := config.Load(func(k string) string {
		if k == "DOCKER_SOCKET" {
			return sock
		}
		return ""
	})
	srv := httptest.NewServer(New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil))))
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestProxy(t *testing.T) {
	srv := setup(t, &fake{events: make(chan string)})

	resp, body := get(t, srv.URL+"/v1.47/containers/abc/json")
	if strings.Contains(body, "supersecret123") || !strings.Contains(body, "OPENAPI_KEY=REDACTED") ||
		!strings.Contains(body, "18446744073709551615") || !strings.Contains(body, `"traefik.enable":"true"`) {
		t.Fatalf("bad body %s", body)
	}
	if resp.ContentLength != int64(len(body)) {
		t.Errorf("content-length %d vs %d", resp.ContentLength, len(body))
	}

	resp, body = get(t, srv.URL+"/_ping")
	if resp.StatusCode != 200 || body != "OK" || resp.Header.Get("Api-Version") != "1.47" {
		t.Errorf("ping: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	if resp, _ := http.Head(srv.URL + "/_ping"); resp.StatusCode != 200 {
		t.Errorf("HEAD ping %d", resp.StatusCode)
	}

	resp, body = get(t, srv.URL+"/networks") // gzip upstream
	if resp.StatusCode != 200 || strings.Contains(body, "secret") || resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("gzip: %d %q %v", resp.StatusCode, body, resp.Header)
	}

	resp, body = get(t, srv.URL+"/images/json")
	if resp.StatusCode != 502 || strings.Contains(body, `{"broken"`) {
		t.Errorf("malformed json: %d %s", resp.StatusCode, body)
	}
	resp, body = get(t, srv.URL+"/info")
	if resp.StatusCode != 502 || strings.Contains(body, "supersecret") {
		t.Errorf("tar: %d %s", resp.StatusCode, body)
	}
	resp, body = get(t, srv.URL+"/version")
	if resp.StatusCode != 404 || !strings.Contains(body, "not found") {
		t.Errorf("404 passthrough: %d %s", resp.StatusCode, body)
	}

	for _, m := range []string{"POST", "DELETE", "PUT"} {
		req, _ := http.NewRequest(m, srv.URL+"/containers/abc/stop", nil)
		resp, _ := http.DefaultClient.Do(req)
		if resp.StatusCode != 405 {
			t.Errorf("%s: %d", m, resp.StatusCode)
		}
	}
	resp, body = get(t, srv.URL+"/containers/abc/archive?path=/etc")
	if resp.StatusCode != 403 || !strings.Contains(body, `"message"`) {
		t.Errorf("archive: %d %s", resp.StatusCode, body)
	}
}

func TestEventsStreaming(t *testing.T) {
	f := &fake{events: make(chan string)}
	srv := setup(t, f)
	resp, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rd := bufio.NewReader(resp.Body)
	for i, ev := range []string{`{"Action":"exec_start: sh -c TOKEN=abc","n":1}`, `{"Action":"die","n":2}`} {
		f.events <- ev + "\n"
		ch := make(chan string, 1)
		go func() { l, _ := rd.ReadString('\n'); ch <- l }()
		select {
		case l := <-ch:
			if strings.Contains(l, "abc") || !strings.Contains(l, `"n":`) {
				t.Fatalf("event %d: %q", i, l)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("event %d not delivered while stream open", i)
		}
	}
	close(f.events)
}
