// Package proxy implements the read-only, redacting reverse proxy.
package proxy

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"docker-socket-secure-proxy/internal/config"
	"docker-socket-secure-proxy/internal/policy"
	"docker-socket-secure-proxy/internal/redact"
)

type ctxKey struct{}

// Handler is the http.Handler of the proxy.
type Handler struct {
	cfg *config.Config
	pol *policy.Policy
	red *redact.Redactor
	rp  *httputil.ReverseProxy
	log *slog.Logger
	sem chan struct{}
}

// New builds a Handler that talks to the unix socket in cfg.
func New(cfg *config.Config, log *slog.Logger) *Handler {
	h := &Handler{
		cfg: cfg,
		pol: policy.New(cfg),
		red: redact.New(redact.Options{
			RedactLabels:    cfg.RedactLabels,
			RedactLabelKeys: cfg.RedactLabelKeys,
			Patterns:        cfg.RedactPatterns,
		}),
		log: log,
		sem: make(chan struct{}, max(cfg.MaxConcurrent, 1)),
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: cfg.DialTimeout}
			return d.DialContext(ctx, "unix", cfg.Socket)
		},
		DisableCompression:    true,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   cfg.DialTimeout,
		ResponseHeaderTimeout: cfg.RequestTimeout,
	}
	h.rp = &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "docker"
			pr.Out.Host = "docker"
			pr.Out.Header.Set("Accept-Encoding", "identity")
			pr.Out.Header.Del("X-Registry-Auth")
			pr.Out.Header.Del("X-Registry-Config")
			pr.Out.Header.Del("Authorization")
		},
		ModifyResponse: h.modify,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.log.Warn("upstream/response error", "method", r.Method, "path", r.URL.Path, "err", err)
			writeError(w, http.StatusBadGateway, "docker-socket-secure-proxy: "+err.Error())
		},
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}
	d := h.pol.Decide(r)
	if !d.Allow {
		if r.Method == http.MethodHead {
			sw.WriteHeader(d.Status)
		} else {
			if d.Status == http.StatusMethodNotAllowed {
				sw.Header().Set("Allow", "GET, HEAD")
			}
			writeError(sw, d.Status, "docker-socket-secure-proxy: "+d.Reason)
		}
		h.log.Warn("denied", "method", r.Method, "path", r.URL.Path, "status", d.Status, "reason", d.Reason, "remote", r.RemoteAddr)
		return
	}
	if !d.Ping { // keep health checks working when saturated
		select {
		case h.sem <- struct{}{}:
			defer func() { <-h.sem }()
		default:
			w.Header().Set("Retry-After", "1")
			writeError(sw, http.StatusServiceUnavailable, "docker-socket-secure-proxy: too many concurrent requests")
			h.log.Warn("rejected", "method", r.Method, "path", r.URL.Path, "status", 503, "reason", "MAX_CONCURRENT_REQUESTS", "remote", r.RemoteAddr)
			return
		}
	}
	ctx := context.WithValue(r.Context(), ctxKey{}, d)
	timeout := h.cfg.RequestTimeout
	if d.Stream || d.Raw {
		timeout = h.cfg.StreamTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	r = r.WithContext(ctx)
	r.URL.Path, r.URL.RawPath = d.Path, ""
	r.Body = http.NoBody
	h.rp.ServeHTTP(sw, r)
	h.log.Info("proxied", "method", r.Method, "path", r.URL.Path, "status", sw.status, "dur", time.Since(start).Round(time.Millisecond))
}

// modify validates and redacts the upstream response.
func (h *Handler) modify(resp *http.Response) error {
	d, _ := resp.Request.Context().Value(ctxKey{}).(policy.Decision)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return errors.New("upstream connection upgrade blocked")
	}
	if resp.Request.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent ||
		resp.StatusCode == http.StatusNotModified || resp.ContentLength == 0 {
		return nil
	}
	mt, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	isJSON := mt == "application/json" || mt == "application/x-ndjson" || mt == "application/jsonl" ||
		mt == "application/json-seq" || mt == "application/x-json-stream" || strings.HasSuffix(mt, "+json")
	okStatus := resp.StatusCode < 300

	switch {
	case isJSON:
	case d.Raw && okStatus:
		return nil // logs: passed through, see README
	case d.Ping && okStatus && mt == "text/plain":
		return nil
	case !okStatus && (mt == "text/plain" || mt == ""):
		return nil // plain error messages from the daemon
	default:
		return fmt.Errorf("response content type %q not allowed", mt)
	}

	body := resp.Body
	if enc := strings.ToLower(resp.Header.Get("Content-Encoding")); enc != "" {
		if enc != "gzip" {
			return fmt.Errorf("unsupported content encoding %q", enc)
		}
		zr, err := gzip.NewReader(body)
		if err != nil {
			return err
		}
		body = struct {
			io.Reader
			io.Closer
		}{zr, resp.Body}
		resp.Header.Del("Content-Encoding")
	}
	resp.Header.Del("Content-Length")
	resp.Uncompressed = true

	if d.Stream && okStatus {
		pr, pw := io.Pipe()
		go func() {
			err := h.red.Stream(body, pw)
			body.Close()
			if err != nil {
				h.log.Warn("stream redaction aborted", "path", resp.Request.URL.Path, "err", err)
			}
			pw.CloseWithError(err) // nil error => EOF
		}()
		resp.Body = pr
		resp.ContentLength = -1
		return nil
	}

	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, h.cfg.MaxBody+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > h.cfg.MaxBody {
		return fmt.Errorf("response larger than MAX_BODY_BYTES (%d)", h.cfg.MaxBody)
	}
	out, err := h.red.Bytes(data)
	if err != nil {
		return fmt.Errorf("cannot parse JSON response, refusing to forward: %w", err)
	}
	resp.Body = io.NopCloser(strings.NewReader(string(out)))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", fmt.Sprint(len(out)))
	return nil
}

func writeError(w http.ResponseWriter, status int, msg string) {
	b, _ := json.Marshal(map[string]string{"message": msg})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(b)+1))
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(c int) {
	if s.status == 0 {
		s.status = c
	}
	s.ResponseWriter.WriteHeader(c)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }
