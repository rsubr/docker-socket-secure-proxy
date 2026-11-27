// Package policy decides whether a request may be forwarded to the Docker daemon.
package policy

import (
	"net/http"
	"path"
	"regexp"
	"strings"

	"docker-socket-secure-proxy/internal/config"
)

// Decision is the verdict for one request.
type Decision struct {
	Allow  bool
	Status int    // HTTP status when denied
	Reason string // human readable reason (also logged)
	Path   string // normalised path to forward (version prefix kept)
	Cat    string // category that allowed the request
	Stream bool   // response is a long-lived JSON stream
	Raw    bool   // response is non-JSON and passes unmodified (logs)
	Ping   bool   // plain-text ping response is acceptable
}

// Policy evaluates requests against the enabled categories.
type Policy struct{ allow map[string]bool }

// New builds a Policy from config.
func New(c *config.Config) *Policy { return &Policy{allow: c.Allow} }

var versionRe = regexp.MustCompile(`^/v[0-9]+(\.[0-9]+)*(/|$)`)

func deny(status int, reason string) Decision {
	return Decision{Status: status, Reason: reason}
}

// Decide evaluates method, URL path and relevant headers.
func (p *Policy) Decide(r *http.Request) Decision {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return deny(http.StatusMethodNotAllowed, "method "+r.Method+" not allowed (read-only proxy)")
	}
	if isUpgrade(r) {
		return deny(http.StatusForbidden, "connection upgrade/hijack not allowed")
	}
	if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		return deny(http.StatusBadRequest, "request body not allowed")
	}
	raw := r.URL.Path
	if raw == "" || raw[0] != '/' || strings.ContainsAny(raw, "\x00\\") {
		return deny(http.StatusBadRequest, "invalid path")
	}
	clean := path.Clean(raw)
	rest := clean
	if loc := versionRe.FindString(clean); loc != "" {
		rest = clean[len(strings.TrimSuffix(loc, "/")):]
		if rest == "" {
			rest = "/"
		}
	}
	segs := strings.Split(strings.Trim(rest, "/"), "/")
	if len(segs) == 1 && segs[0] == "" {
		return deny(http.StatusForbidden, "path not allowed")
	}
	d := p.classify(segs)
	d.Path = clean
	if d.Reason == "" && !d.Allow {
		d.Reason = "path not allowed"
	}
	if d.Status == 0 && !d.Allow {
		d.Status = http.StatusForbidden
	}
	if d.Allow && !p.allow[d.Cat] {
		return deny(http.StatusForbidden, "category "+d.Cat+" disabled (set "+d.Cat+"=1 to enable)")
	}
	return d
}

func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return true
	}
	for _, v := range r.Header.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
				return true
			}
		}
	}
	return false
}

func ok(cat string) Decision { return Decision{Allow: true, Cat: cat} }

func blocked(reason string) Decision { return deny(http.StatusForbidden, reason) }

// classify maps path segments (version prefix removed) to a category.
func (p *Policy) classify(s []string) Decision {
	n := len(s)
	last := s[n-1]
	switch s[0] {
	case "_ping":
		if n == 1 {
			d := ok(config.Ping)
			d.Ping = true
			return d
		}
	case "version":
		if n == 1 {
			return ok(config.Version)
		}
	case "info":
		if n == 1 {
			return ok(config.Info)
		}
	case "events":
		if n == 1 {
			d := ok(config.Events)
			d.Stream = true
			return d
		}
	case "system":
		if n == 2 && s[1] == "df" {
			return ok(config.System)
		}
	case "containers":
		switch {
		case n == 2 && s[1] == "json":
			return ok(config.Containers)
		case n == 3 && (last == "json" || last == "changes"):
			return ok(config.Containers)
		case n == 3 && last == "stats":
			d := ok(config.Containers)
			d.Stream = true
			return d
		case n == 3 && last == "logs":
			d := ok(config.Logs)
			d.Raw = true
			return d
		case n == 3 && last == "top":
			return blocked("container top exposes process command lines")
		case n >= 3 && (last == "archive" || last == "export"):
			return blocked("file/filesystem export blocked")
		case n >= 3 && (strings.HasPrefix(last, "attach") || last == "ws"):
			return blocked("attach blocked")
		}
	case "images":
		switch {
		case n == 2 && s[1] == "json":
			return ok(config.Images)
		case n == 2 && s[1] == "get", n >= 3 && last == "get":
			return blocked("image export blocked")
		case n == 2 && s[1] == "search":
			return blocked("image search blocked")
		case n >= 3 && (last == "json" || last == "history"):
			return ok(config.Images) // name may contain slashes
		}
	case "networks":
		if n <= 2 {
			return ok(config.Networks)
		}
	case "volumes":
		if n <= 2 {
			return ok(config.Volumes)
		}
	case "services":
		return listInspectLogs(n, last, config.Services)
	case "tasks":
		return listInspectLogs(n, last, config.Tasks)
	case "nodes":
		if n <= 2 {
			return ok(config.Nodes)
		}
	case "swarm":
		if n == 1 {
			return ok(config.Swarm)
		}
		if n == 2 && last == "unlockkey" {
			return blocked("swarm unlock key blocked")
		}
	case "secrets":
		if n <= 2 {
			return ok(config.Secrets)
		}
	case "configs":
		if n <= 2 {
			return ok(config.Configs)
		}
	case "plugins":
		switch {
		case n == 1:
			return ok(config.Plugins)
		case n == 2 && last == "privileges":
			return blocked("plugin privileges lookup blocked")
		case n >= 3 && last == "json":
			return ok(config.Plugins)
		}
	case "distribution":
		if n >= 3 && last == "json" {
			return ok(config.Distribution)
		}
	case "exec":
		if n == 3 && last == "json" {
			return ok(config.Exec)
		}
	}
	return blocked("path not allowed")
}

func listInspectLogs(n int, last, cat string) Decision {
	switch {
	case n <= 2:
		return ok(cat)
	case n == 3 && last == "logs":
		d := ok(config.Logs)
		d.Raw = true
		return d
	}
	return blocked("path not allowed")
}
