// Package config loads proxy configuration from environment variables.
package config

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Category names that can be toggled with environment variables.
const (
	Containers   = "CONTAINERS"
	Images       = "IMAGES"
	Networks     = "NETWORKS"
	Volumes      = "VOLUMES"
	Services     = "SERVICES"
	Tasks        = "TASKS"
	Nodes        = "NODES"
	Info         = "INFO"
	Version      = "VERSION"
	Events       = "EVENTS"
	Ping         = "PING"
	Swarm        = "SWARM"
	Secrets      = "SECRETS"
	Configs      = "CONFIGS"
	Plugins      = "PLUGINS"
	Distribution = "DISTRIBUTION"
	System       = "SYSTEM"
	Logs         = "LOGS"
	Exec         = "EXEC"
)

// Defaults lists every category with its default state.
var Defaults = map[string]bool{
	Containers: true, Images: true, Networks: true, Volumes: true,
	Services: true, Tasks: true, Nodes: true, Info: true, Version: true,
	Events: true, Ping: true,
	Swarm: false, Secrets: false, Configs: false, Plugins: false,
	Distribution: false, System: false, Logs: false, Exec: false,
}

// Config is the full runtime configuration.
type Config struct {
	Port       string // PORT env; replaces the port of ListenAddr
	ListenAddr string
	Socket     string
	Allow      map[string]bool

	RedactLabels    bool
	RedactLabelKeys []*regexp.Regexp
	RedactPatterns  []*regexp.Regexp

	MaxBody        int64
	RequestTimeout time.Duration
	LogLevel       string

	MaxConcurrent int           // MAX_CONCURRENT_REQUESTS
	StreamTimeout time.Duration // STREAM_TIMEOUT: max lifetime of log/event streams
	DialTimeout   time.Duration // DIAL_TIMEOUT: connect to the docker socket
}

// ResolveListen returns the address to listen on. A non-empty port (from the
// --port flag or PORT env) replaces the port of listen; the host part is kept.
func ResolveListen(listen, port string) (string, error) {
	if port == "" {
		return listen, nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	host := listen
	if h, _, err := net.SplitHostPort(listen); err == nil {
		host = h
	} else if strings.Contains(listen, ":") {
		return "", fmt.Errorf("invalid listen address %q", listen)
	}
	return net.JoinHostPort(host, port), nil
}

// Load reads configuration using getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	c := &Config{
		Port:           getenv("PORT"),
		ListenAddr:     or(getenv("LISTEN_ADDR"), ":2375"),
		Socket:         or(getenv("DOCKER_SOCKET"), or(getenv("SOCKET_PATH"), "/var/run/docker.sock")), // SOCKET_PATH: tecnativa alias
		Allow:          map[string]bool{},
		MaxBody:        64 << 20,
		RequestTimeout: 60 * time.Second,
		LogLevel:       or(getenv("LOG_LEVEL"), "info"),
		MaxConcurrent:  256,
		StreamTimeout:  24 * time.Hour,
		DialTimeout:    5 * time.Second,
	}
	for k, def := range Defaults {
		v, err := boolEnv(getenv, k, def)
		if err != nil {
			return nil, err
		}
		c.Allow[k] = v
	}
	var err error
	if c.RedactLabels, err = boolEnv(getenv, "REDACT_LABELS", false); err != nil {
		return nil, err
	}
	if c.RedactLabelKeys, err = regexList("REDACT_LABEL_KEYS", getenv("REDACT_LABEL_KEYS")); err != nil {
		return nil, err
	}
	if c.RedactPatterns, err = regexList("REDACT_PATTERNS", getenv("REDACT_PATTERNS")); err != nil {
		return nil, err
	}
	if s := getenv("MAX_BODY_BYTES"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("MAX_BODY_BYTES: invalid %q", s)
		}
		c.MaxBody = n
	}
	if s := getenv("REQUEST_TIMEOUT"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("REQUEST_TIMEOUT: invalid %q", s)
		}
		c.RequestTimeout = d
	}
	if s := getenv("MAX_CONCURRENT_REQUESTS"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("MAX_CONCURRENT_REQUESTS: invalid %q", s)
		}
		c.MaxConcurrent = n
	}
	for _, e := range []struct {
		k string
		d *time.Duration
	}{{"STREAM_TIMEOUT", &c.StreamTimeout}, {"DIAL_TIMEOUT", &c.DialTimeout}} {
		if s := getenv(e.k); s != "" {
			d, err := time.ParseDuration(s)
			if err != nil || d <= 0 {
				return nil, fmt.Errorf("%s: invalid %q", e.k, s)
			}
			*e.d = d
		}
	}
	return c, nil
}

// FromOS loads configuration from the process environment.
func FromOS() (*Config, error) { return Load(os.Getenv) }

func or(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

func boolEnv(getenv func(string) string, k string, def bool) (bool, error) {
	v := strings.TrimSpace(strings.ToLower(getenv(k)))
	switch v {
	case "":
		return def, nil
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%s: invalid boolean %q", k, v)
}

// regexList splits on newlines or ";;" and compiles each entry.
func regexList(name, s string) ([]*regexp.Regexp, error) {
	var out []*regexp.Regexp
	for _, part := range strings.FieldsFunc(strings.ReplaceAll(s, ";;", "\n"), func(r rune) bool { return r == '\n' }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		re, err := regexp.Compile(part)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, re)
	}
	return out, nil
}
