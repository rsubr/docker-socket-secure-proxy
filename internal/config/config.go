// Package config loads proxy configuration from environment variables.
package config

import (
	"fmt"
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
	ListenAddr string
	Socket     string
	Allow      map[string]bool

	RedactLabels    bool
	RedactLabelKeys []*regexp.Regexp
	RedactPatterns  []*regexp.Regexp

	MaxBody        int64
	RequestTimeout time.Duration
	LogLevel       string
}

// Load reads configuration using getenv (os.Getenv in production).
func Load(getenv func(string) string) (*Config, error) {
	c := &Config{
		ListenAddr:     or(getenv("LISTEN_ADDR"), ":2375"),
		Socket:         or(getenv("DOCKER_SOCKET"), "/var/run/docker.sock"),
		Allow:          map[string]bool{},
		MaxBody:        64 << 20,
		RequestTimeout: 60 * time.Second,
		LogLevel:       or(getenv("LOG_LEVEL"), "info"),
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
