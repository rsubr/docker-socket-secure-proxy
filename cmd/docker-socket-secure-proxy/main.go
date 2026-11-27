// Command docker-socket-secure-proxy is a read-only, secret-redacting proxy
// for the Docker Engine API socket.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"docker-socket-secure-proxy/internal/config"
	"docker-socket-secure-proxy/internal/proxy"
)

func main() {
	cfg, err := config.FromOS()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(2)
	}
	listen := flag.String("listen", cfg.ListenAddr, "listen address (env LISTEN_ADDR)")
	port := flag.String("port", cfg.Port, "listen port, replaces the port of --listen (env PORT)")
	socket := flag.String("socket", cfg.Socket, "docker socket path (env DOCKER_SOCKET)")
	health := flag.Bool("healthcheck", false, "HEAD /_ping on the local listener and exit 0/1")
	flag.Parse()
	cfg.Socket = *socket
	if cfg.ListenAddr, err = config.ResolveListen(*listen, *port); err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(2)
	}

	if *health {
		os.Exit(healthcheck(cfg.ListenAddr))
	}

	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(cfg.LogLevel))
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           proxy.New(cfg, log),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    32 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Error("listen failed", "err", err)
		os.Exit(1)
	}
	log.Info("listening", "addr", ln.Addr().String(), "socket", cfg.Socket, "allow", enabled(cfg))
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			log.Warn("graceful shutdown incomplete, forcing close", "err", err)
			srv.Close()
		}
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve failed", "err", err)
		os.Exit(1)
	}
	// Serve returns as soon as Shutdown starts; wait for the drain to finish.
	<-shutdownDone
	log.Info("stopped")
}

func enabled(c *config.Config) []string {
	var l []string
	for k := range config.Defaults {
		if c.Allow[k] {
			l = append(l, k)
		}
	}
	return l
}

func healthcheck(addr string) int {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Head("http://" + net.JoinHostPort(host, port) + "/_ping")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy status", resp.Status)
		return 1
	}
	return 0
}
