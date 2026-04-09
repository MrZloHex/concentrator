package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	cli "github.com/spf13/pflag"
	log "log/slog"

	"concentrator/internal/hub"
)

var logLevelMap = map[string]log.Level{
	"debug": log.LevelDebug,
	"info":  log.LevelInfo,
	"warn":  log.LevelWarn,
	"error": log.LevelError,
}

type TeeHandler struct {
	handlers []log.Handler
}

func (t *TeeHandler) Enabled(ctx context.Context, level log.Level) bool {
	for _, h := range t.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (t *TeeHandler) Handle(ctx context.Context, r log.Record) error {
	var err error
	for _, h := range t.handlers {
		if h.Enabled(ctx, r.Level) {
			if e := h.Handle(ctx, r); e != nil {
				err = e
			}
		}
	}
	return err
}

func (t *TeeHandler) WithAttrs(attrs []log.Attr) log.Handler {
	newHs := make([]log.Handler, len(t.handlers))
	for i, h := range t.handlers {
		newHs[i] = h.WithAttrs(attrs)
	}
	return &TeeHandler{handlers: newHs}
}

func (t *TeeHandler) WithGroup(name string) log.Handler {
	newHs := make([]log.Handler, len(t.handlers))
	for i, h := range t.handlers {
		newHs[i] = h.WithGroup(name)
	}
	return &TeeHandler{handlers: newHs}
}

func NewTee(handlers ...log.Handler) log.Handler {
	return &TeeHandler{handlers: handlers}
}

func initLogging(logLevel log.Level) func() {
	stdoutHandler := tint.NewHandler(os.Stdout, &tint.Options{
		Level: logLevel,
	})

	_ = os.MkdirAll("logs", 0o755)
	pid := os.Getpid()
	filename := fmt.Sprintf("%d_concentrator.log", pid)
	// filename = fmt.Sprintf("%d_concentrator_%s.log", pid, time.Now().Format("2006-01-02"))

	path := filepath.Join("logs", filename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		// Fallback: stdout only
		log.SetDefault(log.New(stdoutHandler))
		log.Error("failed to open file log", "err", err)
		return func() {}
	}

	fileHandler := tint.NewHandler(f, &tint.Options{
		Level: log.LevelDebug, // DEBUG and above to file
	})

	// Fan-out to both handlers
	log.SetDefault(log.New(NewTee(stdoutHandler, fileHandler)))

	_ = os.Remove(filepath.Join("logs", "concentrator.current.log"))
	_ = os.Symlink(filename, filepath.Join("logs", "concentrator.current.log"))

	return func() {
		_ = f.Sync()
		_ = f.Close()
	}
}

func buildTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS12,
	}

	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from client CA file %q", clientCAFile)
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	} else {
		cfg.ClientAuth = tls.NoClientCert
	}

	return cfg, nil
}

func loadDotEnv() {
	err := godotenv.Load()
	if err == nil {
		return
	}
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var pe *os.PathError
	if errors.As(err, &pe) && errors.Is(pe.Err, os.ErrNotExist) {
		return
	}
	_, _ = fmt.Fprintf(os.Stderr, "concentrator: warning: .env: %v\n", err)
}

func envString(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envUint16(key string, fallback uint16) uint16 {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseUint(v, 10, 16)
	if err != nil {
		return fallback
	}
	return uint16(n)
}

func main() {
	loadDotEnv()

	defaultPort := envUint16("CONCENTRATOR_PORT", 8092)
	defaultLog := envString("CONCENTRATOR_LOG", "info")
	defaultCert := os.Getenv("CONCENTRATOR_TLS_CERT")
	defaultKey := os.Getenv("CONCENTRATOR_TLS_KEY")
	defaultClientCA := os.Getenv("CONCENTRATOR_TLS_CLIENT_CA")

	port := cli.Uint16P("port", "p", defaultPort, "Host port (env CONCENTRATOR_PORT)")
	logLevel := cli.StringP("log", "l", defaultLog, "Log level (env CONCENTRATOR_LOG)")
	tlsCert := cli.String("tls-cert", defaultCert, "Path to server TLS certificate (PEM); enables HTTPS when set with --tls-key (env CONCENTRATOR_TLS_CERT)")
	tlsKey := cli.String("tls-key", defaultKey, "Path to server TLS private key (PEM) (env CONCENTRATOR_TLS_KEY)")
	tlsClientCA := cli.String("tls-client-ca", defaultClientCA, "Path to PEM bundle of CAs for verifying client certificates (mTLS) (env CONCENTRATOR_TLS_CLIENT_CA)")
	cli.Parse()

	flush := initLogging(logLevelMap[*logLevel])
	defer flush()

	addr := fmt.Sprintf(":%d", *port)
	log.Info("BOOTING UP ON", "addr", addr)

	h := hub.New()
	go h.Run()

	http.HandleFunc("/", h.Accept)

	var err error
	if *tlsCert != "" || *tlsKey != "" || *tlsClientCA != "" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Error("TLS flags incomplete: --tls-cert and --tls-key are required when using TLS")
			os.Exit(1)
		}
		if *tlsClientCA == "" {
			log.Error("mTLS requires --tls-client-ca (PEM bundle of CAs that issued client certificates)")
			os.Exit(1)
		}
		tlsCfg, terr := buildTLSConfig(*tlsCert, *tlsKey, *tlsClientCA)
		if terr != nil {
			log.Error("TLS configuration failed", "err", terr)
			os.Exit(1)
		}
		srv := &http.Server{
			Addr:      addr,
			TLSConfig: tlsCfg,
		}
		log.Info("listening with mTLS", "cert", *tlsCert, "client_ca", *tlsClientCA)
		err = srv.ListenAndServeTLS("", "")
	} else {
		log.Warn("listening with NO mTLS")
		err = http.ListenAndServe(addr, nil)
	}

	log.Error("Failed to serve", "err", err)
}
