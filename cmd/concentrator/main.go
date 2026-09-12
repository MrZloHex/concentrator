package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/lmittmann/tint"
	cli "github.com/spf13/pflag"
	log "log/slog"

	auth "github.com/MrZloHex/monolink/marshal"

	"concentrator/internal/hub"
)

var logLevelMap = map[string]log.Level{
	"debug": log.LevelDebug,
	"info":  log.LevelInfo,
	"warn":  log.LevelWarn,
	"error": log.LevelError,
}

// buildTLSConfig is mutual TLS: the hub's certificate, and every client's
// checked against the one CA that issues the bubble's (hub.ClientCAPool).
// TLS 1.3 only: every client on the bus is Go. ukaz's library may need 1.2
// when it joins; that is a decision for then, not a door left open now.
func buildTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	pem, err := os.ReadFile(clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read the client CA: %w", err)
	}
	pool, ca, err := hub.ClientCAPool(pem)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", clientCAFile, err)
	}
	log.Info("CLIENT CA", "subject", ca.Subject.String(), "until", ca.NotAfter.Format(time.DateOnly))
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
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

	port := cli.Uint16P("port", "p", envUint16("CONCENTRATOR_PORT", 8443), "Host port (env CONCENTRATOR_PORT)")
	logLevel := cli.StringP("log", "l", envString("CONCENTRATOR_LOG", "info"), "Log level (env CONCENTRATOR_LOG)")
	tlsCert := cli.String("tls-cert", os.Getenv("CONCENTRATOR_TLS_CERT"), "The hub's TLS certificate, PEM (env CONCENTRATOR_TLS_CERT)")
	tlsKey := cli.String("tls-key", os.Getenv("CONCENTRATOR_TLS_KEY"), "The hub's TLS private key, PEM (env CONCENTRATOR_TLS_KEY)")
	tlsClientCA := cli.String("tls-client-ca", os.Getenv("CONCENTRATOR_TLS_CLIENT_CA"), "The one CA that issues the bus's certificates, alone, PEM (env CONCENTRATOR_TLS_CLIENT_CA)")
	policyPath := cli.String("policy", envString("CONCENTRATOR_POLICY", "policy"), "Who may join the bus, as what, and what each may send (env CONCENTRATOR_POLICY)")
	revokedPath := cli.String("revoked", os.Getenv("CONCENTRATOR_REVOKED"), "Revoked certificate serials, one per line (env CONCENTRATOR_REVOKED)")
	ticketKey := cli.String("ticket-key", envString("CONCENTRATOR_TICKET_KEY", "ticket.pub"), "marshal's public key, to check tickets with, PEM (env CONCENTRATOR_TICKET_KEY)")
	cli.Parse()

	// Standard output only: the journal keeps it. Frames are never logged,
	// at any level — they carry session tokens, proofs and messages.
	log.SetDefault(log.New(tint.NewHandler(os.Stdout, &tint.Options{Level: logLevelMap[*logLevel]})))

	if *tlsCert == "" || *tlsKey == "" || *tlsClientCA == "" {
		log.Error("the hub runs only with mutual TLS: --tls-cert, --tls-key and --tls-client-ca are required")
		os.Exit(1)
	}
	tlsCfg, err := buildTLSConfig(*tlsCert, *tlsKey, *tlsClientCA)
	if err != nil {
		log.Error("TLS configuration failed", "err", err)
		os.Exit(1)
	}
	policy, err := hub.LoadPolicy(*policyPath, *revokedPath)
	if err != nil {
		log.Error("policy", "err", err)
		os.Exit(1)
	}

	pub, err := auth.LoadTicketPublicKey(*ticketKey)
	if err != nil {
		log.Error("ticket key", "err", err)
		os.Exit(1)
	}

	h := hub.New(policy, hub.TLSIdentity, hub.Options{TicketKey: pub})
	go h.Run()

	// SIGHUP reads the policy and the revoked list again; a connection they
	// no longer admit is dropped at once. A policy that does not parse is
	// refused, and the one in force stays.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			p, err := hub.LoadPolicy(*policyPath, *revokedPath)
			if err != nil {
				log.Error("policy not reloaded", "err", err)
				continue
			}
			h.Reload(p)
			log.Info("POLICY RELOADED")
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", h.Accept)
	// The timeouts are for the request before it becomes a bus connection,
	// and for connections that never do; a shard sets its own deadlines on
	// every read and write once upgraded.
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           mux,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    8 << 10,
	}
	log.Info("LISTENING", "addr", srv.Addr, "policy", *policyPath, "revoked", *revokedPath)
	log.Error("Failed to serve", "err", srv.ListenAndServeTLS("", ""))
	os.Exit(1)
}
