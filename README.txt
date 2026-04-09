███╗   ███╗ ██████╗ ███╗   ██╗ ██████╗ ██╗     ██╗████████╗██╗  ██╗
████╗ ████║██╔═══██╗████╗  ██║██╔═══██╗██║     ██║╚══██╔══╝██║  ██║
██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║██║     ██║   ██║   ███████║
██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║██║     ██║   ██║   ██╔══██║
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║╚██████╔╝███████╗██║   ██║   ██║  ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝


  ░▒▓█ _concetrator_ █▓▒░  
  A lightweight WebSocket broadcast hub.
  Small. Fast.

  ──────────────────────────────────────────────────────────────────────────────
  ▓ OVERVIEW
  **Concentrator** is a tiny Go service that:
  ▪ Accepts WebSocket clients
  ▪ Broadcasts each message to all connected clients *except* the sender
  Uses a clean, conventional Go repo layout with `cmd/`, `internal/hub`, and `internal/syncmap`.
  
  ──────────────────────────────────────────────────────────────────────────────
  ▓ FEATURES
  ▪ Broadcast fan-out excluding sender
  ▪ Thread-safe client registry
  ▪ Structured logging (`slog` + `tint`)
  ▪ Optional `.env` configuration
  ▪ Optional HTTPS with mutual TLS (mTLS)
  ▪ Single binary, minimal configuration
  
  ──────────────────────────────────────────────────────────────────────────────
  ▓ REQUIREMENTS
  ▪ Go 1.24+
  
  ──────────────────────────────────────────────────────────────────────────────
  ▓ QUICK START
  ```sh
  # build
  go build -o bin/concentrator ./cmd/concentrator
  
  # run on default port 8092
  ./bin/concentrator
  
  # or specify a port
  ./bin/concentrator --port 9000
  # short flag
  ./bin/concentrator -p 9000
  ```
  
  ──────────────────────────────────────────────────────────────────────────────
  ▓ CONFIGURATION
  Flags:
  • `--port`, `-p` : TCP port to listen on (default 8092)
  • `--log`, `-l` : log level (`debug`, `info`, `warn`, `error`)
  • `--tls-cert` : server certificate in PEM format
  • `--tls-key` : server private key in PEM format
  • `--tls-client-ca` : PEM bundle of CAs used to verify client certificates

  Environment variables (used as defaults for flags):
  • `CONCENTRATOR_PORT`
  • `CONCENTRATOR_LOG`
  • `CONCENTRATOR_TLS_CERT`
  • `CONCENTRATOR_TLS_KEY`
  • `CONCENTRATOR_TLS_CLIENT_CA`

  `.env`:
  • `.env` is loaded automatically from the current working directory (optional)
  • command-line flags override values from environment/.env

  mTLS:
  • when TLS is enabled, this service requires client certificates
  • `--tls-cert`, `--tls-key`, and `--tls-client-ca` must all be set
  • clients must connect with `wss://` and present a valid client certificate

  Example:
  ```sh
  ./bin/concentrator -p 8092 \
    --tls-cert certs/server.crt \
    --tls-key certs/server.key \
    --tls-client-ca certs/client-ca.pem
  ```

  Origin checks: **permissive** for development — restrict in
  `internal/hub/concentrator.go` by editing `CheckOrigin` before deployment.
  
