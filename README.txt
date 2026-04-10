███╗   ███╗ ██████╗ ███╗   ██╗ ██████╗ ██╗     ██╗████████╗██╗  ██╗
████╗ ████║██╔═══██╗████╗  ██║██╔═══██╗██║     ██║╚══██╔══╝██║  ██║
██╔████╔██║██║   ██║██╔██╗ ██║██║   ██║██║     ██║   ██║   ███████║
██║╚██╔╝██║██║   ██║██║╚██╗██║██║   ██║██║     ██║   ██║   ██╔══██║
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║╚██████╔╝███████╗██║   ██║   ██║  ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝   ╚═╝  ╚═╝


  ░▒▓█ _concentrator_ █▓▒░
  A lightweight WebSocket broadcast hub. Small. Fast.

  ───────────────────────────────────────────────────────────────
  ▓ OVERVIEW
  **concentrator** is the MONOLITH **hub** — a Go service for the shared WebSocket bus.
  ▪ Accepts WebSocket clients; relays each message to every peer *except* the sender
  ▪ Optional HTTPS with mutual TLS so peers connect with `wss://` and client certificates
  ▪ Layout: `cmd/concentrator`, `internal/hub`, `internal/syncmap`

  ───────────────────────────────────────────────────────────────
  ▓ ARCHITECTURE
  ▪ **RUNTIME**: Go 1.24+ (see `go.mod`)
  ▪ **ROLE**: Inbound WebSocket server; fan-out to peers
  ▪ **TRANSPORT**: Gorilla WebSocket; optional **HTTPS** with **mTLS** (client certs required when TLS is on)
  ▪ **LOGGING**: Structured logging (`slog` + `tint`); optional log file under `logs/`

  ───────────────────────────────────────────────────────────────
  ▓ FEATURES
  ▪ Broadcast fan-out excluding sender
  ▪ Thread-safe client registry
  ▪ Optional `.env` configuration
  ▪ Optional TLS with mutual TLS (mTLS)
  ▪ Single binary, minimal configuration

  ───────────────────────────────────────────────────────────────
  ▓ REQUIREMENTS
  ▪ Go 1.24+ (see `go.mod`)

  ───────────────────────────────────────────────────────────────
  ▓ BUILD & RUN
  **Build**
  ```sh
  go build -o bin/concentrator ./cmd/concentrator
  ```

  **Run**
  ```sh
  ./bin/concentrator
  ```
  Listens on **8092** by default; flags and `CONCENTRATOR_*` are in **CONFIGURATION**.

  **Example** (custom port)
  ```sh
  ./bin/concentrator -p 9000
  ```

  ───────────────────────────────────────────────────────────────
  ▓ CONFIGURATION
  On startup, **concentrator** loads a `.env` file from the current working directory if it exists (`godotenv`). Missing `.env` is fine; other read errors print a warning to stderr and the process continues. Command-line flags override environment and `.env`.

  **Environment** (defaults for flags):
  ▪ `CONCENTRATOR_PORT` — listen port (default `8092`)
  ▪ `CONCENTRATOR_LOG` — `debug`, `info`, `warn`, `error`
  ▪ `CONCENTRATOR_TLS_CERT` — server certificate (PEM)
  ▪ `CONCENTRATOR_TLS_KEY` — server private key (PEM)
  ▪ `CONCENTRATOR_TLS_CLIENT_CA` — PEM bundle of CAs for **client** certificate verification

  **Flags**
  ▪ `-p`, `--port` — TCP port (default `8092`)
  ▪ `-l`, `--log` — log level (`debug`, `info`, `warn`, `error`)
  ▪ `--tls-cert` — server certificate (PEM)
  ▪ `--tls-key` — server private key (PEM)
  ▪ `--tls-client-ca` — PEM bundle for verifying **client** certificates (mTLS)

  **mTLS**
  ▪ When TLS is enabled, clients must use `wss://` and present a valid client certificate
  ▪ `--tls-cert`, `--tls-key`, and `--tls-client-ca` must all be set together

  Example:
  ```sh
  ./bin/concentrator -p 8092 \
    --tls-cert certs/server.crt \
    --tls-key certs/server.key \
    --tls-client-ca certs/client-ca.pem
  ```

  **Deployment note:** WebSocket **Origin** checks are permissive for development — tighten `CheckOrigin` in `internal/hub/concentrator.go` before production.

  ───────────────────────────────────────────────────────────────
  ▓ PROTOCOL
  Application messages on the wire use the MONOLITH colon-separated form `TO:VERB:NOUN[:ARGS]:FROM` (DSKY-style). This binary is the **hub**; for verbs and nouns implemented by nodes (e.g. governor, achtung), see those modules’ README files.

  ───────────────────────────────────────────────────────────────
  ▓ FINAL WORDS
  Small hub, big fan-out.
