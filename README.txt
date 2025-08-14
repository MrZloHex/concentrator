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
  ▓ HTTP / WS API
  `GET /` — Upgrades to WebSocket
  • Text & binary frames accepted
  • No application protocol enforced (pure relay/bus)
  
  ──────────────────────────────────────────────────────────────────────────────
  ▓ CONFIGURATION
  Flags:
  • `--port`, `-p` : TCP port to listen on (default 8092)
  Origin checks: **permissive** for development — restrict in
  `internal/hub/concentrator.go` by editing `CheckOrigin` before deployment.
  
  ──────────────────────────────────────────────────────────────────────────────
  ▓ REPOSITORY LAYOUT
  ```
  .
  ├── cmd/
  │   └── concentrator/
  │       └── main.go           # CLI/bootstrap only
  ├── internal/
  │   ├── hub/
  │   │   ├── concentrator.go   # Hub: accepts connections & broadcasts
  │   │   └── shard.go          # Per-connection read loop & write wrapper
  │   └── syncmap/
  │       └── syncmap.go        # Generic mutex-protected map utility
  ├── go.mod
  ├── go.sum
  ├── .gitignore
  └── README.txt
  ```
  
  ──────────────────────────────────────────────────────────────────────────────
  ▓ HOW IT WORKS
  1) HTTP `GET /` → upgrade to WebSocket (**shard**)
  2) Each shard reads frames, tags them with sender, sends into hub
  3) Hub broadcasts to all shards except sender; write failures drop shard
  4) On shard close, `onClose` unregisters it immediately
  
