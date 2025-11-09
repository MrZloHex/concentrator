package main

import (
	"fmt"
	"net/http"
	"os"
	"context"
	"path/filepath"

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
		Level:      logLevel,
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

func main() {
	port := cli.Uint16P("port", "p", 8092, "Host port")
	logLevel := cli.StringP("log", "l", "info", "Log level")
	cli.Parse()

	flush := initLogging(logLevelMap[*logLevel])
	defer flush()

	log.Info("BOOTING UP ON", "port", *port)

	h := hub.New()
	go h.Run()

	http.HandleFunc("/", h.Accept)
	err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	log.Error("Failed to serve", "err", err)
}
