package main

import (
	"fmt"
	"net/http"
	"os"

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

func main() {
	port := cli.Uint16P("port", "p", 8092, "Host port")
	logLevel := cli.StringP("log", "l", "info", "Log level")
	cli.Parse()

	log.SetDefault(log.New(
		tint.NewHandler(os.Stdout, &tint.Options{
			Level: logLevelMap[*logLevel],
		}),
	))
	log.Info("BOOTING UP ON", "port", *port)

	h := hub.New()
	go h.Run()

	http.HandleFunc("/", h.Accept)
	err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	log.Error("Failed to serve", "err", err)
}
