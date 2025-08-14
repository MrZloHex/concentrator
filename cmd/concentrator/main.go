package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/lmittmann/tint"
	cli "github.com/spf13/pflag"

	"concentrator/internal/hub"
)

var log = slog.New(tint.NewHandler(os.Stdout, &tint.Options{Level: slog.LevelInfo}))

func main() {
	port := cli.Uint16P("port", "p", 8092, "Host port")
	cli.Parse()

	log.Info("BOOTING UP ON", "port", *port)

	h := hub.New()
	go h.Run()

	http.HandleFunc("/", h.Accept)
	err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	log.Error("Failed to serve", "err", err)
}
