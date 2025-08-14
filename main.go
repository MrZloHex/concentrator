package main

import "fmt"
import "log/slog"
import "os"
import "net/http"

import "github.com/lmittmann/tint"
import cli "github.com/spf13/pflag"

var log *slog.Logger = slog.New(tint.NewHandler(os.Stdout, &tint.Options{
	Level: slog.LevelDebug,
}))

func main() {
	var port *uint16 = cli.Uint16P("port", "p", 8092, "Host port")
	cli.Parse()

	log.Info("BOOTING UP ON", "port", *port)

	var cctr *Concentrator = newConcentrator()
	go cctr.serve()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		cctr.accept(w, r)
	})
	err := http.ListenAndServe(fmt.Sprintf(":%d", *port), nil)
	log.Error("Failed to serve", "err", err)
}
