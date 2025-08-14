package hub

import (
	"log/slog"
	"net/http"

	"concentrator/internal/syncmap"
	ws "github.com/gorilla/websocket"
)

var log = slog.Default()

type packet struct {
	kind int
	pay  []byte
	from *shard
}

type Hub struct {
	upd    ws.Upgrader
	shards *syncmap.Map[*shard, struct{}]
	income chan packet
}

func New() *Hub {
	return &Hub{
		upd: ws.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
		shards: syncmap.New[*shard, struct{}](),
		income: make(chan packet),
	}
}

func (h *Hub) Accept(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upd.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Failed to upgrade connection", "err", err)
		return
	}

	log.Info("New shard", "addr", conn.RemoteAddr())
	s := newShard(conn, h.income)
	s.onClose = func(s2 *shard) { h.shards.Delete(s2) }
	h.shards.Store(s, struct{}{})
	go s.glisten()
}

func (h *Hub) Run() {
	for {
		pack := <-h.income
		for _, s := range h.shards.Keys() {
			if s == pack.from {
				continue
			}
			if ok := s.absorb(pack); !ok {
				h.shards.Delete(s)
			}
		}
	}
}
