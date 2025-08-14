package main

import "net/http"
import ws "github.com/gorilla/websocket"

type packet struct {
	kind int
	pay  []byte
}

type Concentrator struct {
	upd    ws.Upgrader
	shards *Map[*Shard, struct{}]
	income chan packet
}

func newConcentrator() *Concentrator {
	return &Concentrator{
		upd: ws.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func(*http.Request) bool { return true },
		},
		shards: NewMap[*Shard, struct{}](),
		income: make(chan packet),
	}
}

func (cctr *Concentrator) accept(w http.ResponseWriter, r *http.Request) {
	conn, err := cctr.upd.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Failed to upgrade connection", "err", err)
		return
	}

	log.Info("New shard", "addr", conn.RemoteAddr())
	var shard *Shard = newShard(conn, cctr.income)
	shard.onClose = func(s *Shard) {
		cctr.shards.Delete(s)
	}

	cctr.shards.Store(shard, struct{}{})
	go shard.glisten()
}

func (cctr *Concentrator) serve() {
	for {
		pack := <-cctr.income

		for _, sh := range cctr.shards.Keys() {
			if ok := sh.absorb(pack); !ok {
				cctr.shards.Delete(sh)
			}
		}
	}
}
