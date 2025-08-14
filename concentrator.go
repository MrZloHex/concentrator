package main;

import 		"net/http"
import ws 	"github.com/gorilla/websocket";

type packet struct {
	kind int;
	pay  []byte;
};

type Concetrator struct {
	upd 	ws.Upgrader;
	shards 	map[*Shard]struct{};
	income 	chan packet;
};

func newCctr() *Concetrator {
	return &Concetrator {
		upd: ws.Upgrader {
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin:     func (*http.Request) bool { return true; },
		},
		shards: make(map[*Shard]struct{}),
		income: make(chan packet),
	};
}

func (cctr *Concetrator) accept(w http.ResponseWriter, r *http.Request) {
	conn, err := cctr.upd.Upgrade(w, r, nil)
	if err != nil {
		log.Error("Failed to upgrade connection", "err", err);
		return;
	}
	
	log.Info("New shard", "addr", conn.RemoteAddr());
	var shard *Shard = newShard(conn, cctr.income);
	
	cctr.shards[shard] = struct{}{};
	go shard.glisten();
}

func (cctr *Concetrator) serve() {
	for {
		pack := <- cctr.income;

		for sh := range cctr.shards {
			is_on := sh.absorb(pack);

			if !is_on {
				delete(cctr.shards, sh);
			}
		}
	}
}
