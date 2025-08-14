package main;

import ws "github.com/gorilla/websocket";

type Shard struct {
	conn   *ws.Conn;
	hub     chan<- packet
	online  bool
};

func newShard(conn *ws.Conn, income chan<- packet) *Shard {
	return &Shard {
		conn:   conn,
		hub:    income,
		online: true,
	};
}

func (shard *Shard) glisten() {
	for {
		kind, pay, err := shard.conn.ReadMessage();
		if err != nil {
			break;
		}

		shard.hub <- packet{kind, pay};
	}
	log.Info("Disconnected", "addr", shard.conn.RemoteAddr());
	shard.online = false;
}

func (shard *Shard) absorb(pack packet) bool {
	shard.conn.WriteMessage(pack.kind, pack.pay);
	return shard.online;
}
