package main

import ws "github.com/gorilla/websocket"

type Shard struct {
	conn    *ws.Conn
	hub     chan<- packet
	onClose func(*Shard)
}

func newShard(conn *ws.Conn, income chan<- packet) *Shard {
	return &Shard{
		conn: conn,
		hub:  income,
	}
}

func (shard *Shard) glisten() {
	defer shard.conn.Close()

	for {
		kind, pay, err := shard.conn.ReadMessage()
		if err != nil {
			break
		}

		shard.hub <- packet{kind: kind, pay: pay}
	}

	if shard.onClose != nil {
		shard.onClose(shard)
	}

	log.Info("Disconnected", "addr", shard.conn.RemoteAddr())
}

func (shard *Shard) absorb(pack packet) bool {
	if err := shard.conn.WriteMessage(pack.kind, pack.pay); err != nil {
		return false
	}
	return true
}
