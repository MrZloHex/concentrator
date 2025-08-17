package hub

import (
	ws "github.com/gorilla/websocket"
	log "log/slog"
)

type shard struct {
	conn    *ws.Conn
	hub     chan<- packet
	onClose func(*shard)
}

func newShard(conn *ws.Conn, income chan<- packet) *shard {
	return &shard{conn: conn, hub: income}
}

func (s *shard) glisten() {
	defer s.conn.Close()
	for {
		kind, pay, err := s.conn.ReadMessage()
		if err != nil {
			break
		}
		s.hub <- packet{kind: kind, pay: pay, from: s}
	}
	if s.onClose != nil {
		s.onClose(s)
	}
	log.Info("Disconnected", "addr", s.conn.RemoteAddr())
}

func (s *shard) absorb(pack packet) bool {
	err := s.conn.WriteMessage(pack.kind, pack.pay)
	return err == nil
}
