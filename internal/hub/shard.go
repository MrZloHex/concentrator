package hub

import (
	"sync"
	"time"

	ws "github.com/gorilla/websocket"
	log "log/slog"
)

const (
	// outboxSize is how many frames may wait for one client. A client that
	// falls this far behind has stopped reading.
	outboxSize   = 1024
	writeTimeout = 5 * time.Second
)

type shard struct {
	conn    *ws.Conn
	hub     chan<- packet
	onClose func(*shard)

	out  chan packet // frames waiting to be written to this client
	done chan struct{}
	once sync.Once
}

func newShard(conn *ws.Conn, income chan<- packet) *shard {
	s := &shard{conn: conn, hub: income, out: make(chan packet, outboxSize), done: make(chan struct{})}
	go s.write()
	return s
}

func (s *shard) glisten() {
	defer s.close()
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

// write sends this client its frames in order, each with a deadline. It
// runs apart from the hub, so a slow client costs only itself.
func (s *shard) write() {
	for {
		select {
		case <-s.done:
			return
		case pack := <-s.out:
			s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := s.conn.WriteMessage(pack.kind, pack.pay); err != nil {
				log.Warn("Write failed, dropping client", "addr", s.conn.RemoteAddr(), "err", err)
				s.close()
				return
			}
		}
	}
}

// absorb queues a frame for this client without waiting. A full queue means
// a client that stopped reading — ukaz once did, its network task stuck —
// and it is dropped rather than allowed to stall the hub for everyone.
func (s *shard) absorb(pack packet) bool {
	select {
	case <-s.done:
		return false
	case s.out <- pack:
		return true
	default:
		log.Warn("Client not reading, dropping it", "addr", s.conn.RemoteAddr())
		s.close()
		return false
	}
}

func (s *shard) close() {
	s.once.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}
