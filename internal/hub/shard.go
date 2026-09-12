package hub

import (
	"errors"
	"net"
	"sync"
	"time"

	ws "github.com/gorilla/websocket"
	log "log/slog"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

const (
	// outboxSize is how many frames may wait for one client. A client that
	// falls this far behind has stopped reading.
	outboxSize   = 1024
	writeTimeout = 5 * time.Second
	logEvery     = time.Second // a flood of refusals is logged once a second
)

type shard struct {
	conn    *ws.Conn
	hub     chan<- packet
	onClose func(*shard)
	id      Identity
	cert    Cert

	out            chan packet // frames waiting to be written to this client
	done           chan struct{}
	once           sync.Once
	ping, pongWait time.Duration

	// In glisten alone: what this client may still send.
	rate, burst, tokens float64
	filled              time.Time
	flooded             int
	lastFloodLog        time.Time

	// In the hub's Run alone.
	pending      int          // its requests awaiting an answer
	ticket       *auth.Ticket // a panel's: whom it acts for, and how far
	lastRollCall time.Time
	drops        int
	lastDropLog  time.Time
	lost         int // frames for it that found its queue full
	lastLostLog  time.Time
}

// take is what became of a frame offered to a client.
type take int

const (
	queued take = iota
	behind      // its queue is full: the frame is lost, the client kept
	shut        // it has closed
)

// ticketAt is the panel's ticket if it is still good at now.
func (s *shard) ticketAt(now time.Time) *auth.Ticket {
	if s.ticket == nil || !now.Before(s.ticket.Expires) {
		return nil
	}
	return s.ticket
}

func newShard(conn *ws.Conn, income chan<- packet, id Identity, cert Cert, opt Options) *shard {
	s := &shard{conn: conn, hub: income, id: id, cert: cert,
		out: make(chan packet, outboxSize), done: make(chan struct{}),
		ping: opt.Ping, pongWait: opt.PongWait,
		rate: opt.Rate, burst: float64(opt.Burst), tokens: float64(opt.Burst), filled: time.Now()}
	go s.write()
	return s
}

// glisten reads this client's frames. A client silent for longer than
// pongWait — not even answering the pings write sends — is gone, and its
// connection is dropped rather than left holding a place.
func (s *shard) glisten() {
	defer s.close()
	s.conn.SetReadDeadline(time.Now().Add(s.pongWait))
	s.conn.SetPongHandler(func(string) error { return s.conn.SetReadDeadline(time.Now().Add(s.pongWait)) })
	for {
		kind, pay, err := s.conn.ReadMessage()
		if err != nil {
			s.readFailed(err)
			break
		}
		s.conn.SetReadDeadline(time.Now().Add(s.pongWait))
		if !s.allow(time.Now()) {
			s.flooding()
			continue
		}
		s.hub <- packet{kind: kind, pay: pay, from: s}
	}
	if s.onClose != nil {
		s.onClose(s)
	}
	log.Info("LEFT", "cn", s.cert.CN, "addr", s.conn.RemoteAddr())
}

func (s *shard) readFailed(err error) {
	var ne net.Error
	switch {
	case errors.Is(err, ws.ErrReadLimit):
		log.Warn("FRAME TOO LARGE, dropping client", "cn", s.cert.CN, "limit", monolink.MaxFrame)
	case errors.As(err, &ne) && ne.Timeout():
		log.Warn("SILENT, dropping client", "cn", s.cert.CN, "for", s.pongWait)
	}
}

// allow takes one frame from this client's allowance, refilled at its rate.
func (s *shard) allow(now time.Time) bool {
	s.tokens = min(s.burst, s.tokens+now.Sub(s.filled).Seconds()*s.rate)
	s.filled = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

func (s *shard) flooding() {
	s.flooded++
	if now := time.Now(); now.Sub(s.lastFloodLog) >= logEvery {
		log.Warn("TOO FAST, frames dropped", "cn", s.cert.CN, "dropped", s.flooded)
		s.flooded, s.lastFloodLog = 0, now
	}
}

// dropped notes a frame the hub refused. Only its verb, noun and addresses
// are logged, and only once the frame has parsed as v2, whose fields are
// checked and bounded: its arguments may be a token, a signature or a
// message, and an unparsed frame's fields are whatever its sender chose.
func (s *shard) dropped(why string, m *monolink.Message) {
	s.drops++
	now := time.Now()
	if now.Sub(s.lastDropLog) < logEvery {
		return
	}
	attrs := []any{"cn", s.cert.CN, "why", why, "dropped", s.drops}
	if m != nil {
		attrs = append(attrs, "from", m.From, "to", m.To, "verb", m.Verb, "noun", m.Noun)
	}
	log.Warn("DROPPED", attrs...)
	s.drops, s.lastDropLog = 0, now
}

// write sends this client its frames in order, each with a deadline, and a
// ping now and then. It runs apart from the hub, so a slow client costs
// only itself.
func (s *shard) write() {
	ping := time.NewTicker(s.ping)
	defer ping.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ping.C:
			if err := s.conn.WriteControl(ws.PingMessage, nil, time.Now().Add(writeTimeout)); err != nil {
				s.close()
				return
			}
		case pack := <-s.out:
			s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := s.conn.WriteMessage(pack.kind, pack.pay); err != nil {
				log.Warn("Write failed, dropping client", "cn", s.cert.CN, "addr", s.conn.RemoteAddr(), "err", err)
				s.close()
				return
			}
		}
	}
}

// absorb queues a frame for this client without waiting, so no client can
// stall the hub. A full queue loses the frame, not the client: the client may
// only be slow, and one that has stopped reading — ukaz once did, its network
// task stuck — is caught by write's deadline, which drops it. Dropping the
// client on a full queue would let anyone who sends fast enough push a node
// off the bus.
func (s *shard) absorb(pack packet) take {
	select {
	case <-s.done:
		return shut
	case s.out <- pack:
		return queued
	default:
		return behind
	}
}

// fellBehind notes a frame lost to a full queue, logged at most once a
// second.
func (s *shard) fellBehind() {
	s.lost++
	if now := time.Now(); now.Sub(s.lastLostLog) >= logEvery {
		log.Warn("BEHIND, frames for it lost", "cn", s.cert.CN, "lost", s.lost)
		s.lost, s.lastLostLog = 0, now
	}
}

func (s *shard) close() {
	s.once.Do(func() {
		close(s.done)
		s.conn.Close()
	})
}
