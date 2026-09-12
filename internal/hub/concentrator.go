package hub

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	log "log/slog"
	"math/big"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	ws "github.com/gorilla/websocket"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"

	"concentrator/internal/syncmap"
)

// The hub. SECURITY.txt §5: it is no longer blind. Every connection is a
// certificate the policy names, issued by the one CA that issues the bus's;
// a node has one connection, and a node's name one certificate. Every frame
// is read, only v2 is carried, and what goes on is exactly the bytes that
// were checked. A frame goes only where it is addressed, a reply only to the
// connection that asked, an announcement only to those it concerns.
//
// A panel is held to its person's grants. Until a ticket signed by marshal is
// on its connection it may do nothing but sign in; after, every frame names
// the person, it may send what the ticket's grants cover, and it hears only
// the announcements they cover. Ending a person's tickets ends them for good:
// shown again, they are refused.
//
// Nothing a frame carries is ever logged — its verb, noun and addresses at
// most, never its arguments, which hold session tokens, signatures and
// messages.

const (
	maxPanels     = 1024                  // panel connections, all told; a node is never refused for room
	maxPerPanel   = 64                    // connections one panel's certificate may hold: portal's browsers
	replyTTL      = time.Minute           // how long an answer is awaited
	maxPending    = 256                   // requests one connection may have outstanding
	readLimit     = monolink.MaxFrame + 2 // a frame, and a line ending some senders add
	rollCallEvery = 5 * time.Second       // how often one panel connection may call the roll
	rollCallRate  = 1.0                   // roll calls a second, from every panel together
	rollCallBurst = 10.0
)

// Options tunes a Hub; a zero value takes the default.
type Options struct {
	Rate      float64           // frames a second one connection may send, sustained (100)
	Burst     int               // frames it may send at once (200)
	TicketKey ed25519.PublicKey // marshal's, to check tickets with; none, and no panel gets past signing in
	Ping      time.Duration     // how often each connection is pinged (30 s)
	PongWait  time.Duration     // how long a connection may be silent before it is dropped (75 s)
	Sweep     time.Duration     // how often what has lapsed is cleared away (10 s)
	// What all the connections of one panel's certificate may send together
	// — portal's, one per browser — beyond each one's own rate (500 a
	// second, 1000 at once). Nodes hold one connection each, so with this
	// the bus as a whole has a bound.
	PanelRate  float64
	PanelBurst int
}

// budget is an allowance that refills: what a sender may still send.
type budget struct {
	left float64
	at   time.Time
}

// Cert is what the TLS handshake proved about a connection's certificate.
type Cert struct {
	CN      string
	Serial  *big.Int
	Expires time.Time
}

// Identify names the certificate a connection came with.
type Identify func(*http.Request) (Cert, bool)

// TLSIdentity is a connection's client certificate, as the handshake
// verified it against the one CA ClientCAPool admits: issued by that CA
// directly, with nothing between, or it is not taken.
func TLSIdentity(r *http.Request) (Cert, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return Cert{}, false
	}
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) != 2 {
			return Cert{}, false
		}
	}
	c := r.TLS.PeerCertificates[0]
	return Cert{CN: c.Subject.CommonName, Serial: c.SerialNumber, Expires: c.NotAfter}, true
}

// ClientCAPool is the one CA whose certificates may join the bus. A
// certificate's name is all the policy goes by, so any CA trusted here could
// issue one named marshal: the file holds the CA that issues the bus's
// certificates and nothing else — not the root above it — and that CA may
// sign no CA below it (pathlen:0).
func ClientCAPool(pemBytes []byte) (*x509.CertPool, *x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := pemBytes; ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, c)
	}
	switch {
	case len(certs) != 1:
		return nil, nil, fmt.Errorf("%d certificates: the client CA file holds the one CA that issues the bus's certificates, alone", len(certs))
	case !certs[0].BasicConstraintsValid || !certs[0].IsCA:
		return nil, nil, fmt.Errorf("%s is not a CA", certs[0].Subject)
	case certs[0].MaxPathLen != 0 || !certs[0].MaxPathLenZero:
		return nil, nil, fmt.Errorf("%s may sign CAs below it, any of which could issue a certificate named marshal; the issuing CA is pathlen:0", certs[0].Subject)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certs[0])
	return pool, certs[0], nil
}

type packet struct {
	kind int
	pay  []byte
	from *shard
}

// replyKey is the answer a request awaits: from whom, with which id, to
// which address.
type replyKey struct{ responder, id, to string }

type awaited struct {
	shard   *shard
	expires time.Time
}

type Hub struct {
	upd      ws.Upgrader
	identify Identify
	opt      Options
	started  time.Time
	policy   atomic.Pointer[Policy]
	shards   *syncmap.Map[*shard, struct{}]
	income   chan packet
	admit    sync.Mutex // Accept and Reload: a connection is kept only under the policy in force

	// Touched by Run alone.
	pending     map[replyKey]awaited
	ended       map[string]time.Time // by person: their tickets issued up to then are void
	rollTokens  float64
	rollFilled  time.Time
	panelBudget map[string]*budget // by panel certificate: what its connections together may still send
}

func New(p *Policy, identify Identify, opt Options) *Hub {
	if opt.Rate <= 0 {
		opt.Rate = 100
	}
	if opt.Burst <= 0 {
		opt.Burst = 200
	}
	if opt.Ping <= 0 {
		opt.Ping = 30 * time.Second
	}
	if opt.PongWait <= 0 {
		opt.PongWait = 75 * time.Second
	}
	if opt.Sweep <= 0 {
		opt.Sweep = 10 * time.Second
	}
	if opt.PanelRate <= 0 {
		opt.PanelRate = 500
	}
	if opt.PanelBurst <= 0 {
		opt.PanelBurst = 1000
	}
	now := time.Now()
	h := &Hub{
		upd: ws.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			// No node is a browser. A request carrying an Origin is a web page's.
			CheckOrigin: func(r *http.Request) bool { return r.Header.Get("Origin") == "" },
		},
		identify:    identify,
		opt:         opt,
		started:     now,
		shards:      syncmap.New[*shard, struct{}](),
		income:      make(chan packet, 256),
		pending:     map[replyKey]awaited{},
		ended:       map[string]time.Time{},
		rollTokens:  rollCallBurst,
		rollFilled:  now,
		panelBudget: map[string]*budget{},
	}
	h.policy.Store(p)
	return h
}

// Reload takes a new policy, and drops every connection it no longer admits
// as it was admitted. Those it still admits reconnect under the new one.
func (h *Hub) Reload(p *Policy) {
	h.admit.Lock()
	defer h.admit.Unlock()
	h.policy.Store(p)
	for _, s := range h.shards.Keys() {
		id, ok := p.Lookup(s.cert.CN)
		if !ok || p.Revoked(s.cert.Serial) || !id.equal(s.id) {
			log.Warn("NO LONGER ADMITTED AS IT WAS", "cn", s.cert.CN, "addr", s.conn.RemoteAddr())
			s.close()
		}
	}
}

func (h *Hub) Accept(w http.ResponseWriter, r *http.Request) {
	c, ok := h.identify(r)
	if !ok {
		refuse(w, r, "", "no certificate from the bus's CA")
		return
	}
	if r.Header.Get("Origin") != "" {
		refuse(w, r, c.CN, "a request from a web page")
		return
	}
	h.admit.Lock()
	id, why := h.room(c, r.RemoteAddr, time.Now())
	h.admit.Unlock()
	if why != "" {
		refuse(w, r, c.CN, why)
		return
	}
	conn, err := h.upd.Upgrade(w, r, nil)
	if err != nil {
		log.Warn("Failed to upgrade connection", "cn", c.CN, "err", err)
		return
	}
	conn.SetReadLimit(readLimit)

	// Again, under the lock Reload takes: while the connection was upgraded
	// the policy may have changed, or another connection of this node come.
	h.admit.Lock()
	again, why := h.room(c, r.RemoteAddr, time.Now())
	if why == "" && !again.equal(id) {
		why = "the policy changed as it joined"
	}
	if why != "" {
		h.admit.Unlock()
		log.Warn("REFUSED", "cn", c.CN, "addr", r.RemoteAddr, "why", why)
		conn.Close()
		return
	}
	s := newShard(conn, h.income, id, c, h.opt)
	s.onClose = func(s2 *shard) { h.shards.Delete(s2) }
	h.shards.Store(s, struct{}{})
	h.admit.Unlock()
	log.Info("JOINED", "cn", c.CN, "as", id.Node, "addr", conn.RemoteAddr())
	go s.glisten()
}

// room says why the certificate c may not join now, or "" and what it may
// be. Called with h.admit held.
func (h *Hub) room(c Cert, addr string, now time.Time) (Identity, string) {
	p := h.policy.Load()
	if p.Revoked(c.Serial) {
		return Identity{}, "certificate revoked"
	}
	id, ok := p.Lookup(c.CN)
	if !ok {
		return Identity{}, "not in the policy"
	}
	if !c.Expires.IsZero() && !now.Before(c.Expires) {
		return Identity{}, "certificate expired"
	}
	mine, panels := 0, 0
	var first *shard
	for _, s := range h.shards.Keys() {
		if s.cert.CN == c.CN {
			mine++
			first = s
		}
		if s.id.Panel {
			panels++
		}
	}
	switch {
	case !id.Panel && mine > 0:
		// Either the node restarted and its old connection has not yet gone
		// silent long enough to be dropped — it will be — or someone else
		// holds a copy of its key.
		log.Error("A SECOND CONNECTION AS A NODE, refused — is a copy of its key in use?",
			"cn", c.CN, "as", id.Node, "new", addr, "connected", first.conn.RemoteAddr())
		return id, "a node has one connection"
	case id.Panel && mine >= maxPerPanel:
		return id, "as many connections as one panel may hold"
	case id.Panel && panels >= maxPanels:
		return id, "hub full"
	}
	return id, ""
}

func refuse(w http.ResponseWriter, r *http.Request, cn, why string) {
	log.Warn("REFUSED", "cn", cn, "addr", r.RemoteAddr, "why", why)
	http.Error(w, "forbidden", http.StatusForbidden)
}

func (h *Hub) Run() {
	tick := time.NewTicker(h.opt.Sweep)
	defer tick.Stop()
	for {
		select {
		case pack, ok := <-h.income:
			if !ok {
				return
			}
			h.route(pack, time.Now())
		case now := <-tick.C:
			h.sweep(now)
		}
	}
}

func isReply(verb string) bool { return verb == monolink.VerbOK || verb == monolink.VerbErr }

// frame is the one frame in pay: a line ending, as some senders add, taken
// off, and nothing else around it. What is checked is what is passed on,
// byte for byte, so no receiver can read it as anything else.
func frame(pay []byte) ([]byte, bool) {
	pay = bytes.TrimSuffix(pay, []byte("\n"))
	pay = bytes.TrimSuffix(pay, []byte("\r"))
	return pay, len(pay) > 0 && len(bytes.TrimSpace(pay)) == len(pay)
}

// route decides where one frame goes, if anywhere.
func (h *Hub) route(pack packet, now time.Time) {
	from := pack.from
	if pack.kind != ws.TextMessage {
		from.dropped("not a text frame", nil)
		return
	}
	raw, ok := frame(pack.pay)
	if !ok {
		from.dropped("space around the frame", nil)
		return
	}
	// v1 carries no ids, cannot be told a reply from a stray, and its sender
	// is whatever its last field says: the bus has moved to v2 (SPEC §44).
	if raw[0] < '0' || raw[0] > '9' {
		from.dropped("v1; the bus carries v2 only", nil)
		return
	}
	m, err := monolink.Parse(string(raw))
	if err != nil {
		from.dropped("not a frame", nil)
		return
	}
	pack.pay = raw

	// Identity: a connection speaks as its own node; a panel also as the
	// person its ticket names, and as nobody else.
	sender, err := monolink.ParseAddress(m.From)
	if err != nil || sender.Bubble != "" || sender.Node != from.id.Node {
		from.dropped("speaks as someone else", &m)
		return
	}
	tk := from.ticketAt(now)
	if sender.Actor != "" && (!from.id.Panel || tk == nil || sender.Actor != tk.Person) {
		from.dropped("speaks as someone else", &m)
		return
	}
	// A panel's certificate may hold many connections, each with its own
	// rate; together they have one more, so that no certificate can take the
	// hub's whole attention.
	if from.id.Panel && !h.panelAllows(from.cert.CN, now) {
		from.dropped("its certificate's connections together send too fast", &m)
		return
	}
	to, err := monolink.ParseAddress(m.To)
	if err != nil || to.Bubble != "" {
		from.dropped("no such address", &m)
		return
	}
	if to.Node == auth.Hub {
		h.serve(from, m, now)
		return
	}
	// A panel acting for someone acts for them in everything, so that no
	// node is asked by nobody: only renewing its ticket goes as the panel.
	if tk != nil && sender.Actor == "" && to.Node != auth.Node {
		from.dropped("names no person, on a panel acting for one", &m)
		return
	}

	// A reply goes to whoever asked, by the request's id, and nowhere else.
	if isReply(m.Verb) {
		if from.id.Panel {
			from.dropped("a panel answers nothing", &m)
			return
		}
		k := replyKey{responder: sender.Node, id: m.ID, to: m.To}
		a, ok := h.pending[k]
		if !ok || now.After(a.expires) {
			from.dropped("a reply nobody asked for", &m)
			return
		}
		h.forget(k, a)
		h.deliver(a.shard, pack)
		return
	}

	// A node's announcements of its own go out; anything else must be
	// something this connection may send.
	announce := !from.id.Panel && to.Node == monolink.All &&
		(m.Verb == monolink.VerbPub || m.Verb == monolink.VerbReg)
	if !announce {
		if why := h.refusal(from, tk, to.Node, &m, now); why != "" {
			from.dropped(why, &m)
			return
		}
	}
	if to.Node == monolink.All {
		h.broadcast(pack, from, &m, sender.Node, now)
		return
	}
	k := replyKey{responder: to.Node, id: m.ID, to: m.From}
	if a, ok := h.pending[k]; ok && a.shard != from && now.Before(a.expires) {
		from.dropped("request id in use", &m)
		return
	}
	if from.pending >= maxPending {
		from.dropped("too many requests outstanding", &m)
		return
	}
	if a, ok := h.pending[k]; ok {
		h.forget(k, a)
	}
	h.pending[k] = awaited{shard: from, expires: now.Add(replyTTL)}
	from.pending++
	if h.deliverTo(to.Node, pack, from, &m, sender.Node, now) {
		return
	}
	// The addressee is there but so far behind that its queue is full. The
	// asker is told at once rather than left to wait out its timeout — in
	// the addressee's name, as a reply must be to meet its request.
	h.forget(k, h.pending[k])
	busy, err := monolink.Message{Version: monolink.V2, ID: m.ID, From: to.Node, To: m.From,
		Verb: monolink.VerbErr, Noun: monolink.CodeBusy, Args: []string{to.Node + " is behind; try again"}}.Marshal()
	if err == nil {
		h.deliver(from, packet{kind: ws.TextMessage, pay: []byte(busy)})
	}
}

// panelAllows spends one frame of what the connections of panel certificate
// cn may send together. Called from Run alone.
func (h *Hub) panelAllows(cn string, now time.Time) bool {
	b := h.panelBudget[cn]
	if b == nil {
		b = &budget{left: float64(h.opt.PanelBurst), at: now}
		h.panelBudget[cn] = b
	}
	b.left = min(float64(h.opt.PanelBurst), b.left+now.Sub(b.at).Seconds()*h.opt.PanelRate)
	b.at = now
	if b.left < 1 {
		return false
	}
	b.left--
	return true
}

// refusal says why from may not send m to node to, or "" if it may. A node
// is held to its policy line; a panel to its ticket's grants, and without
// a ticket to signing in.
func (h *Hub) refusal(from *shard, tk *auth.Ticket, to string, m *monolink.Message, now time.Time) string {
	if !from.id.Panel {
		if from.id.may(auth.Action(to, m.Verb, m.Noun)) {
			return ""
		}
		return "not permitted"
	}
	switch {
	case to == auth.Node:
		return "" // signing in happens here, and marshal judges its own requests
	case tk == nil:
		return "sign in first"
	case m.Verb == monolink.VerbPing:
		if to != monolink.All && m.Noun == monolink.VerbPing && len(m.Args) == 0 {
			return "" // are you there — which asks nothing else of a node
		}
		return "not permitted"
	case to == monolink.All:
		if m.Verb == monolink.VerbGet && m.Noun == monolink.VerbReg && len(m.Args) == 0 {
			return h.rollCall(from, now)
		}
		return "not permitted"
	case auth.Allowed(tk.Grants, auth.Action(to, m.Verb, m.Noun)):
		return ""
	}
	return "not permitted"
}

// rollCall rations ALL:GET:REG from panels: each makes every node announce
// everything it has to everyone who may hear it.
func (h *Hub) rollCall(from *shard, now time.Time) string {
	if !from.lastRollCall.IsZero() && now.Sub(from.lastRollCall) < rollCallEvery {
		return "the roll was called a moment ago"
	}
	h.rollTokens = min(rollCallBurst, h.rollTokens+now.Sub(h.rollFilled).Seconds()*rollCallRate)
	h.rollFilled = now
	if h.rollTokens < 1 {
		return "too many roll calls"
	}
	h.rollTokens--
	from.lastRollCall = now
	return ""
}

// hears reports whether s is to be given m, which node from sent. A node
// is given what is asked of it, and the announcements its policy line
// lists; a panel only the announcements its ticket covers.
func (s *shard) hears(m *monolink.Message, from string, now time.Time) bool {
	announcement := m.Verb == monolink.VerbPub || m.Verb == monolink.VerbReg || m.Verb == monolink.VerbFire
	if !s.id.Panel {
		return !announcement || s.id.hears(auth.Action(from, m.Verb, m.Noun))
	}
	tk := s.ticketAt(now)
	if tk == nil {
		return false
	}
	switch m.Verb {
	case monolink.VerbPub:
		return auth.Allowed(tk.Grants, auth.Action(from, monolink.VerbGet, m.Noun))
	case monolink.VerbReg:
		return true // what exists is no secret; what it is, is
	case monolink.VerbFire:
		return auth.Allowed(tk.Grants, auth.Action(from, monolink.VerbFire, m.Noun))
	}
	return false // a panel serves no requests
}

// serve answers what is asked of the hub itself: tickets.
func (h *Hub) serve(from *shard, m monolink.Message, now time.Time) {
	// Replies and announcements are never answered (SPEC §18), the hub's own
	// no more than a node's.
	switch m.Verb {
	case monolink.VerbOK, monolink.VerbErr, monolink.VerbPong, monolink.VerbPub, monolink.VerbReg, monolink.VerbFire:
		from.dropped("the hub answers no reply or announcement", &m)
		return
	}
	reply := func(verb, noun string, args ...string) {
		wire, err := monolink.Message{Version: monolink.V2, ID: m.ID, From: auth.Hub, To: m.From,
			Verb: verb, Noun: noun, Args: args}.Marshal()
		if err == nil {
			h.deliver(from, packet{kind: ws.TextMessage, pay: []byte(wire)})
		}
	}
	switch m.Verb + ":" + m.Noun {
	case "SET:TICKET":
		if !from.id.Panel {
			reply(monolink.VerbErr, monolink.CodeDenied, "only a panel holds a ticket")
			return
		}
		if h.opt.TicketKey == nil {
			reply(monolink.VerbErr, monolink.CodeState, "the hub has no key to check tickets with")
			return
		}
		t, err := auth.ParseTicket(m.Args)
		if err != nil {
			reply(monolink.VerbErr, monolink.CodeArg, err.Error())
			return
		}
		why := ""
		switch cut, cutOK := h.ended[t.Person]; {
		case t.Panel != from.id.Node:
			why = "not this panel's ticket"
		case t.Check(h.opt.TicketKey, now) != nil:
			why = t.Check(h.opt.TicketKey, now).Error()
		case t.Issued.Before(h.started):
			why = "issued before this hub started; ask marshal for a new one"
		case cutOK && !t.Issued.After(cut):
			why = "ended; ask marshal for a new one"
		}
		if why != "" {
			from.dropped("a ticket refused: "+why, &m)
			reply(monolink.VerbErr, monolink.CodeDenied, why)
			return
		}
		from.ticket = &t
		log.Info("TICKET", "cn", from.cert.CN, "person", t.Person, "until", t.Expires.Format(time.TimeOnly))
		reply(monolink.VerbOK, auth.NounTicket, strconv.FormatInt(t.Expires.Unix(), 10))

	case "STOP:TICKET":
		from.ticket = nil
		reply(monolink.VerbOK, auth.NounTicket)

	case "STOP:TICKETS":
		if from.id.Node != auth.Node {
			from.dropped("only marshal ends tickets", &m)
			reply(monolink.VerbErr, monolink.CodeDenied, "only marshal ends tickets")
			return
		}
		if len(m.Args) < 1 || len(m.Args) > 2 || !auth.ValidName(m.Args[0]) {
			reply(monolink.VerbErr, monolink.CodeArg, "STOP:TICKETS:<person>[:<since>]")
			return
		}
		person, since := m.Args[0], now
		if len(m.Args) == 2 {
			t, err := auth.ParseTimeArg(m.Args[1])
			if err != nil || t.After(now.Add(auth.ClockSkew)) {
				reply(monolink.VerbErr, monolink.CodeArg, "not a time in the past")
				return
			}
			since = t
		}
		if since.After(h.ended[person]) {
			h.ended[person] = since
		}
		n := 0
		for _, s := range h.shards.Keys() {
			if s.ticket != nil && s.ticket.Person == person && !s.ticket.Issued.After(since) {
				s.close() // its panel reconnects, and asks marshal for a ticket signed after
				n++
			}
		}
		log.Info("TICKETS ENDED", "person", person, "connections", n)
		reply(monolink.VerbOK, auth.NounTickets, strconv.Itoa(n))

	default:
		reply(monolink.VerbErr, monolink.CodeNoun, "the hub knows only tickets")
	}
}

func (h *Hub) forget(k replyKey, a awaited) {
	delete(h.pending, k)
	a.shard.pending--
}

// sweep clears away what has lapsed: requests whose answers never came, the
// record of tickets ended long enough ago that every one of them has
// expired, and connections whose certificates have.
func (h *Hub) sweep(now time.Time) {
	for k, a := range h.pending {
		if now.After(a.expires) {
			h.forget(k, a)
		}
	}
	for person, since := range h.ended {
		if now.Sub(since) > auth.TicketTTL+auth.ClockSkew {
			delete(h.ended, person)
		}
	}
	for _, s := range h.shards.Keys() {
		if !s.cert.Expires.IsZero() && !now.Before(s.cert.Expires) {
			log.Warn("CERTIFICATE EXPIRED, dropping client", "cn", s.cert.CN, "addr", s.conn.RemoteAddr())
			s.close()
		}
	}
}

func (h *Hub) deliver(s *shard, pack packet) take {
	t := s.absorb(pack)
	switch t {
	case shut:
		h.shards.Delete(s)
	case behind:
		s.fellBehind()
	}
	return t
}

// deliverTo gives a frame to the node it is addressed to. It reports false
// only when that node is connected but so far behind that the frame could
// not be queued.
func (h *Hub) deliverTo(node string, pack packet, from *shard, m *monolink.Message, sender string, now time.Time) bool {
	queued := true
	for _, s := range h.shards.Keys() {
		if s != from && s.id.Node == node && s.hears(m, sender, now) && h.deliver(s, pack) == behind {
			queued = false
		}
	}
	return queued
}

func (h *Hub) broadcast(pack packet, from *shard, m *monolink.Message, sender string, now time.Time) {
	for _, s := range h.shards.Keys() {
		if s != from && s.hears(m, sender, now) {
			h.deliver(s, pack)
		}
	}
}
