package hub

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	ws "github.com/gorilla/websocket"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

// marshal's key, as the hub knows it; tests sign tickets with it.
var ticketPub, ticketPriv, _ = ed25519.GenerateKey(rand.Reader)

const testPolicy = `
# cn        node      kind    may send                                hears
achtung     ACHTUNG   node    ALL.FIRE.* VERTEX.SET.BUZZ.STATE
governor    GOVERNOR  node
marshal     MARSHAL   node    UKAZ.PRINT.*
synapse     SYNAPSE   node    MARSHAL.GET.PEOPLE                      hears MARSHAL.PUB.PEOPLE
ukaz        UKAZ      node    GOVERNOR.GET.* ACHTUNG.GET.UPTIME       hears ACHTUNG.FIRE.* GOVERNOR.PUB.*
vertex      VERTEX    node
portal      MONOWEB   panel
monoview    MONOVIEW  panel
`

// nodes are the policy's nodes, which the roll call reaches.
var nodes = []string{"achtung", "governor", "marshal", "synapse", "ukaz", "vertex"}

// hearing is the policy with achtung hearing everything announced, for the
// tests that measure what one node is given.
var hearing = strings.Replace(testPolicy, "VERTEX.SET.BUZZ.STATE", "VERTEX.SET.BUZZ.STATE hears *", 1)

func policy(t *testing.T, text, revoked string) *Policy {
	t.Helper()
	p, err := ParsePolicy(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.ParseRevoked(strings.NewReader(revoked)); err != nil {
		t.Fatal(err)
	}
	return p
}

// queryIdentity stands in for the TLS handshake: the test names the
// certificate in the URL. TestTLSIdentity checks the real thing.
func queryIdentity(r *http.Request) (Cert, bool) {
	q := r.URL.Query()
	c := Cert{CN: q.Get("cn")}
	c.Serial, _ = new(big.Int).SetString(q.Get("serial"), 16)
	if ms, err := strconv.ParseInt(q.Get("exp"), 10, 64); err == nil {
		c.Expires = time.UnixMilli(ms)
	}
	return c, c.CN != ""
}

func start(t *testing.T, p *Policy, opt Options) (string, *Hub) {
	t.Helper()
	if opt.TicketKey == nil {
		opt.TicketKey = ticketPub
	}
	h := New(p, queryIdentity, opt)
	go h.Run()
	srv := httptest.NewServer(http.HandlerFunc(h.Accept))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), h
}

// peer is one connection, read on its own goroutine: a read that times out
// breaks a websocket for good, so waiting for silence must not read.
type peer struct {
	c  *ws.Conn
	in chan string // closed when the connection is
}

func wrap(t *testing.T, c *ws.Conn) *peer {
	t.Helper()
	p := &peer{c: c, in: make(chan string, 8192)}
	go func() {
		defer close(p.in)
		for {
			_, m, err := c.ReadMessage()
			if err != nil {
				return
			}
			p.in <- string(m)
		}
	}()
	t.Cleanup(func() { c.Close() })
	return p
}

func dial(url, query string, header http.Header) (*ws.Conn, error) {
	c, _, err := ws.DefaultDialer.Dial(url+"?"+query, header)
	return c, err
}

func dialRaw(t *testing.T, url, query string) *ws.Conn {
	t.Helper()
	c, err := dial(url, query, nil)
	if err != nil {
		t.Fatalf("%s could not join: %v", query, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func join(t *testing.T, url, cn string) *peer { return wrap(t, dialRaw(t, url, "cn="+cn)) }

// bus is a hub with every certificate of the test policy connected.
func bus(t *testing.T) (string, map[string]*peer) {
	t.Helper()
	url, _ := start(t, policy(t, testPolicy, ""), Options{})
	c := map[string]*peer{}
	for _, cn := range append(append([]string{}, nodes...), "portal", "monoview") {
		c[cn] = join(t, url, cn)
	}
	time.Sleep(50 * time.Millisecond) // every connection registered
	return url, c
}

func send(t *testing.T, p *peer, frame string) {
	t.Helper()
	if err := p.c.WriteMessage(ws.TextMessage, []byte(frame)); err != nil {
		t.Fatal(err)
	}
}

func expect(t *testing.T, p *peer, want string) {
	t.Helper()
	select {
	case got, ok := <-p.in:
		if !ok || got != want {
			t.Fatalf("expected %q, got %q (connected: %v)", want, got, ok)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("expected %q, got nothing", want)
	}
}

func next(t *testing.T, p *peer) string {
	t.Helper()
	select {
	case got := <-p.in:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("no answer")
		return ""
	}
}

// nothing fails the test if p is given a frame in the next moment.
func nothing(t *testing.T, p *peer, who string) {
	t.Helper()
	select {
	case got, ok := <-p.in:
		if ok {
			t.Fatalf("%s was given %q", who, got)
		}
	case <-time.After(150 * time.Millisecond):
	}
}

// gone fails the test unless p's connection is closed soon.
func gone(t *testing.T, p *peer, who string) {
	t.Helper()
	timeout := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-p.in:
			if !ok {
				return
			}
		case <-timeout:
			t.Fatalf("%s is still connected", who)
		}
	}
}

func quiet(t *testing.T, c map[string]*peer, except ...string) {
	t.Helper()
	for cn, conn := range c {
		skip := false
		for _, e := range except {
			skip = skip || e == cn
		}
		if !skip {
			nothing(t, conn, cn)
		}
	}
}

// show shows the hub tk on p's connection, and returns its answer.
func show(t *testing.T, p *peer, from string, tk auth.Ticket) string {
	t.Helper()
	frame, err := monolink.Message{Version: monolink.V2, ID: "tk", From: from, To: auth.Hub,
		Verb: monolink.VerbSet, Noun: auth.NounTicket, Args: tk.Args()}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	send(t, p, frame)
	return next(t, p)
}

// present shows the hub a ticket signed now by marshal's key, and expects it
// taken.
func present(t *testing.T, p *peer, panel, person string, ttl time.Duration, grants ...string) auth.Ticket {
	t.Helper()
	tk := auth.Ticket{Person: person, Panel: panel, Expires: time.Now().Add(ttl), Grants: grants}.Sign(ticketPriv)
	if got, want := show(t, p, panel, tk), "2:tk:CONCENTRATOR:"+panel+":OK:TICKET:"+strconv.FormatInt(tk.Expires.Unix(), 10); got != want {
		t.Fatalf("presenting a ticket: %q, want %q", got, want)
	}
	return tk
}

func denied(t *testing.T, answer, what string) {
	t.Helper()
	if !strings.HasPrefix(answer, "2:tk:CONCENTRATOR:") || !strings.Contains(answer, ":ERR:DENIED") {
		t.Errorf("%s: %q", what, answer)
	}
}

// ─── who may join ────────────────────────────────────────────────────

func TestOnlyCertificatesInThePolicyJoin(t *testing.T) {
	url, _ := start(t, policy(t, testPolicy, "1F\n00:00:2a\n"), Options{})
	for _, q := range []string{"cn=eve", "", "cn=ukaz&serial=1f", "cn=ukaz&serial=2A"} {
		if c, err := dial(url, q, nil); err == nil {
			c.Close()
			t.Errorf("%q joined", q)
		}
	}
	if c, err := dial(url, "cn=ukaz&serial=20", nil); err != nil {
		t.Errorf("an unrevoked ukaz was refused: %v", err)
	} else {
		c.Close()
	}
}

func TestPolicyErrorsNameTheLine(t *testing.T) {
	for _, c := range []struct{ text, want string }{
		{"a  A  node\nb  B  robot", "line 2"},
		{"a  ALL  node", "not a node's name"},
		{"a  CONCENTRATOR  node", "not a node's name"},
		{"a  A.mzh  panel", "not a node's name"},
		{"a  A  node  VERTEX.:bad", "not a pattern"},
		{"a  A  node  hears  VERTEX.:bad", "not a pattern"},
		{"a  A  node\na  B  node", "listed twice"},
		{"a  A  node\nb  A  node", "one certificate a node"},
		{"a  A  panel\nb  A  panel", "one certificate a node"},
		{"a  A  panel  VERTEX.*", "a panel lists no patterns"},
		{"a  A", "line 1"},
	} {
		if _, err := ParsePolicy(strings.NewReader(c.text)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v, want %q", c.text, err, c.want)
		}
	}
	p := policy(t, testPolicy, "")
	if err := p.ParseRevoked(strings.NewReader("zz")); err == nil {
		t.Error("a revoked serial that is not hex was taken")
	}
	id, _ := p.Lookup("ukaz")
	if strings.Join(id.May, " ") != "GOVERNOR.GET.* ACHTUNG.GET.UPTIME" || strings.Join(id.Hears, " ") != "ACHTUNG.FIRE.* GOVERNOR.PUB.*" {
		t.Errorf("ukaz's line read as %+v", id)
	}
	if id, _ := p.Lookup("portal"); id.may("GOVERNOR.GET.EVENTS") {
		t.Error("a panel's line lets it send something")
	}
}

func TestTheExamplePolicyLoads(t *testing.T) {
	p, err := LoadPolicy("../../policy.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := p.Lookup("synapse"); !ok || !id.hears("MARSHAL.PUB.PEOPLE") || !id.may("MARSHAL.GET.PEOPLE") {
		t.Errorf("synapse's line read as %+v", id)
	}
	if id, ok := p.Lookup("vertex"); !ok || len(id.May) != 0 || len(id.Hears) != 0 {
		t.Errorf("vertex's line, with its comment, read as %+v", id)
	}
}

// A node's certificate holds one connection. A second is refused: it is the
// node restarted before its old connection went silent, or a copy of its key.
func TestANodeHasOneConnection(t *testing.T) {
	url, _ := start(t, policy(t, testPolicy, ""), Options{})
	first := join(t, url, "marshal")
	time.Sleep(30 * time.Millisecond)
	if c, err := dial(url, "cn=marshal", nil); err == nil {
		c.Close()
		t.Fatal("a second marshal joined")
	}
	send(t, first, "2:o1:MARSHAL:CONCENTRATOR:GET:CLIENTS")
	expect(t, first, "2:o1:CONCENTRATOR:MARSHAL:ERR:NOUN:the hub knows only tickets")

	first.c.Close()
	gone(t, first, "the first marshal")
	time.Sleep(50 * time.Millisecond)
	join(t, url, "marshal") // once it has gone, its node may join again
}

func TestAPanelHoldsSoManyConnectionsAndNoMore(t *testing.T) {
	url, _ := start(t, policy(t, testPolicy, ""), Options{})
	for i := 0; i < maxPerPanel; i++ {
		join(t, url, "portal")
	}
	time.Sleep(50 * time.Millisecond)
	if c, err := dial(url, "cn=portal", nil); err == nil {
		c.Close()
		t.Fatalf("portal held more than %d connections", maxPerPanel)
	}
	join(t, url, "governor") // and a node still finds room
}

func TestAWebPageCannotConnect(t *testing.T) {
	url, _ := start(t, policy(t, testPolicy, ""), Options{})
	if c, err := dial(url, "cn=portal", http.Header{"Origin": {"https://evil.example"}}); err == nil {
		c.Close()
		t.Fatal("a request from a web page joined")
	}
}

// ─── who may speak as whom ───────────────────────────────────────────

func TestANodeSpeaksOnlyAsItself(t *testing.T) {
	_, c := bus(t)
	send(t, c["governor"], "2:a1:MARSHAL:ALL:PUB:PEOPLE:eve")
	send(t, c["governor"], "2:a2:GOVERNOR.mzh:ALL:PUB:NEXT.DEADLINE:x")
	send(t, c["governor"], "rubbish")
	quiet(t, c)

	send(t, c["governor"], "2:a3:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x")
	expect(t, c["ukaz"], "2:a3:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x")
	quiet(t, c) // no other node hears governor; no panel without a ticket hears anything
}

func TestAPanelSpeaksForItsTicketsPerson(t *testing.T) {
	_, c := bus(t)
	present(t, c["monoview"], "MONOVIEW", "mzh", time.Minute, "GOVERNOR.GET.*")
	send(t, c["monoview"], "2:p1:MONOVIEW.mzh:GOVERNOR:GET:EVENTS")
	expect(t, c["governor"], "2:p1:MONOVIEW.mzh:GOVERNOR:GET:EVENTS")
	send(t, c["monoview"], "2:p2:MONOVIEW.dasha:GOVERNOR:GET:EVENTS") // not the ticket's person
	send(t, c["monoview"], "2:p3:MONOWEB.mzh:GOVERNOR:GET:EVENTS")    // not its panel
	quiet(t, c)
}

func TestWithoutATicketAPanelMayOnlySignIn(t *testing.T) {
	_, c := bus(t)
	send(t, c["portal"], "2:w1:MONOWEB:GOVERNOR:GET:EVENTS")
	send(t, c["portal"], "2:w2:MONOWEB.mzh:MARSHAL:GET:GRANTS:mzh") // a person, and no ticket
	send(t, c["portal"], "2:w3:MONOWEB:ALL:GET:REG")
	send(t, c["portal"], "2:w4:MONOWEB:VERTEX:PING:PING")
	quiet(t, c)
	send(t, c["portal"], "2:w5:MONOWEB:MARSHAL:AUTH:CHALLENGE")
	expect(t, c["marshal"], "2:w5:MONOWEB:MARSHAL:AUTH:CHALLENGE")
}

func TestATicketHoldsAPanelToItsGrants(t *testing.T) {
	_, c := bus(t)
	present(t, c["portal"], "MONOWEB", "dasha", time.Minute, "VERTEX.*", "GOVERNOR.GET.*")
	send(t, c["portal"], "2:g1:MONOWEB.dasha:GOVERNOR:NEW:EVENT:x:2026.09.12:10.00")
	send(t, c["portal"], "2:g2:MONOWEB.dasha:UKAZ:DO:PRINT.TEXT:hi")
	send(t, c["portal"], "2:g3:MONOWEB.dasha:ALL:FIRE:TIMER:x")
	send(t, c["portal"], "2:g4:MONOWEB.dasha:ALL:PUB:LAMP.STATE:ON") // a panel announces nothing
	send(t, c["portal"], "2:g5:MONOWEB:GOVERNOR:GET:EVENTS")         // acting for dasha, it names her
	send(t, c["portal"], "2:g6:MONOWEB.dasha:UKAZ:PING:DUMP")        // a ping asks nothing else
	send(t, c["portal"], "2:g7:MONOWEB.dasha:UKAZ:PING:PING:x")
	send(t, c["portal"], "2:g8:MONOWEB.dasha:ALL:PING:PING")
	quiet(t, c)
	send(t, c["portal"], "2:g9:MONOWEB.dasha:VERTEX:SET:LAMP.STATE:ON")
	expect(t, c["vertex"], "2:g9:MONOWEB.dasha:VERTEX:SET:LAMP.STATE:ON")
	send(t, c["portal"], "2:ga:MONOWEB.dasha:UKAZ:PING:PING")
	expect(t, c["ukaz"], "2:ga:MONOWEB.dasha:UKAZ:PING:PING")
	send(t, c["portal"], "2:gb:MONOWEB:MARSHAL:GET:TICKET:token") // renewing its ticket goes as the panel
	expect(t, c["marshal"], "2:gb:MONOWEB:MARSHAL:GET:TICKET:token")
}

// ─── who hears what ──────────────────────────────────────────────────

func TestAPanelHearsOnlyWhatItMayRead(t *testing.T) {
	_, c := bus(t)
	present(t, c["portal"], "MONOWEB", "dasha", time.Minute, "VERTEX.GET.*", "ACHTUNG.FIRE.TIMER")
	send(t, c["governor"], "2:h1:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x")
	send(t, c["achtung"], "2:h2:ACHTUNG:ALL:FIRE:ALARM:wake")
	nothing(t, c["portal"], "dasha, of what she may not read")
	send(t, c["vertex"], "2:h3:VERTEX:ALL:PUB:LAMP.STATE:ON")
	expect(t, c["portal"], "2:h3:VERTEX:ALL:PUB:LAMP.STATE:ON")
	send(t, c["governor"], "2:h4:GOVERNOR:ALL:REG:NODE:1:governor:v:4096")
	expect(t, c["portal"], "2:h4:GOVERNOR:ALL:REG:NODE:1:governor:v:4096")
	send(t, c["achtung"], "2:h5:ACHTUNG:ALL:FIRE:TIMER:tea")
	expect(t, c["portal"], "2:h5:ACHTUNG:ALL:FIRE:TIMER:tea")
	nothing(t, c["monoview"], "monoview, holding no ticket")
}

// A node is given what is asked of it, and of what is announced only what
// its line lists: nothing goes to a node that does not need it.
func TestANodeHearsOnlyWhatItsLineLists(t *testing.T) {
	_, c := bus(t)
	send(t, c["marshal"], "2:n1:MARSHAL:ALL:PUB:PEOPLE:dasha|mzh")
	expect(t, c["synapse"], "2:n1:MARSHAL:ALL:PUB:PEOPLE:dasha|mzh")
	send(t, c["achtung"], "2:n2:ACHTUNG:ALL:FIRE:TIMER:tea")
	expect(t, c["ukaz"], "2:n2:ACHTUNG:ALL:FIRE:TIMER:tea")
	send(t, c["synapse"], "2:n3:SYNAPSE:ALL:PUB:UNREAD.dasha:3")
	quiet(t, c) // nobody listed synapse's announcements

	present(t, c["monoview"], "MONOVIEW", "mzh", time.Minute, "*")
	send(t, c["monoview"], "2:n4:MONOVIEW.mzh:ALL:GET:REG")
	for _, cn := range nodes {
		expect(t, c[cn], "2:n4:MONOVIEW.mzh:ALL:GET:REG") // the roll call is put to every node
	}
	nothing(t, c["portal"], "a panel, which serves no requests")
}

// ─── tickets ─────────────────────────────────────────────────────────

func TestForgedAndStrayTicketsAreRefused(t *testing.T) {
	_, c := bus(t)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	soon := now.Add(time.Minute)
	sign := func(tk auth.Ticket) auth.Ticket { return tk.Sign(ticketPriv) }
	for what, try := range map[string]struct {
		p    *peer
		from string
		tk   auth.Ticket
	}{
		"another key's":           {c["portal"], "MONOWEB", auth.Ticket{Person: "mzh", Panel: "MONOWEB", Expires: soon, Grants: []string{"*"}}.Sign(otherKey)},
		"another panel's":         {c["monoview"], "MONOVIEW", sign(auth.Ticket{Person: "mzh", Panel: "MONOWEB", Expires: soon, Grants: []string{"*"}})},
		"expired":                 {c["portal"], "MONOWEB", sign(auth.Ticket{Person: "mzh", Panel: "MONOWEB", Issued: now.Add(-time.Minute), Expires: now.Add(-time.Second)})},
		"a node's":                {c["ukaz"], "UKAZ", sign(auth.Ticket{Person: "mzh", Panel: "UKAZ", Expires: soon, Grants: []string{"*"}})},
		"for a year":              {c["portal"], "MONOWEB", sign(auth.Ticket{Person: "mzh", Panel: "MONOWEB", Expires: now.AddDate(1, 0, 0), Grants: []string{"*"}})},
		"issued ahead":            {c["portal"], "MONOWEB", sign(auth.Ticket{Person: "mzh", Panel: "MONOWEB", Issued: now.Add(10 * time.Minute), Expires: now.Add(15 * time.Minute)})},
		"from before the hub was": {c["portal"], "MONOWEB", sign(auth.Ticket{Person: "mzh", Panel: "MONOWEB", Issued: now.Add(-2 * time.Minute), Expires: soon, Grants: []string{"*"}})},
	} {
		if try.p == c["ukaz"] {
			if got := show(t, try.p, try.from, try.tk); !strings.Contains(got, ":ERR:DENIED") {
				t.Errorf("%s: %q", what, got)
			}
			continue
		}
		denied(t, show(t, try.p, try.from, try.tk), what)
	}
	send(t, c["portal"], "2:f1:MONOWEB.mzh:VERTEX:SET:LAMP.STATE:ON")
	quiet(t, c)
}

// Ending a person's tickets ends them for good: the connections holding one
// are dropped, and the same ticket shown again on a new connection is
// refused. A ticket marshal signs after the change passes.
func TestAnEndedTicketCannotBeShownAgain(t *testing.T) {
	url, c := bus(t)
	mzh := join(t, url, "portal")
	time.Sleep(30 * time.Millisecond)
	old := present(t, c["portal"], "MONOWEB", "dasha", time.Minute, "*")
	present(t, mzh, "MONOWEB", "mzh", time.Minute, "*")

	send(t, c["ukaz"], "2:e1:UKAZ:CONCENTRATOR:STOP:TICKETS:dasha")
	expect(t, c["ukaz"], "2:e1:CONCENTRATOR:UKAZ:ERR:DENIED:only marshal ends tickets")
	nothing(t, c["portal"], "dasha's browser, still connected")

	since := time.Now()
	send(t, c["marshal"], "2:e2:MARSHAL:CONCENTRATOR:STOP:TICKETS:dasha:"+auth.TimeArg(since))
	expect(t, c["marshal"], "2:e2:CONCENTRATOR:MARSHAL:OK:TICKETS:1")
	gone(t, c["portal"], "dasha's browser")

	again := join(t, url, "portal") // it reconnects, and shows the ticket it had
	time.Sleep(30 * time.Millisecond)
	denied(t, show(t, again, "MONOWEB", old), "the ended ticket, shown again")
	send(t, again, "2:e3:MONOWEB.dasha:GOVERNOR:GET:EVENTS")
	nothing(t, c["governor"], "governor, asked by an ended ticket")

	fresh := auth.Ticket{Person: "dasha", Panel: "MONOWEB", Issued: since.Add(time.Millisecond),
		Expires: time.Now().Add(time.Minute), Grants: []string{"GOVERNOR.GET.*"}}.Sign(ticketPriv)
	if got := show(t, again, "MONOWEB", fresh); !strings.Contains(got, ":OK:TICKET:") {
		t.Fatalf("a ticket signed after the change: %q", got)
	}
	send(t, mzh, "2:e4:MONOWEB.mzh:GOVERNOR:GET:EVENTS")
	expect(t, c["governor"], "2:e4:MONOWEB.mzh:GOVERNOR:GET:EVENTS") // mzh's own ticket stands

	send(t, c["marshal"], "2:e5:MARSHAL:CONCENTRATOR:STOP:TICKETS:dasha:"+auth.TimeArg(time.Now().Add(time.Hour)))
	expect(t, c["marshal"], "2:e5:CONCENTRATOR:MARSHAL:ERR:ARG:not a time in the past")
}

func TestATicketLapsesAndCanBeDropped(t *testing.T) {
	_, c := bus(t)
	present(t, c["monoview"], "MONOVIEW", "mzh", 5*time.Second, "*")
	send(t, c["monoview"], "2:l1:MONOVIEW.mzh:GOVERNOR:GET:EVENTS")
	expect(t, c["governor"], "2:l1:MONOVIEW.mzh:GOVERNOR:GET:EVENTS")
	send(t, c["monoview"], "2:l2:MONOVIEW:CONCENTRATOR:STOP:TICKET")
	expect(t, c["monoview"], "2:l2:CONCENTRATOR:MONOVIEW:OK:TICKET")
	send(t, c["monoview"], "2:l3:MONOVIEW.mzh:GOVERNOR:GET:EVENTS")
	nothing(t, c["governor"], "governor, after the ticket was dropped")

	present(t, c["monoview"], "MONOVIEW", "mzh", 2500*time.Millisecond, "*")
	time.Sleep(2600 * time.Millisecond)
	send(t, c["monoview"], "2:l4:MONOVIEW.mzh:GOVERNOR:GET:EVENTS")
	nothing(t, c["governor"], "governor, after the ticket lapsed")
}

// ─── where a frame goes ──────────────────────────────────────────────

func TestARequestReachesOnlyItsAddressee(t *testing.T) {
	_, c := bus(t)
	present(t, c["monoview"], "MONOVIEW", "mzh", time.Minute, "SYNAPSE.*")
	send(t, c["monoview"], "2:r1:MONOVIEW.mzh:SYNAPSE:GET:MSGS:dasha")
	expect(t, c["synapse"], "2:r1:MONOVIEW.mzh:SYNAPSE:GET:MSGS:dasha")
	quiet(t, c)
}

func TestAReplyReachesOnlyWhoAsked(t *testing.T) {
	url, c := bus(t)
	other := join(t, url, "portal") // a second browser
	time.Sleep(30 * time.Millisecond)

	send(t, c["portal"], "2:q1:MONOWEB:MARSHAL:AUTH:CHALLENGE")
	expect(t, c["marshal"], "2:q1:MONOWEB:MARSHAL:AUTH:CHALLENGE")
	send(t, c["marshal"], "2:q1:MARSHAL:MONOWEB:OK:CHALLENGE:nonce")
	expect(t, c["portal"], "2:q1:MARSHAL:MONOWEB:OK:CHALLENGE:nonce")
	nothing(t, other, "the other browser")

	send(t, c["marshal"], "2:q1:MARSHAL:MONOWEB:OK:CHALLENGE:again")
	nothing(t, c["portal"], "the asker, answered twice")
}

func TestAReplyNobodyAskedForGoesNowhere(t *testing.T) {
	_, c := bus(t)
	send(t, c["marshal"], "2:zz:MARSHAL:MONOWEB:OK:SESSION:token:mzh:2026-10-01T00%3A00%3A00Z")
	quiet(t, c)
}

// Only the node asked may answer: another node cannot slip in a reply to a
// request that was not put to it.
func TestOnlyTheNodeAskedMayAnswer(t *testing.T) {
	_, c := bus(t)
	send(t, c["portal"], "2:q2:MONOWEB:MARSHAL:AUTH:CHALLENGE")
	expect(t, c["marshal"], "2:q2:MONOWEB:MARSHAL:AUTH:CHALLENGE")
	send(t, c["governor"], "2:q2:GOVERNOR:MONOWEB:OK:CHALLENGE:forged")
	nothing(t, c["portal"], "the asker")
}

// v1 carries no ids, and its sender is its last field: the bus has moved to
// v2, and a v1 frame goes nowhere — a request, a reply, or one whose verb
// holds a dot to stretch a grant.
func TestTheBusCarriesV2Only(t *testing.T) {
	_, c := bus(t)
	present(t, c["monoview"], "MONOVIEW", "mzh", time.Minute, "*")
	send(t, c["monoview"], "VERTEX:TOGGLE:LAMP:MONOVIEW.mzh")
	send(t, c["vertex"], "MONOVIEW:OK:LAMP:VERTEX")
	send(t, c["ukaz"], "GOVERNOR:GET:AGENDA:UKAZ")
	send(t, c["ukaz"], "GOVERNOR:GET.X:Y:UKAZ")
	send(t, c["achtung"], "ALL:FIRE:TIMER:tea:ACHTUNG")
	quiet(t, c)
}

// What the hub checked is what it passes on. A frame with anything around it
// could be read differently by a receiver that does not trim — a leading
// space makes " 2:…" a v1 frame whose sender is its last field.
func TestWhatIsCheckedIsWhatIsPassedOn(t *testing.T) {
	_, c := bus(t)
	for _, f := range []string{
		" 2:w1:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x",
		"\t2:w2:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x",
		"2:w3:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x ",
		"2:w4:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x\n\n",
		" 2:w5:GOVERNOR:MARSHAL:GET:USERS:MARSHAL",
	} {
		send(t, c["governor"], f)
	}
	quiet(t, c)
	send(t, c["governor"], "2:w6:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x\n")
	expect(t, c["ukaz"], "2:w6:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x")
	send(t, c["governor"], "2:w7:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x\r\n")
	expect(t, c["ukaz"], "2:w7:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x")
}

// ─── what a node may send ────────────────────────────────────────────

func TestANodeSendsOnlyWhatItMay(t *testing.T) {
	_, c := bus(t)
	send(t, c["synapse"], "2:s1:SYNAPSE:VERTEX:SET:LAMP.STATE:ON")
	send(t, c["governor"], "2:s2:GOVERNOR:ALL:FIRE:TIMER:tea")
	send(t, c["ukaz"], "2:s3:UKAZ:MARSHAL:GET:USERS")
	send(t, c["achtung"], "2:s4:ACHTUNG:VERTEX:ON:BUZZ")
	quiet(t, c)

	send(t, c["synapse"], "2:s5:SYNAPSE:MARSHAL:GET:PEOPLE")
	expect(t, c["marshal"], "2:s5:SYNAPSE:MARSHAL:GET:PEOPLE")
	send(t, c["achtung"], "2:s6:ACHTUNG:VERTEX:SET:BUZZ.STATE:ON")
	expect(t, c["vertex"], "2:s6:ACHTUNG:VERTEX:SET:BUZZ.STATE:ON")
	send(t, c["achtung"], "2:s7:ACHTUNG:ALL:FIRE:TIMER:tea")
	expect(t, c["ukaz"], "2:s7:ACHTUNG:ALL:FIRE:TIMER:tea")
	quiet(t, c)
}

func TestTheHubAnswersOnlyAboutTickets(t *testing.T) {
	_, c := bus(t)
	send(t, c["monoview"], "2:h1:MONOVIEW:CONCENTRATOR:GET:CLIENTS")
	expect(t, c["monoview"], "2:h1:CONCENTRATOR:MONOVIEW:ERR:NOUN:the hub knows only tickets")
	quiet(t, c)
}

// Replies and announcements are never answered — not even by the hub.
func TestTheHubAnswersNoReplyOrAnnouncement(t *testing.T) {
	_, c := bus(t)
	send(t, c["governor"], "2:h2:GOVERNOR:CONCENTRATOR:PUB:X:1")
	send(t, c["marshal"], "2:h3:MARSHAL:CONCENTRATOR:OK:TICKETS:0")
	send(t, c["achtung"], "2:h4:ACHTUNG:CONCENTRATOR:FIRE:TIMER:tea")
	quiet(t, c)
}

// Portal holds a connection for every browser, each with its own rate;
// together they have one more, so one certificate cannot take the hub's
// whole attention.
func TestAPanelsConnectionsShareOneRate(t *testing.T) {
	url, _ := start(t, policy(t, testPolicy, ""), Options{Rate: 1e6, Burst: 1e6, PanelRate: 50, PanelBurst: 100})
	marshal := join(t, url, "marshal")
	webs := []*peer{join(t, url, "portal"), join(t, url, "portal"), join(t, url, "portal")}
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 100; i++ {
		for j, w := range webs {
			send(t, w, "2:p"+strconv.Itoa(j)+"x"+strconv.Itoa(i)+":MONOWEB:MARSHAL:AUTH:CHALLENGE")
		}
	}
	n := 0
	for counting := true; counting; {
		select {
		case <-marshal.in:
			n++
		case <-time.After(300 * time.Millisecond):
			counting = false
		}
	}
	if n < 100 || n > 200 {
		t.Fatalf("%d of 300 frames from three of portal's connections got through; want its burst of 100 and little more", n)
	}
}

// A node that falls behind keeps its place: frames for it are lost while its
// queue is full, and whoever asks it something is told BUSY at once rather
// than left to time out. Dropping it instead would let anyone who sends fast
// enough push a node off the bus.
func TestANodeThatFallsBehindIsKeptAndAskersAreToldBusy(t *testing.T) {
	url, _ := start(t, policy(t, hearing, ""), Options{Rate: 1e6, Burst: 1e6})
	stuck := dialRaw(t, url, "cn=achtung") // hears everything, and never reads
	if tcp, ok := stuck.UnderlyingConn().(*net.TCPConn); ok {
		tcp.SetReadBuffer(4096)
	}
	sender := join(t, url, "governor")
	asker := join(t, url, "ukaz")
	time.Sleep(50 * time.Millisecond)

	args := strings.TrimSuffix(strings.Repeat(strings.Repeat("x", 200)+":", 10), ":") // 2 KB a frame
	for i := 0; i < 6000; i++ {
		if err := sender.c.WriteMessage(ws.TextMessage, []byte("2:b"+strconv.Itoa(i)+":GOVERNOR:ALL:PUB:X:"+args)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	send(t, asker, "2:u1:UKAZ:ACHTUNG:GET:UPTIME")
	deadline := time.After(3 * time.Second)
	for {
		select {
		case got := <-asker.in:
			if strings.HasPrefix(got, "2:u1:") {
				if !strings.HasPrefix(got, "2:u1:ACHTUNG:UKAZ:ERR:BUSY") {
					t.Fatalf("the asker was told %q", got)
				}
				return
			}
		case <-deadline:
			t.Fatal("the asker was told nothing about a node that is behind")
		}
	}
}

// ─── limits ──────────────────────────────────────────────────────────

// The roll call makes every node announce everything: a panel may call it
// once in a while, not a hundred times a second.
func TestTheRollCallIsRationed(t *testing.T) {
	_, c := bus(t)
	present(t, c["portal"], "MONOWEB", "dasha", time.Minute, "VERTEX.*")
	send(t, c["portal"], "2:c1:MONOWEB.dasha:ALL:GET:REG")
	for _, cn := range nodes {
		expect(t, c[cn], "2:c1:MONOWEB.dasha:ALL:GET:REG")
	}
	send(t, c["portal"], "2:c2:MONOWEB.dasha:ALL:GET:REG")
	quiet(t, c)
}

func TestAnOversizedFrameDropsItsSender(t *testing.T) {
	_, c := bus(t)
	send(t, c["governor"], "2:b1:GOVERNOR:ALL:PUB:X:"+strings.Repeat("y", 5000))
	gone(t, c["governor"], "the sender of an oversized frame")
	quiet(t, c, "governor")
}

func TestAFloodIsCut(t *testing.T) {
	url, _ := start(t, policy(t, hearing, ""), Options{Rate: 50, Burst: 100})
	sender, reader := join(t, url, "governor"), join(t, url, "achtung")
	time.Sleep(30 * time.Millisecond)
	for i := 0; i < 1000; i++ {
		send(t, sender, "2:f"+strconv.Itoa(i)+":GOVERNOR:ALL:PUB:N:"+strconv.Itoa(i))
	}
	n := 0
	for counting := true; counting; {
		select {
		case <-reader.in:
			n++
		case <-time.After(300 * time.Millisecond):
			counting = false
		}
	}
	if n < 100 || n > 200 {
		t.Fatalf("%d of 1000 frames sent at once got through; want the burst of 100 and little more", n)
	}
}

// A client that stops reading — ukaz once did, its network task stuck —
// must not stall the hub for everyone else. Frames for it are lost while its
// queue is full, and its writer's deadline drops it.
func TestStuckClientDoesNotStallTheHub(t *testing.T) {
	url, _ := start(t, policy(t, hearing, ""), Options{Rate: 1e6, Burst: 1e6})
	stuck := dialRaw(t, url, "cn=ukaz")
	if tcp, ok := stuck.UnderlyingConn().(*net.TCPConn); ok {
		tcp.SetReadBuffer(4096) // and it never reads
	}
	reader := join(t, url, "achtung")
	sender := join(t, url, "governor")
	time.Sleep(50 * time.Millisecond)

	const frames = 4000
	args := strings.TrimSuffix(strings.Repeat(strings.Repeat("x", 200)+":", 10), ":") // 2 KB a frame
	got := make(chan int, 1)
	go func() {
		n := 0
		deadline := time.After(20 * time.Second)
		for n < frames {
			select {
			case _, ok := <-reader.in:
				if !ok {
					got <- n
					return
				}
				n++
			case <-deadline:
				got <- n
				return
			}
		}
		got <- n
	}()
	go func() {
		for i := 0; i < frames; i++ {
			if err := sender.c.WriteMessage(ws.TextMessage, []byte("2:i"+strconv.Itoa(i)+":GOVERNOR:ALL:PUB:X:"+args)); err != nil {
				return
			}
		}
	}()
	select {
	case n := <-got:
		if n != frames {
			t.Fatalf("the reading client got %d of %d frames", n, frames)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("the hub stalled behind a client that stopped reading")
	}
}

// Announcements reach who hears them in the order they were sent, and never
// their sender.
func TestAnnouncementsArriveInOrder(t *testing.T) {
	url, _ := start(t, policy(t, hearing, ""), Options{})
	a, b := join(t, url, "governor"), join(t, url, "achtung")
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 50; i++ {
		send(t, a, "2:o"+strconv.Itoa(i)+":GOVERNOR:ALL:PUB:N:"+strconv.Itoa(i))
	}
	for i := 0; i < 50; i++ {
		expect(t, b, "2:o"+strconv.Itoa(i)+":GOVERNOR:ALL:PUB:N:"+strconv.Itoa(i))
	}
	nothing(t, a, "the sender")
}

// A connection that stops answering — not even the hub's pings — is gone,
// and does not keep its place.
func TestASilentConnectionIsDropped(t *testing.T) {
	url, _ := start(t, policy(t, testPolicy, ""), Options{Ping: 50 * time.Millisecond, PongWait: 300 * time.Millisecond})
	silent := dialRaw(t, url, "cn=ukaz") // never reads, so never answers a ping
	alive := join(t, url, "governor")    // reads, and answers every ping as it does
	time.Sleep(900 * time.Millisecond)

	silent.SetReadDeadline(time.Now().Add(time.Second))
	for {
		_, _, err := silent.ReadMessage()
		if err == nil {
			continue
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatal("the silent connection is still open")
		}
		break
	}
	send(t, alive, "2:s1:GOVERNOR:CONCENTRATOR:GET:CLIENTS")
	expect(t, alive, "2:s1:CONCENTRATOR:GOVERNOR:ERR:NOUN:the hub knows only tickets")
}

func TestAnExpiredCertificateIsDropped(t *testing.T) {
	url, _ := start(t, policy(t, testPolicy, ""), Options{Sweep: 50 * time.Millisecond})
	soon := time.Now().Add(300 * time.Millisecond).UnixMilli()
	p := wrap(t, dialRaw(t, url, "cn=governor&exp="+strconv.FormatInt(soon, 10)))
	gone(t, p, "governor, its certificate expired")
	if c, err := dial(url, "cn=achtung&exp="+strconv.FormatInt(time.Now().Add(-time.Second).UnixMilli(), 10), nil); err == nil {
		c.Close()
		t.Fatal("an expired certificate joined")
	}
}

// ─── changing the policy ─────────────────────────────────────────────

func TestReloadDropsWhomItNoLongerAdmits(t *testing.T) {
	url, h := start(t, policy(t, testPolicy, ""), Options{})
	u := join(t, url, "ukaz")
	g := join(t, url, "governor")
	time.Sleep(30 * time.Millisecond)

	var kept []string
	for _, line := range strings.Split(testPolicy, "\n") {
		if !strings.HasPrefix(line, "ukaz") {
			kept = append(kept, line)
		}
	}
	h.Reload(policy(t, strings.Join(kept, "\n"), ""))
	gone(t, u, "ukaz, taken out of the policy")
	nothing(t, g, "governor, still admitted") // and still connected
	if c, err := dial(url, "cn=ukaz", nil); err == nil {
		c.Close()
		t.Fatal("ukaz joined again")
	}
}

// ─── the real handshake ──────────────────────────────────────────────

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string, parent *testCA, pathlen int) testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		MaxPathLen: pathlen, MaxPathLenZero: pathlen == 0}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return testCA{c, key}
}

func (ca testCA) issue(t *testing.T, cn string, serial int64, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
}

func pemOf(certs ...*x509.Certificate) []byte {
	var b []byte
	for _, c := range certs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return b
}

// The client CA is the one CA that issues the bus's certificates, alone, and
// it may sign no CA below it: otherwise any CA it trusts could issue a
// certificate named marshal.
func TestTheClientCAIsOneCAWithNoneBelowIt(t *testing.T) {
	root := newCA(t, "root", nil, 1)
	bubble := newCA(t, "bubble", &root, 0)
	open := newCA(t, "open", nil, -1)
	if _, ca, err := ClientCAPool(pemOf(bubble.cert)); err != nil || ca.Subject.CommonName != "bubble" {
		t.Fatalf("the bubble CA alone: %v", err)
	}
	for what, file := range map[string][]byte{
		"the root and the bubble CA": pemOf(bubble.cert, root.cert),
		"a CA that may sign CAs":     pemOf(root.cert),
		"a CA with no limit":         pemOf(open.cert),
		"nothing":                    nil,
	} {
		if _, _, err := ClientCAPool(file); err == nil {
			t.Errorf("%s: taken", what)
		}
	}
}

// TLSIdentity takes the name from the certificate the handshake checked, and
// only from one the client CA issued itself.
func TestTLSIdentity(t *testing.T) {
	ca := newCA(t, "test CA", nil, -1) // it may sign CAs: TLSIdentity must not take theirs
	below := newCA(t, "a CA below", &ca, 0)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)

	h := New(policy(t, testPolicy, "7"), TLSIdentity, Options{TicketKey: ticketPub})
	go h.Run()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(h.Accept))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ca.issue(t, "hub", 2, x509.ExtKeyUsageServerAuth)},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	url := "wss" + strings.TrimPrefix(srv.URL, "https")

	dialAs := func(cert tls.Certificate) (*peer, error) {
		d := ws.Dialer{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}}
		c, _, err := d.Dial(url, nil)
		if err != nil {
			return nil, err
		}
		return wrap(t, c), nil
	}
	governor, err := dialAs(ca.issue(t, "governor", 3, x509.ExtKeyUsageClientAuth))
	if err != nil {
		t.Fatal(err)
	}
	ukaz, err := dialAs(ca.issue(t, "ukaz", 4, x509.ExtKeyUsageClientAuth))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dialAs(ca.issue(t, "eve", 5, x509.ExtKeyUsageClientAuth)); err == nil {
		t.Fatal("a certificate from the CA but not in the policy joined")
	}
	if _, err := dialAs(ca.issue(t, "vertex", 7, x509.ExtKeyUsageClientAuth)); err == nil {
		t.Fatal("a revoked certificate joined")
	}
	if _, err := dialAs(below.issue(t, "marshal", 8, x509.ExtKeyUsageClientAuth)); err == nil {
		t.Fatal("a certificate named marshal, from a CA below the client CA, joined")
	}
	time.Sleep(30 * time.Millisecond)

	send(t, governor, "2:t1:MARSHAL:ALL:PUB:PEOPLE:eve") // governor's certificate, MARSHAL's name
	nothing(t, ukaz, "ukaz")
	send(t, governor, "2:t2:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x")
	expect(t, ukaz, "2:t2:GOVERNOR:ALL:PUB:NEXT.DEADLINE:x")
}
