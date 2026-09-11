package hub

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	ws "github.com/gorilla/websocket"
)

func start(t *testing.T) string {
	t.Helper()
	h := New()
	go h.Run()
	srv := httptest.NewServer(http.HandlerFunc(h.Accept))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

func dial(t *testing.T, url string) *ws.Conn {
	t.Helper()
	c, _, err := ws.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// A client that stops reading — ukaz once did, its network task stuck —
// must not stall the hub for everyone else. It is dropped instead.
func TestStuckClientDoesNotStallTheHub(t *testing.T) {
	url := start(t)
	stuck := dial(t, url)
	if tcp, ok := stuck.UnderlyingConn().(*net.TCPConn); ok {
		tcp.SetReadBuffer(4096) // and it never reads
	}
	reader := dial(t, url)
	sender := dial(t, url)
	time.Sleep(50 * time.Millisecond) // all three registered

	const frames = 4000
	payload := strings.Repeat("x", 2048) // 8 MB in all: far more than any socket buffers

	got := make(chan int, 1)
	go func() {
		n := 0
		reader.SetReadDeadline(time.Now().Add(20 * time.Second))
		for n < frames {
			if _, _, err := reader.ReadMessage(); err != nil {
				break
			}
			n++
		}
		got <- n
	}()
	go func() {
		for i := 0; i < frames; i++ {
			if err := sender.WriteMessage(ws.TextMessage, []byte(strconv.Itoa(i)+payload)); err != nil {
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

// The sender is not sent its own frames, and every other client gets them
// in order.
func TestRelayInOrderToEveryoneElse(t *testing.T) {
	url := start(t)
	a, b := dial(t, url), dial(t, url)
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 50; i++ {
		a.WriteMessage(ws.TextMessage, []byte(strconv.Itoa(i)))
	}
	b.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < 50; i++ {
		_, msg, err := b.ReadMessage()
		if err != nil || string(msg) != strconv.Itoa(i) {
			t.Fatalf("frame %d: %q, %v", i, msg, err)
		}
	}
	a.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, msg, err := a.ReadMessage(); err == nil {
		t.Fatalf("the sender was echoed %q", msg)
	}
}
