package hub

import (
	"bufio"
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"
	"strings"

	"github.com/MrZloHex/monolink"
	auth "github.com/MrZloHex/monolink/marshal"
)

// Identity is what one certificate may be on the bus. SECURITY.txt §5.
type Identity struct {
	CN    string   // the certificate's common name
	Node  string   // the node it speaks as — and no other certificate does
	Panel bool     // a person's door: it may speak as <node>.<person>
	May   []string // a node's: the requests it may send, as TO.VERB.NOUN patterns
	Hears []string // a node's: the announcements it is given, as FROM.VERB.NOUN patterns
}

func (a Identity) equal(b Identity) bool {
	return a.CN == b.CN && a.Node == b.Node && a.Panel == b.Panel &&
		slices.Equal(a.May, b.May) && slices.Equal(a.Hears, b.Hears)
}

// may reports whether a node may send action, TO.VERB.NOUN. A panel may
// send nothing by its line: what it may is its ticket's, and refusal asks
// that instead.
func (a Identity) may(action string) bool { return !a.Panel && auth.Allowed(a.May, action) }

// hears reports whether a node is given an announcement, FROM.VERB.NOUN —
// a PUB, REG or FIRE. A panel hears what its ticket covers, not its line.
func (a Identity) hears(action string) bool { return !a.Panel && auth.Allowed(a.Hears, action) }

// Policy is who may join the bus, as what, what each may send and hear; and
// which certificates are revoked.
type Policy struct {
	ids     map[string]Identity // by CN
	revoked map[string]bool     // certificate serials, lower-case hex
}

// ParsePolicy reads a policy:
//
//	# a comment
//	<certificate CN>  <node>  node   [<may send>...] [hears <announcement>...]
//	<certificate CN>  <node>  panel
//
// A pattern is written as a grant is (SPEC §24): TO.VERB.NOUN for what a
// node sends, FROM.VERB.NOUN for what it hears, or a prefix of one ending in
// "*". Replies to what a node was asked, its own PUB and REG to ALL, and the
// requests put to it, need none; every announcement of another's it hears
// must be listed. A panel lists nothing: its person's ticket says. A
// certificate not listed may not join, and a node is one certificate's.
func ParsePolicy(r io.Reader) (*Policy, error) {
	p := &Policy{ids: map[string]Identity{}, revoked: map[string]bool{}}
	nodes := map[string]string{} // node → the CN that speaks as it
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 3 {
			return nil, fmt.Errorf("policy line %d: want <cn> <node> node|panel [<pattern>...] [hears <pattern>...]", n)
		}
		id := Identity{CN: f[0], Node: f[1]}
		rest := f[3:]
		switch f[2] {
		case "node":
			id.May = rest
			if i := slices.Index(rest, "hears"); i >= 0 {
				id.May, id.Hears = rest[:i], rest[i+1:]
			}
		case "panel":
			id.Panel = true
			if len(rest) > 0 {
				return nil, fmt.Errorf("policy line %d: a panel lists no patterns — its person's ticket says what it may", n)
			}
		default:
			return nil, fmt.Errorf("policy line %d: %q is neither node nor panel", n, f[2])
		}
		if a, err := monolink.ParseAddress(id.Node); err != nil || a.Node != id.Node || a.Actor != "" ||
			a.Bubble != "" || id.Node == monolink.All || id.Node == auth.Hub {
			return nil, fmt.Errorf("policy line %d: %q is not a node's name", n, id.Node)
		}
		for _, pat := range append(slices.Clone(id.May), id.Hears...) {
			if !auth.ValidPattern(pat) {
				return nil, fmt.Errorf("policy line %d: %q is not a pattern", n, pat)
			}
		}
		if _, dup := p.ids[id.CN]; dup {
			return nil, fmt.Errorf("policy line %d: %s is listed twice", n, id.CN)
		}
		if other, dup := nodes[id.Node]; dup {
			return nil, fmt.Errorf("policy line %d: %s is %s's already — one certificate a node; another needs a node of its own", n, id.Node, other)
		}
		nodes[id.Node] = id.CN
		p.ids[id.CN] = id
	}
	return p, sc.Err()
}

// ParseRevoked adds revoked certificate serials to p: one per line, in hex,
// colons and leading zeros as you like — as openssl prints them.
func (p *Policy) ParseRevoked(r io.Reader) error {
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line, _, _ := strings.Cut(sc.Text(), "#")
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		k := serialKey(s)
		if _, ok := new(big.Int).SetString(k, 16); !ok {
			return fmt.Errorf("revoked line %d: %q is not a serial number", n, s)
		}
		p.revoked[k] = true
	}
	return sc.Err()
}

// LoadPolicy reads the policy file and, if revokedPath is not empty, the
// list of revoked serials.
func LoadPolicy(policyPath, revokedPath string) (*Policy, error) {
	f, err := os.Open(policyPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	p, err := ParsePolicy(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", policyPath, err)
	}
	if revokedPath != "" {
		r, err := os.Open(revokedPath)
		if err != nil {
			return nil, err
		}
		defer r.Close()
		if err := p.ParseRevoked(r); err != nil {
			return nil, fmt.Errorf("%s: %w", revokedPath, err)
		}
	}
	return p, nil
}

// Lookup is the identity a certificate may have, if it may join at all.
func (p *Policy) Lookup(cn string) (Identity, bool) {
	id, ok := p.ids[cn]
	return id, ok
}

// Revoked reports whether a certificate's serial is on the revoked list.
func (p *Policy) Revoked(serial *big.Int) bool {
	return serial != nil && p.revoked[serialKey(serial.Text(16))]
}

func serialKey(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, ":", ""))
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}
